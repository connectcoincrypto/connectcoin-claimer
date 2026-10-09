import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { builtinModules } from 'node:module';
import { access, chmod, copyFile, cp, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import postject from 'postject';
import { packageTarget } from './package-target.mjs';
import { signMacOSFrameworks, verifyMacOSPackage } from './macos-package.mjs';
import { packageEntries } from './package-files.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const windows = process.platform === 'win32';
const macos = process.platform === 'darwin';
const { platform, executable: executableName } = packageTarget();
const helperName = windows ? 'connectwallet-claims.exe' : 'connectwallet-claims';
const manifestName = 'package-manifest.json';
const args = process.argv.slice(2);
if (args.some((arg) => arg !== '--archive')) throw new Error('Usage: node scripts/build.mjs [--archive]');
const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
if (nodeMajor !== 24 || nodeMinor < 19) throw new Error('Build with Node.js 24.19.0 or newer within the Node.js 24 LTS line.');
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
if (!/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(pkg.version)) throw new Error('Invalid package version.');
const packageName = `connectcoin-claimer-${pkg.version}-${platform}-${process.arch}`;
const dist = join(root, 'dist');
const destination = join(dist, packageName);
const helperSource = join(root, 'helpers', 'bin', 'connectwallet-claims');
try { await access(join(helperSource, helperName)); }
catch { throw new Error('The native claims helper is missing. Run npm run build:claims first.'); }

function run(command, commandArgs, options = {}) {
  return new Promise((accept, reject) => {
    const child = spawn(command, commandArgs, {
      cwd: root, stdio: 'inherit', windowsHide: true, shell: false, ...options,
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? accept() : reject(new Error(`${basename(command)} failed (${signal ?? code}).`)));
  });
}

async function writeLicenses(directory, metafile) {
  const licenses = join(directory, 'licenses');
  await mkdir(licenses, { recursive: true });
  const packageRoots = new Set();
  for (const input of Object.keys(metafile.inputs)) {
    const parts = input.replaceAll('\\', '/').split('/');
    const index = parts.lastIndexOf('node_modules');
    if (index < 0) continue;
    packageRoots.add(parts.slice(0, index + (parts[index + 1].startsWith('@') ? 3 : 2)).join('/'));
  }
  const dependencies = [];
  for (const packageRoot of [...packageRoots].sort()) {
    const dependency = JSON.parse(await readFile(resolve(root, packageRoot, 'package.json'), 'utf8'));
    const names = (await readdir(resolve(root, packageRoot))).filter((name) => /^(licen[cs]e|notice|copying)(\.|$)/i.test(name));
    if (!names.length) throw new Error(`Missing license for bundled dependency ${dependency.name}.`);
    const folder = join(licenses, dependency.name.replaceAll('/', '__'));
    await mkdir(folder, { recursive: true });
    for (const name of names) await copyFile(resolve(root, packageRoot, name), join(folder, name));
    dependencies.push({ name: dependency.name, version: dependency.version, license: dependency.license });
  }
  let nodeLicense;
  for (const candidate of [join(dirname(process.execPath), 'LICENSE'), resolve(dirname(process.execPath), '..', 'LICENSE')]) {
    try {
      const content = await readFile(candidate, 'utf8');
      if (content.includes('Node.js is licensed for use as follows')) { nodeLicense = content; break; }
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  if (!nodeLicense) {
    const url = `https://raw.githubusercontent.com/nodejs/node/${process.version}/LICENSE`;
    const response = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error(`Unable to retrieve Node.js license: HTTP ${response.status}.`);
    nodeLicense = await response.text();
    if (!nodeLicense.includes('Node.js is licensed for use as follows')) throw new Error('Unexpected Node.js license response.');
  }
  await writeFile(join(licenses, 'LICENSE.node.txt'), nodeLicense);
  await writeFile(join(licenses, 'javascript-dependencies.json'), `${JSON.stringify(dependencies, null, 2)}\n`);
}

await mkdir(dist, { recursive: true });
const scratch = await mkdtemp(join(dist, '.claimer-build-'));
const stage = join(scratch, packageName);
try {
  await mkdir(stage);
  const bundle = join(scratch, 'claimer.cjs');
  const result = await build({
    absWorkingDir: root,
    entryPoints: ['src/cli.mjs'],
    outfile: bundle,
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node24',
    metafile: true,
    sourcemap: false,
    legalComments: 'inline',
    banner: { js: 'const __claimerImportMetaUrl = require("node:url").pathToFileURL(__filename).href;' },
    define: { 'import.meta.url': '__claimerImportMetaUrl', 'import.meta.dirname': '__dirname', 'import.meta.filename': '__filename' },
    logLevel: 'info',
  });
  const builtins = new Set(builtinModules.flatMap((name) => [name, `node:${name}`]));
  for (const output of Object.values(result.metafile.outputs)) {
    for (const imported of output.imports) {
      if (imported.external && !builtins.has(imported.path)) throw new Error(`Unbundled dependency: ${imported.path}`);
    }
  }
  const buildInputs = await Promise.all(Object.keys(result.metafile.inputs).sort().map(async (path) => ({
    path: path.replaceAll('\\', '/'),
    sha256: createHash('sha256').update(await readFile(resolve(root, path))).digest('hex'),
  })));
  const blob = join(scratch, 'claimer.blob');
  const config = join(scratch, 'sea-config.json');
  // The blob and binary must use the exact same Node.js runtime.
  // https://nodejs.org/api/single-executable-applications.html
  await writeFile(config, JSON.stringify({
    main: bundle, output: blob, disableExperimentalSEAWarning: true,
    useCodeCache: false, useSnapshot: false, execArgvExtension: 'none',
  }));
  await run(process.execPath, ['--experimental-sea-config', config]);
  const executable = join(stage, executableName);
  await copyFile(process.execPath, executable);
  // Injection changes signed Mach-O bytes. Remove the copied Node signature,
  // use Node's SEA segment, then sign the finished binary (no Developer ID).
  if (macos) await run('/usr/bin/codesign', ['--remove-signature', executable]);
  await postject.inject(executable, 'NODE_SEA_BLOB', await readFile(blob), {
    sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
    ...(macos ? { machoSegmentName: 'NODE_SEA' } : {}),
  });
  if (!windows) await chmod(executable, 0o755);
  if (macos) await run('/usr/bin/codesign', ['--force', '--sign', '-', executable]);
  // macOS framework aliases are part of the signed bundle layout. Preserve
  // their relative targets, then validate every link before archiving.
  await cp(helperSource, join(stage, 'helpers', 'bin', 'connectwallet-claims'), {
    recursive: true, dereference: !macos, ...(macos ? { verbatimSymlinks: true } : {}),
  });
  for (const name of ['README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'PROVENANCE.md']) {
    await copyFile(join(root, name), join(stage, name));
  }
  for (const name of ['helpers/PROVENANCE.md', 'helpers/p2c_roots_v1.pem', 'helpers/vendor/LICENSE.connectcoin-p2c-tools']) {
    await mkdir(dirname(join(stage, name)), { recursive: true });
    await copyFile(join(root, name), join(stage, name));
  }
  await writeLicenses(stage, result.metafile);
  if (macos) {
    // PyInstaller signs individual cached binaries before assembling onedir
    // frameworks. Seal the complete framework resources in their final layout.
    await signMacOSFrameworks(stage);
    await verifyMacOSPackage(stage);
  }
  await run(executable, ['--version'], { cwd: stage });
  await run(join(stage, 'helpers', 'bin', 'connectwallet-claims', helperName), ['--self-test'], { cwd: stage });
  const inventory = await packageEntries(stage, { allowSymlinks: macos });
  const entries = [];
  for (const { path: name } of inventory.filter((entry) => entry.type === 'file')) {
    const bytes = await readFile(join(stage, name));
    entries.push({ path: name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  await writeFile(join(stage, manifestName), `${JSON.stringify({
    format: macos ? 2 : 1, name: 'connectcoin-claimer', version: pkg.version,
    platform: process.platform, arch: process.arch, node: process.version,
    entrypoint: executableName, buildInputs, files: entries,
    ...(macos ? { symlinks: inventory.filter((entry) => entry.type === 'symlink').map(({ path, target }) => ({ path, target })) } : {}),
  }, null, 2)}\n`);
  const manifestHash = createHash('sha256').update(await readFile(join(stage, manifestName))).digest('hex');
  await writeFile(join(stage, 'SHA256SUMS'), `${entries.map((entry) => `${entry.sha256}  ${entry.path}`).join('\n')}\n${manifestHash}  ${manifestName}\n`);
  try {
    await stat(destination);
    const previous = JSON.parse(await readFile(join(destination, manifestName), 'utf8'));
    if (previous.name !== 'connectcoin-claimer' || previous.version !== pkg.version) throw new Error('Existing output is not a generated claimer package.');
    const expected = new Set([...previous.files.map((entry) => entry.path), ...(previous.symlinks ?? []).map((entry) => entry.path), manifestName, 'SHA256SUMS']);
    for (const { path: name } of await packageEntries(destination, { allowSymlinks: macos })) {
      if (!expected.has(name)) throw new Error(`Existing output contains user files (${name}); move that folder before rebuilding.`);
    }
    const fromDist = relative(dist, destination);
    if (!fromDist || fromDist.startsWith(`..${sep}`) || isAbsolute(fromDist)) throw new Error('Unsafe output directory.');
    // Only replace the verified, generated package, never dist itself or user data.
    await rm(destination, { recursive: true });
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  await rename(stage, destination);
  if (args.includes('--archive')) {
    const archive = join(dist, `${packageName}.zip`);
    // Always create a new archive: zip updates an existing file and can retain
    // obsolete entries, including configuration from an older package.
    const freshArchive = join(scratch, `${packageName}.zip`);
    if (windows) {
      // Windows 10+ includes bsdtar; -a chooses ZIP from the archive extension.
      // Avoid PowerShell module auto-loading and its inherited PSModulePath.
      const tar = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe');
      await run(tar, ['-a', '-cf', freshArchive, '-C', dist, packageName]);
    } else {
      // Info-ZIP preserves Unix executable modes for native unzip extraction.
      await run('zip', ['-q', '-r', ...(macos ? ['-y'] : []), freshArchive, packageName], { cwd: dist });
    }
    const checksum = createHash('sha256').update(await readFile(freshArchive)).digest('hex');
    const freshChecksum = `${freshArchive}.sha256`;
    await writeFile(freshChecksum, `${checksum}  ${basename(archive)}\n`);
    await rename(freshArchive, archive);
    await rename(freshChecksum, `${archive}.sha256`);
    console.log(`Archive: ${archive}`);
  }
  console.log(`Portable package: ${destination}`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
