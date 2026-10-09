import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { ConnectionPool } from '../src/core/claim-pool.mjs';
import { CONFIG_TEMPLATE } from '../src/config.mjs';
import { packageTarget } from './package-target.mjs';
import { verifyMacOSPackage } from './macos-package.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const windows = process.platform === 'win32';
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
if (process.argv.length > 3) throw new Error('Usage: node scripts/test-package.mjs [package.zip]');
const target = packageTarget();
const packageName = `connectcoin-claimer-${pkg.version}-${target.platform}-${target.arch}`;
const archive = resolve(process.argv[2] ?? join(root, 'dist', `${packageName}.zip`));
assert.ok(archive.endsWith('.zip'), 'Package verification requires the distributed ZIP.');
const archiveHash = createHash('sha256').update(await readFile(archive)).digest('hex');
assert.equal(await readFile(`${archive}.sha256`, 'utf8'), `${archiveHash}  ${basename(archive)}\n`, 'ZIP checksum must match the exact archive.');
const forbiddenPackagePath = /(^|\/)(?:node_modules|\.claims-venv|\.git)(\/|$)|\.conf(?:[./]|$)|\.state\.json(?:[./]|$)|\.lock(?:[./]|$)|(^|\/)wallet\.json$/i;

async function filesBelow(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await filesBelow(join(directory, entry.name), name));
    else if (entry.isFile()) files.push(name);
    else throw new Error(`Unsupported package entry: ${name}`);
  }
  return files.sort();
}

const scratch = await mkdtemp(join(tmpdir(), 'claimer package test '));
try {
  const extract = join(scratch, 'extracted ZIP');
  await mkdir(extract);
  const nativeArchiveTool = windows ? join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe') : 'unzip';
  const runArchiveTool = promisify(execFile);
  const archiveOptions = { windowsHide: true, timeout: 120_000, maxBuffer: 16 * 1024 * 1024 };
  const { stdout: listing } = await runArchiveTool(nativeArchiveTool, windows ? ['-tf', archive] : ['-Z1', archive], archiveOptions);
  const archiveEntries = listing.trimEnd().split(/\r?\n/);
  assert.ok(archiveEntries.length > 0, 'The ZIP must contain a package.');
  assert.equal(new Set(archiveEntries).size, archiveEntries.length, 'The ZIP must not contain duplicate entries.');
  for (const entry of archiveEntries) {
    const parts = entry.replace(/\/$/, '').split('/');
    assert.ok(!isAbsolute(entry) && !/[\\:]/.test(entry) && parts.every((part) => part && part !== '.' && part !== '..'), 'ZIP paths must stay inside the extraction folder.');
    assert.equal(parts[0], packageName, 'The ZIP must contain exactly the named package folder.');
    assert.ok(!forbiddenPackagePath.test(entry), `Release ZIP contains configuration, runtime state, credentials or development files: ${entry}`);
  }
  await runArchiveTool(nativeArchiveTool, windows ? ['-xf', archive, '-C', extract] : ['-q', archive, '-d', extract], archiveOptions);
  const source = join(extract, packageName);
  const manifestBytes = await readFile(join(source, 'package-manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifest.format, 1);
  assert.equal(manifest.name, 'connectcoin-claimer');
  assert.equal(manifest.version, pkg.version);
  assert.equal(manifest.platform, process.platform);
  assert.equal(manifest.arch, process.arch);
  assert.equal(manifest.entrypoint, windows ? 'claimer.exe' : 'claimer');
  for (const entry of manifest.files) {
    assert.ok(!isAbsolute(entry.path) && !/[\\:]/.test(entry.path) && entry.path.split('/').every((part) => part && part !== '.' && part !== '..'), 'Manifest paths must stay inside the package.');
    assert.ok(!forbiddenPackagePath.test(entry.path), `Forbidden release file: ${entry.path}`);
    const bytes = await readFile(join(source, entry.path));
    assert.equal(bytes.length, entry.bytes, entry.path);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256, entry.path);
  }
  const pristineFiles = [...manifest.files.map((entry) => entry.path), 'package-manifest.json', 'SHA256SUMS'].sort();
  assert.deepEqual(await filesBelow(source), pristineFiles, 'Every extracted file must appear exactly once in the manifest.');
  const manifestHash = createHash('sha256').update(manifestBytes).digest('hex');
  assert.equal(await readFile(join(source, 'SHA256SUMS'), 'utf8'), `${manifest.files.map((entry) => `${entry.sha256}  ${entry.path}`).join('\n')}\n${manifestHash}  package-manifest.json\n`, 'SHA256SUMS must match all files and the manifest exactly.');
  const helperPath = join('helpers', 'bin', 'connectwallet-claims', windows ? 'connectwallet-claims.exe' : 'connectwallet-claims');
  if (!windows) {
    for (const name of [manifest.entrypoint, helperPath]) {
      assert.ok((await stat(join(source, name))).mode & 0o111, `ZIP extraction must preserve executable permissions: ${name}`);
    }
  }
  const portable = join(scratch, 'portable folder with spaces');
  const elsewhere = join(scratch, 'unrelated working directory');
  await cp(source, portable, { recursive: true });
  await mkdir(elsewhere);
  if (process.platform === 'darwin') await verifyMacOSPackage(portable);
  const executable = join(portable, manifest.entrypoint);
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(?:PATH|PYTHON.*|NODE.*|VIRTUAL_ENV|CONDA.*|DYLD_.*|CLAIMER.*|CONNECT.*)$/i.test(name)));
  env.PATH = '';
  function run(command, args, expected = 0) {
    return new Promise((accept, reject) => {
      const child = spawn(command, args, { cwd: elsewhere, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '';
      const timer = setTimeout(() => { child.kill(); reject(new Error(`Packaged command timed out: ${args.join(' ')}`)); }, 30_000);
      child.stdout.on('data', (data) => { output += data; });
      child.stderr.on('data', (data) => { output += data; });
      child.once('error', (error) => { clearTimeout(timer); reject(error); });
      child.once('exit', (code) => {
        clearTimeout(timer);
        try { assert.equal(code, expected, `Packaged command failed (${args.join(' ')}):\n${output}`); accept(output); }
        catch (error) { reject(error); }
      });
    });
  }
  assert.ok((await run(executable, ['--version'])).includes(pkg.version));
  assert.match(await run(executable, ['--help']), /--config/);
  assert.deepEqual(await filesBelow(portable), pristineFiles, '--help/--version must not create any files.');
  const helper = join(portable, helperPath);
  await run(helper, ['--self-test']);
  const pool = new ConnectionPool({
    basePath: portable,
    spawnProcess(command, args, options) {
      assert.equal(command, helper, 'Helper discovery must use the relocated native helper.');
      return spawn(command, args, { ...options, cwd: elsewhere, env });
    },
  });
  try { await pool.start({}); }
  finally { await pool.close(); }
  // Public test fixture only. --check is offline and must never start mining or RPC.
  const address = 'cc1pr6lfwrhp9h65ffn7zs20ce4r56zh3uvucuzxp0w6xp9yzx847c7qeejl6q';
  const defaultConfig = join(portable, 'claimer.conf');
  assert.match(await run(executable, [], 2), /No connections were made\./);
  const template = await readFile(defaultConfig, 'utf8');
  assert.equal(template, CONFIG_TEMPLATE, 'First launch must create the default configuration with a blank receiving address.');
  assert.match(template, /^receiving_address=\s*$/m);
  assert.deepEqual(await filesBelow(portable), [...pristineFiles, 'claimer.conf'].sort(), 'First launch may only create the blank configuration, never state or a lock.');
  assert.deepEqual(await filesBelow(elsewhere), [], 'First launch must write beside the executable, not in the working directory.');
  await run(executable, ['--init']);
  assert.equal(await readFile(defaultConfig, 'utf8'), template, '--init must preserve an existing configuration.');
  await run(executable, ['--check'], 1);
  await writeFile(defaultConfig, `receiving_address=${address}\nrpc_host=127.0.0.1\nrpc_port=1\n`);
  assert.match(await run(executable, ['--check']), /Configuration valid\./);
  const explicitConfig = join(elsewhere, 'explicit configuration.conf');
  await writeFile(explicitConfig, `receiving_address=${address}\nrpc_host=127.0.0.1\nrpc_port=1\n`);
  assert.match(await run(executable, ['--config', explicitConfig, '--check']), /Configuration valid\./);
  await writeFile(explicitConfig, 'receiving_address=invalid\n');
  await run(executable, ['--config', explicitConfig, '--check'], 1);
  assert.deepEqual(await filesBelow(portable), [...pristineFiles, 'claimer.conf'].sort(), 'Offline checks must not create state or lock files.');
  assert.deepEqual(await filesBelow(elsewhere), ['explicit configuration.conf'], 'Explicit offline checks must not create state or lock files.');
  assert.deepEqual(await filesBelow(source), pristineFiles, 'Verification must preserve the pristine extracted package.');
  console.log('Distributed ZIP, exact file hashes, executable modes, first-launch configuration and bundled helper passed offline checks with an empty PATH and relocated package.');
} finally {
  await rm(scratch, { recursive: true, force: true });
}
