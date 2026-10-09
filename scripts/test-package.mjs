import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConnectionPool } from '../src/core/claim-pool.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const windows = process.platform === 'win32';
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
if (process.argv.length > 3) throw new Error('Usage: node scripts/test-package.mjs [package-directory]');
const source = resolve(process.argv[2] ?? join(root, 'dist', `connectcoin-claimer-${pkg.version}-${windows ? 'win' : process.platform}-${process.arch}`));
const manifest = JSON.parse(await readFile(join(source, 'package-manifest.json'), 'utf8'));
assert.equal(manifest.name, 'connectcoin-claimer');
assert.equal(manifest.version, pkg.version);
assert.equal(manifest.platform, process.platform);
assert.equal(manifest.arch, process.arch);
assert.equal(manifest.entrypoint, windows ? 'claimer.exe' : 'claimer');

async function filesBelow(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await filesBelow(join(directory, entry.name), name));
    else files.push(name);
  }
  return files.sort();
}

for (const entry of manifest.files) {
  assert.ok(!isAbsolute(entry.path) && !entry.path.split(/[\\/]/).includes('..'), 'Manifest paths must stay inside the package.');
  const bytes = await readFile(join(source, entry.path));
  assert.equal(bytes.length, entry.bytes, entry.path);
  assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.sha256, entry.path);
}
assert.deepEqual(await filesBelow(source), [...manifest.files.map((entry) => entry.path), 'package-manifest.json', 'SHA256SUMS'].sort());
assert.ok(!manifest.files.some(({ path }) => /(^|\/)(?:node_modules|\.claims-venv|\.git)(\/|$)|\.conf$|\.state\.json$|wallet\.json$/i.test(path)), 'The release must not contain working credentials, configuration or development environments.');

const scratch = await mkdtemp(join(tmpdir(), 'claimer package test '));
try {
  const portable = join(scratch, 'portable folder with spaces');
  const elsewhere = join(scratch, 'unrelated working directory');
  await cp(source, portable, { recursive: true });
  await mkdir(elsewhere);
  const executable = join(portable, manifest.entrypoint);
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(?:PATH|PYTHON.*|NODE.*|VIRTUAL_ENV|CONDA.*|CLAIMER.*|CONNECT.*)$/i.test(name)));
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
  assert.ok(!(await filesBelow(portable)).includes('claimer.conf'), '--help/--version must not create a config.');
  const helper = join(portable, 'helpers', 'bin', 'connectwallet-claims', windows ? 'connectwallet-claims.exe' : 'connectwallet-claims');
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
  await run(executable, [], 2);
  const template = await readFile(defaultConfig, 'utf8');
  assert.match(template, /^receiving_address=\s*$/m);
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
  assert.ok(!(await filesBelow(portable)).some((name) => name.endsWith('.state.json')), 'Offline check must not create state.');
  assert.ok(!(await filesBelow(elsewhere)).some((name) => name.endsWith('.state.json')), 'Explicit offline check must not create state.');
  console.log('Portable executable and bundled claims helper passed offline checks with an empty PATH, relocated package, and unrelated working directory.');
} finally {
  await rm(scratch, { recursive: true, force: true });
}
