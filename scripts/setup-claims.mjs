import { execFile, spawn } from 'node:child_process';
import { access, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { ConnectionPool } from '../src/core/claim-pool.mjs';
import { pinnedCryptographyVersion } from './helper-security.mjs';
import { assertStaticOpenSSL, needsStaticCryptography, staticCryptographyInstall } from './claims-build-policy.mjs';

const base = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const windows = process.platform === 'win32';
const python = resolve(base, '.claims-venv', windows ? 'Scripts/python.exe' : 'bin/python');
const build = process.argv.slice(2).includes('--build');
const execFileAsync = promisify(execFile);
if (process.argv.slice(2).some((arg) => arg !== '--build')) throw new Error('Usage: node scripts/setup-claims.mjs [--build]');

function run(command, args, env = process.env) {
  return new Promise((accept, reject) => {
    const child = spawn(command, args, { cwd: base, stdio: 'inherit', shell: false, windowsHide: true, env });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? accept() : reject(new Error(`${command} exited with ${code}`)));
  });
}

try { await access(python); } catch {
  // PYTHON is an executable path, never a shell command. No silent system mutation.
  const command = process.env.PYTHON || (windows ? 'py' : 'python3');
  const prefix = windows && !process.env.PYTHON ? ['-3'] : [];
  await run(command, [...prefix, '-m', 'venv', resolve(base, '.claims-venv')]);
}
await run(python, ['-c', 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required"']);
if (build) await run(python, ['-c',
  'import platform, struct, sys; expected = {"x64": ("amd64", "x86_64"), "arm64": ("arm64", "aarch64")}; assert struct.calcsize("P") == 8 and platform.machine().lower() in expected.get(sys.argv[1], ()), "Python architecture must match the native Node/Electron target"', process.arch]);
if (needsStaticCryptography(build)) {
  // Intel has no upstream wheel at the provider pin. A dynamic source build
  // collides with CPython's different libssl.3.dylib when PyInstaller bundles it.
  // https://cryptography.io/en/50.0.1/installation/#building-cryptography-on-macos
  const directory = process.env.OPENSSL_DIR ?? (await execFileAsync('brew', ['--prefix', 'openssl@3'],
    { cwd: base, shell: false, timeout: 30000, maxBuffer: 4096 })).stdout.trim();
  const version = pinnedCryptographyVersion(await readFile(resolve(base, 'helpers/requirements.txt'), 'utf8'));
  const installation = staticCryptographyInstall(version, directory);
  for (const file of ['include/openssl/ssl.h', 'lib/libssl.a', 'lib/libcrypto.a']) {
    try { await access(resolve(directory, file)); }
    catch { throw new Error(`Static OpenSSL development files are required: ${resolve(directory, file)}`); }
  }
  await run(python, installation.args, installation.env);
}
await run(python, ['-m', 'pip', 'install', '--disable-pip-version-check', '-r', resolve(base, 'helpers', build ? 'requirements-build.txt' : 'requirements.txt')]);
if (needsStaticCryptography(build)) {
  const { stdout } = await execFileAsync(python, ['-I', '-c',
    'from cryptography.hazmat.bindings import _rust; print(_rust.__file__)'],
  { cwd: base, shell: false, timeout: 30000, maxBuffer: 4096 });
  const extension = stdout.trim();
  if (!extension.startsWith('/') || /[\0\r\n]/.test(extension)) throw new Error('Invalid cryptography extension path.');
  const dependencies = await execFileAsync('/usr/bin/otool', ['-L', extension],
    { cwd: base, shell: false, timeout: 30000, maxBuffer: 65536 });
  assertStaticOpenSSL(dependencies.stdout, extension);
  console.log(`Verified static OpenSSL linkage for native Intel cryptography ${extension}.`);
}
await run(python, ['-I', resolve(base, 'helpers/claims_bridge.py'), '--self-test']);
// Force the source runtime even if a previously built native helper exists.
// This is the wallet's actual isolated launch/protocol, with no network or keys.
const sourcePool = new ConnectionPool({ helper: { command: python, args: ['-I', resolve(base, 'helpers/claims_bridge.py')] } });
try { await sourcePool.start({}); }
finally { await sourcePool.close(); }
console.log('Isolated source protocol-4 startup and shutdown verified.');
await run(python, ['-m', 'unittest', 'discover', '-s', resolve(base, 'helpers/tests'), '-v']);
if (build) {
  await run(python, [resolve(base, 'helpers/collect_licenses.py')]);
  await run(python, ['-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--name', 'connectwallet-claims',
    ...(process.platform === 'darwin' ? ['--target-architecture', process.arch === 'x64' ? 'x86_64' : 'arm64'] : []),
    '--distpath', resolve(base, 'helpers/bin'), '--workpath', resolve(base, 'tmp/claims-build'),
    '--specpath', resolve(base, 'tmp'), '--paths', resolve(base, 'helpers/vendor'),
    '--add-data', `${resolve(base, 'helpers/p2c_roots_v1.pem')}${windows ? ';' : ':'}.`,
    '--add-data', `${resolve(base, 'helpers/vendor/LICENSE.connectcoin-p2c-tools')}${windows ? ';' : ':'}licenses`,
    '--add-data', `${resolve(base, 'helpers/PROVENANCE.md')}${windows ? ';' : ':'}licenses`,
    '--add-data', `${resolve(base, 'tmp/claims-licenses')}${windows ? ';' : ':'}licenses/dependencies`,
    resolve(base, 'helpers/claims_bridge.py')]);
  await run(resolve(base, 'helpers/bin/connectwallet-claims', windows ? 'connectwallet-claims.exe' : 'connectwallet-claims'), ['--self-test']);
}
console.log(build ? 'Standalone Automatic Claims helper built and verified.' : 'Automatic Claims helper installed and verified.');
