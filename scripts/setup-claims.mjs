// Build the C++ protocol-4 helper. Python is a differential-test reference only.
import { execFile, spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { availableParallelism } from 'node:os';
import { ConnectionPool } from '../src/core/claim-pool.mjs';
import { validateNativeHelperSecurity } from './helper-security.mjs';

const base = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv.slice(2).some(arg => arg !== '--build')) throw new Error('Usage: node scripts/setup-claims.mjs [--build]');
const cmake = process.env.CMAKE || 'cmake';
const directory = resolve(base, 'tmp/native-build');
const destination = resolve(base, 'helpers/native-bin/connectwallet-claims');
const referencePython = resolve(base, '.claims-venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const testPython = process.env.CLAIMER_TEST_PYTHON || (existsSync(referencePython) ? referencePython : process.env.PYTHON);
const parallel = process.env.CLAIMER_BUILD_JOBS ?? String(Math.min(4, availableParallelism()));
if (!/^[1-9][0-9]*$/.test(parallel) || Number(parallel) > 256) throw new Error('Invalid CLAIMER_BUILD_JOBS.');
const run = (command, args) => new Promise((accept, reject) => {
  const child = spawn(command, args, { cwd: base, stdio: 'inherit', shell: false, windowsHide: true });
  child.once('error', reject);
  child.once('exit', code => code === 0 ? accept() : reject(new Error(`${command} exited with ${code}`)));
});
await run(cmake, ['-S', resolve(base, 'native'), '-B', directory, '-DCMAKE_BUILD_TYPE=Release',
  ...(testPython ? [`-DCLAIMER_TEST_PYTHON=${testPython}`] : []),
  ...(process.platform === 'win32' ? ['-A', process.arch === 'arm64' ? 'ARM64' : 'x64'] : []),
  ...(process.platform === 'darwin' ? ['-DCMAKE_OSX_DEPLOYMENT_TARGET=15.0', `-DCMAKE_OSX_ARCHITECTURES=${process.arch === 'arm64' ? 'arm64' : 'x86_64'}`] : []),
  `-DCMAKE_INSTALL_PREFIX=${destination}`]);
await run(cmake, ['--build', directory, '--config', 'Release', '--parallel', parallel]);
await run(process.env.CTEST || 'ctest', ['--test-dir', directory, '-C', 'Release', '--output-on-failure']);
await run(cmake, ['--install', directory, '--config', 'Release', '--component', 'claimerRuntime']);
const command = resolve(destination, process.platform === 'win32' ? 'connectwallet-claims.exe' : 'connectwallet-claims');
const name = process.platform === 'win32' ? 'connectwallet-claims.exe' : 'connectwallet-claims';
const built = [resolve(directory, 'Release', name), resolve(directory, name)].find(existsSync);
if (!built || createHash('sha256').update(await readFile(built)).digest('hex') !==
    createHash('sha256').update(await readFile(command)).digest('hex')) throw new Error('Installed helper differs from the fresh build.');
const { stdout } = await promisify(execFile)(command, ['--self-test', '--require-native-mbedtls'], { timeout: 30000, windowsHide: true, maxBuffer: 65536 });
validateNativeHelperSecurity(stdout);
const pool = new ConnectionPool({ helper: { command, args: [], native: true } });
try { await pool.start({}); } finally { await pool.close(); }
await mkdir(resolve(destination, 'licenses'), { recursive: true });
for (const name of ['LICENSE', 'PROVENANCE.md']) {
  await writeFile(resolve(destination, 'licenses', name), await readFile(resolve(base, 'native', name)));
}
console.log('C++ Automatic Claims helper built; offline protocol startup/shutdown verified.');
