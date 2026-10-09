import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { encodeAddress } from '../src/core/crypto.mjs';
import { parseConfig, ensureConfig, readConfig, CONFIG_TEMPLATE } from '../src/config.mjs';
import { acquireLock } from '../src/lock.mjs';

const address = encodeAddress('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
const conf = `receiving_address=${address}\n`;
const run = promisify(execFile);
async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-config-test-'));
  t.after(() => rm(directory, { recursive: true, force: true })); return directory;
}
test('default values match the requested config and address-only mainnet policy', () => {
  assert.throws(() => parseConfig(CONFIG_TEMPLATE), /receiving_address/);
  const config = parseConfig(conf);
  assert.equal(config.connectionsPerSecond, 100); assert.equal(config.concurrency, 100);
  assert.equal(config.minExpectedReturn, 1000); assert.equal(config.network, 'main');
  assert.deepEqual(config.rpc, { host: 'connectcoin4.com', port: 48190 });
  assert.equal(config.feeRate, 1500); assert.equal(config.lookbackBlocks, 600);
  assert.equal(Object.isFrozen(config.rpc), true);
});
test('supports rates beyond 256 and validates boundaries without silent clamping', () => {
  assert.equal(parseConfig(conf + 'max_simultaneous_connections=1000').concurrency, 1000);
  assert.equal(parseConfig(conf + 'max_connections_per_second=2147483647').connectionsPerSecond, 2147483647);
  assert.equal(parseConfig(conf + 'min_connects_per_connection_second=0').minExpectedReturn, 0);
  for (const value of ['0', '-1', '1.2', '2147483648', '1e3', 'NaN', 'Infinity', '']) {
    assert.throws(() => parseConfig(conf + `max_connections_per_second=${value}`));
  }
  for (const row of ['lookback_blocks=601', 'fee_rate=0', 'rpc_port=65536', 'rpc_host=https://example.com', 'min_connects_per_connection_second=-1']) {
    assert.throws(() => parseConfig(conf + row));
  }
});
test('rejects unknown keys, duplicate settings, wrong network, invalid encoding and secrets', () => {
  for (const row of ['seed=anything', 'private_key=anything', 'network=testnet4', 'rpc_host=x\nrpc_host=y', '[section]']) assert.throws(() => parseConfig(conf + row));
  assert.throws(() => parseConfig(`receiving_address=${encodeAddress('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'testnet4')}`));
  assert.throws(() => parseConfig(conf + '\0')); assert.throws(() => parseConfig('#'.repeat(16385)));
  assert.equal(parseConfig('\uFEFF# comment\r\n' + conf).receivingAddress, address);
});
test('exclusive config creation never overwrites an existing file; bounded UTF-8 read', async t => {
  const path = join(await temporary(t), 'claimer.conf');
  assert.equal(await ensureConfig(path), true); assert.equal(await ensureConfig(path), false);
  assert.equal(await readFile(path, 'utf8'), CONFIG_TEMPLATE);
  await writeFile(path, conf); assert.equal(await ensureConfig(path), false);
  assert.equal((await readConfig(path)).receivingAddress, address);
  await writeFile(path, Buffer.from([0xff])); await assert.rejects(readConfig(path));
  await writeFile(path, '#'.repeat(16385)); await assert.rejects(readConfig(path), /too large/);
});
test('one instance per configuration and lock release cannot delete a changed owner', async t => {
  const path = join(await temporary(t), 'claimer.conf.lock');
  const release = await acquireLock(path); await assert.rejects(acquireLock(path), /Another instance/);
  await release(); const releaseAgain = await acquireLock(path);
  await writeFile(path, 'another-owner'); await releaseAgain(); assert.equal(await readFile(path, 'utf8'), 'another-owner');
});
test('CLI help/version have no side effects; default first run creates empty config offline', async t => {
  const directory = await temporary(t), cli = resolve('src/cli.mjs');
  assert.match((await run(process.execPath, [cli, '--help'], { cwd: directory })).stdout, /Ctrl\+C/);
  assert.equal((await run(process.execPath, [cli, '--version'], { cwd: directory })).stdout.trim(), '1.0.0');
  await assert.rejects(readFile(join(directory, 'claimer.conf')), { code: 'ENOENT' });
  await assert.rejects(run(process.execPath, [cli], { cwd: directory }), error => error.code === 2 && /No connections were made/.test(error.stdout));
  assert.equal(await readFile(join(directory, 'claimer.conf'), 'utf8'), CONFIG_TEMPLATE);
  await assert.rejects(run(process.execPath, [cli], { cwd: directory }), error => error.code === 1 && /receiving_address/.test(error.stderr));
  await assert.rejects(run(process.execPath, [cli, '--bad'], { cwd: directory }), error => error.code === 1);
});
