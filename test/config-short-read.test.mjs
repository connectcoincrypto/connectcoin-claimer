import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readConfig, parseConfig } from '../src/config.mjs';

const prefix = 'receiving_address=cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya\n';
const contents = prefix + '# Configuração de teste\nmax_connections_per_second=800\nmax_simultaneous_connections=400\nrpc_host=example.com\n';
async function fixture(t, bytes, chunkSize, errorAt = Infinity) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'claimer-config-short-read-')), path = join(directory, 'claimer.conf');
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(path, bytes);
  let reads = 0, closes = 0;
  const realOpen = fs.open;
  const stub = t.mock.method(fs, 'open', async (name, flags, ...rest) => {
    const handle = await realOpen(name, flags, ...rest);
    if (name !== path || flags !== 'r') return handle;
    return {
      stat: () => handle.stat(),
      async read(buffer, offset, length, position) {
        if (++reads === errorAt) throw Object.assign(new Error('Injected configuration read error'), { code: 'EIO' });
        return handle.read(buffer, offset, Math.min(chunkSize, length), position);
      },
      async close() { closes++; return handle.close(); },
    };
  });
  syncBuiltinESMExports();
  t.after(() => { stub.mock.restore(); syncBuiltinESMExports(); });
  return { path, closes: () => closes };
}

for (const chunkSize of [1, 11, Buffer.byteLength(prefix)]) test(`short configuration reads of ${chunkSize} bytes cannot replace later settings with defaults`, async t => {
  const { path, closes } = await fixture(t, contents, chunkSize);
  assert.deepEqual(await readConfig(path), parseConfig(contents));
  assert.equal(closes(), 1); assert.equal(await fs.readFile(path, 'utf8'), contents);
});

for (const [name, bytes, errorAt] of [
  ['duplicate field after a valid prefix', prefix + 'max_connections_per_second=800\nmax_connections_per_second=400\n'],
  ['invalid UTF-8 after a valid prefix', Buffer.concat([Buffer.from(prefix), Buffer.from([0xff])])],
  ['IO error after a valid prefix', contents, 2],
  ['oversized comment after a valid prefix', prefix + '#' + 'x'.repeat(16385)],
]) test(`configuration rejects ${name} without overwriting the source file`, async t => {
  const { path, closes } = await fixture(t, bytes, Buffer.byteLength(prefix), errorAt);
  await assert.rejects(readConfig(path));
  assert.equal(closes(), 1); assert.deepEqual(await fs.readFile(path), Buffer.from(bytes));
});

test('configuration accepts the exact byte limit with short reads', async t => {
  const text = contents + '#' + 'x'.repeat(16384 - Buffer.byteLength(contents) - 1);
  const { path, closes } = await fixture(t, text, 127);
  assert.deepEqual(await readConfig(path), parseConfig(contents));
  assert.equal(closes(), 1);
});
