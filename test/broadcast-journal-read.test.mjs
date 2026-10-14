import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BroadcastJournal, transactionDigest } from '../src/broadcast-journal.mjs';

const record = { outpoint: `${'12'.repeat(32)}:0`, txid: 'ab'.repeat(32), receivingAddress: 'publicAddress123',
  status: 'unknown', updatedAt: 1, transactionHex: 'cd'.repeat(100), transactionHash: transactionDigest('cd'.repeat(100)) };
const serialized = JSON.stringify({ version: 3, records: [record] });
async function fixture(t, contents, chunkSize, { readErrorAt = Infinity, statSize } = {}) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'claimer-journal-read-')), path = join(directory, 'state.json');
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  await fs.writeFile(path, contents);
  const realOpen = fs.open;
  let reads = 0, closes = 0;
  const stub = t.mock.method(fs, 'open', async (name, flags, ...rest) => {
    const handle = await realOpen(name, flags, ...rest);
    if (name !== path || flags !== 'r') return handle;
    return {
      async stat() { const info = await handle.stat(); if (statSize !== undefined) info.size = statSize; return info; },
      async read(buffer, offset, length, position) {
        if (++reads === readErrorAt) throw Object.assign(new Error('Injected interrupted read'), { code: 'EIO' });
        return handle.read(buffer, offset, Math.min(length, chunkSize), position);
      },
      async close() { closes++; return handle.close(); },
    };
  });
  syncBuiltinESMExports();
  t.after(() => { stub.mock.restore(); syncBuiltinESMExports(); });
  return { path, journal: new BroadcastJournal(path), reads: () => reads, closes: () => closes };
}

for (const chunkSize of [1, 7, 127]) test(`short journal reads of ${chunkSize} bytes preserve the complete saved claim`, async t => {
  const { path, journal, reads, closes } = await fixture(t, serialized, chunkSize);
  assert.deepEqual(await journal.load(), [record]);
  assert.ok(reads() > 1); assert.equal(closes(), 1);
  assert.equal(journal.serializedBytes, Buffer.byteLength(JSON.stringify({ version: 3, records: [record] }, null, 2) + '\n'));
  await journal.update(record.outpoint, { ...record, status: 'accepted' });
  const reloaded = new BroadcastJournal(path); await reloaded.load();
  assert.equal(reloaded.entries()[0].status, 'accepted');
  assert.equal(reloaded.entries()[0].transactionHex, record.transactionHex);
  assert.equal(reloaded.entries()[0].transactionHash, record.transactionHash);
});

test('a valid JSON prefix in a short read cannot hide corrupt trailing journal data', async t => {
  const content = serialized + '\ncorrupt trailing data';
  const { path, journal, closes } = await fixture(t, content, Buffer.byteLength(serialized));
  await assert.rejects(journal.load());
  assert.equal(journal.loaded, false); assert.deepEqual(journal.entries(), []); assert.equal(closes(), 1);
  assert.equal(await fs.readFile(path, 'utf8'), content);
});

test('an IO error after a valid prefix cannot publish a partially read journal', async t => {
  const content = serialized + '\n';
  const { path, journal, closes } = await fixture(t, content, Buffer.byteLength(serialized), { readErrorAt: 2 });
  await assert.rejects(journal.load(), { code: 'EIO' });
  assert.equal(journal.loaded, false); assert.deepEqual(journal.entries(), []); assert.equal(closes(), 1);
  assert.equal(await fs.readFile(path, 'utf8'), content);
});

test('bounded journal loading also rejects growth after stat despite short reads', async t => {
  const content = serialized + ' '.repeat(8 * 1024 * 1024);
  const { path, journal, closes } = await fixture(t, content, 64 * 1024, { statSize: Buffer.byteLength(serialized) });
  await assert.rejects(journal.load(), /size limit/);
  assert.equal(journal.loaded, false); assert.deepEqual(journal.entries(), []); assert.equal(closes(), 1);
  assert.equal((await fs.stat(path)).size, Buffer.byteLength(content));
});

test('journal loading accepts the exact byte limit through short reads', async t => {
  const content = serialized.padEnd(8 * 1024 * 1024, ' ');
  const { journal, closes } = await fixture(t, content, 64 * 1024);
  assert.deepEqual(await journal.load(), [record]);
  assert.equal(closes(), 1);
});

test('saved identifiers and confirmation hashes cannot pass validation through string coercion', async t => {
  const { path } = await fixture(t, serialized, 127);
  for (const malformed of [
    { ...record, txid: [record.txid] },
    { outpoint: record.outpoint, txid: record.txid, receivingAddress: record.receivingAddress,
      status: 'confirmed', updatedAt: 1, blockHeight: 100, blockHash: ['ef'.repeat(32)] },
  ]) {
    const content = JSON.stringify({ version: 3, records: [malformed] });
    await fs.writeFile(path, content);
    const journal = new BroadcastJournal(path);
    await assert.rejects(journal.load());
    assert.equal(journal.loaded, false); assert.deepEqual(journal.entries(), []);
    assert.equal(await fs.readFile(path, 'utf8'), content);
  }
});

test('journal updates reject coerced identifiers without replacing the saved proof', async t => {
  const { path, journal } = await fixture(t, serialized, 127);
  await journal.load();
  for (const malformed of [
    { ...record, txid: [record.txid] },
    { txid: record.txid, receivingAddress: record.receivingAddress,
      status: 'confirmed', blockHeight: 100, blockHash: ['ef'.repeat(32)] },
  ]) {
    await assert.rejects(journal.update(record.outpoint, malformed));
    assert.deepEqual(journal.entries(), [record]);
    assert.equal(await fs.readFile(path, 'utf8'), serialized);
  }
  await assert.rejects(journal.update(`${'12'.repeat(32)}:1`, { ...record, txid: [record.txid] }));
  assert.deepEqual(journal.entries(), [record]);
  assert.equal(await fs.readFile(path, 'utf8'), serialized);
});
