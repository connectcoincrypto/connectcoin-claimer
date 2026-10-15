import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EventEmitter } from 'node:events';
import { BroadcastJournal, transactionDigest } from '../src/broadcast-journal.mjs';
import { ClaimerService } from '../src/service.mjs';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { parseTransaction, serializeTransaction, claimChallenge, transactionId } from '../src/core/transaction.mjs';

const record = {
  txid: 'ab'.repeat(32), receivingAddress: 'publicAddress123', status: 'pending',
  // Storage framing fixture only; transaction/proof validation is tested at
  // the service boundary. The journal must preserve these exact public bytes.
  transactionHex: 'cd'.repeat(100), transactionHash: transactionDigest('cd'.repeat(100)),
};
const key = index => `${'12'.repeat(32)}:${index}`;

async function fixture(t, stage) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'claimer-journal-durability-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.json'), journal = new BroadcastJournal(path);
  await journal.load();
  const realOpen = fs.open, platform = Object.getOwnPropertyDescriptor(process, 'platform');
  let fail = false, directoryWrites = 0;
  const fault = () => {
    if (fail) { fail = false; throw Object.assign(new Error(`Injected directory ${stage} failure`), { code: 'EIO' }); }
  };
  // Exercise the POSIX post-rename path even on Windows. File writes, fsync,
  // atomic replacement and reload are real; only directory IO is injected.
  Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
  const mockedOpen = t.mock.method(fs, 'open', async (pathToOpen, flags, ...rest) => {
    if (pathToOpen !== directory || flags !== 'r') return realOpen(pathToOpen, flags, ...rest);
    directoryWrites++;
    if (stage === 'open') fault();
    return {
      async sync() { if (stage === 'sync') fault(); },
      async close() { if (stage === 'close') fault(); },
    };
  });
  syncBuiltinESMExports();
  t.after(() => {
    mockedOpen.mock.restore(); syncBuiltinESMExports();
    Object.defineProperty(process, 'platform', platform);
  });
  return { path, journal, failNext: () => { fail = true; }, writes: () => directoryWrites };
}

for (const stage of ['open', 'sync', 'close']) {
  test(`confirmation published before directory ${stage} failure remains recoverable across restart and reorg`, async t => {
    const { path, journal, failNext } = await fixture(t, stage);
    const receivingAddress = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
    const tip = { height: 100, hash: '22'.repeat(32), mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };
    const tx = parseTransaction('0200000001548c9fc15a3c2bc70e81307961d1350359b8d080130859f526cc1c794bd54eb30000000000ffffffff0138bd9252020000000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000');
    tx.inputs[0].witness = ['02010000220303' + claimChallenge(tx) + '02000000080000000b0000000f000000'];
    const transactionHex = serializeTransaction(tx).toString('hex'), outpoint = `${tx.inputs[0].txid}:0`;
    const saved = { txid: transactionId(tx), receivingAddress, status: 'unknown',
      transactionHex, transactionHash: transactionDigest(transactionHex) };
    await journal.update(outpoint, saved);
    const fundingHash = '33'.repeat(32), calls = [];
    const bounty = { txid: tx.inputs[0].txid, vout: 0, block_hash: fundingHash, block_height: 99,
      amount: '10000000000', domain: 'example.com', connection_work_target: 'ff'.repeat(32),
      root_certificates_version: 1, signature_algorithms_mask: 7, status: 'available' };
    const config = { receivingAddress, network: 'main', rpc: { host: 'invalid.example', port: 48190 },
      connectionsPerSecond: 100, concurrency: 100, minExpectedReturn: 1000, lookbackBlocks: 600, feeRate: 1500 };
    let currentTip = tip;
    const makeService = journal => {
      const rpc = new EventEmitter(); rpc.connect = async () => {}; rpc.close = () => {};
      rpc.request = async (method, params) => {
        calls.push(method); assert.equal(method, 'gettransactionstatus'); assert.equal(params.txid, saved.txid);
        return { tip, txid: saved.txid, status: 'confirmed', block_hash: tip.hash, block_height: tip.height, confirmations: 1 };
      };
      return new ClaimerService({ config, journal, rpcFactory: () => rpc,
        engineFactory: options => {
          const engine = new ClaimsEngine(options);
          // Exercise real admission/counter ownership without starting fresh
          // capture/funding work once the orphaned reservation is released.
          engine.pump = async () => {};
          return engine;
        },
        discover: async () => ({ blocks: new Map([[fundingHash, [bounty]]]), cursor: 'coherent', tip: currentTip,
          window: { tip: currentTip, blocks: [{ height: 100, hash: currentTip.hash }, { height: 99, hash: fundingHash }], window: 600 } }),
        setTimer: () => ({ unref() {} }), clearTimer: () => {} });
    };
    const original = makeService(journal); t.after(() => original.stop()); await original.start();
    failNext();
    await assert.rejects(original.reconcileBroadcasts().catch(error => { original.fail(error); throw error; }), { code: 'EIO', helperFatal: true });
    assert.equal(original.running, false); assert.equal(original.snapshot().claims.completed, 0);
    assert.equal(original.reserved.has(outpoint), true);
    await original.stop();
    // The rename succeeded: a fresh process must adopt the visible confirmed
    // marker, without inventing an ACK/counter or replaying compacted bytes.
    const reloaded = new BroadcastJournal(path), restarted = makeService(reloaded);
    t.after(() => restarted.stop()); await restarted.start();
    assert.equal(reloaded.entries()[0].status, 'confirmed');
    assert.equal(reloaded.entries()[0].transactionHex, undefined);
    assert.equal(restarted.reserved.has(outpoint), true);
    assert.equal(restarted.engine.queue.has(outpoint), false);
    assert.equal(restarted.snapshot().claims.completed, 0);
    currentTip = { ...tip, hash: '44'.repeat(32) };
    await restarted.cycle();
    assert.equal(restarted.reserved.has(outpoint), false);
    assert.equal(restarted.engine.queue.has(outpoint), true);
    assert.equal(reloaded.entries().length, 0);
    const disk = new BroadcastJournal(path); await disk.load(); assert.deepEqual(disk.entries(), []);
    assert.equal(restarted.snapshot().claims.completed, 0); assert.equal(restarted.snapshot().claims.attempts, 0);
    assert.deepEqual(calls, ['gettransactionstatus']);
  });

  test(`queued journal write preserves the published record after directory ${stage} fails`, async t => {
    const { path, journal, failNext, writes } = await fixture(t, stage);
    failNext();
    const failed = journal.update(key(0), record);
    const rejection = assert.rejects(failed, { code: 'EIO' });
    // This write is already waiting before the first operation fails.
    const queued = journal.update(key(1), { ...record, txid: 'ef'.repeat(32) });
    await Promise.all([rejection, queued]);
    await journal.flush();
    assert.equal(writes(), 2);
    assert.equal(journal.entries().length, 2);
    const disk = new BroadcastJournal(path); await disk.load();
    assert.deepEqual(disk.entries(), journal.entries());
    for (const saved of disk.entries()) {
      assert.equal(saved.transactionHex, record.transactionHex);
      assert.equal(saved.transactionHash, record.transactionHash);
    }
    assert.equal(journal.serializedBytes, (await fs.stat(path)).size);
  });

  test(`failed directory ${stage} after publishing acceptance cannot downgrade the retained proof`, async t => {
    const { path, journal, failNext } = await fixture(t, stage);
    await journal.update(key(0), record);
    failNext();
    await assert.rejects(journal.update(key(0), { ...record, status: 'accepted' }), { code: 'EIO' });
    assert.equal(journal.entries()[0].status, 'accepted');
    await assert.rejects(journal.update(key(0), { ...record, status: 'unknown' }), /accepted claim cannot become pending/);
    await journal.update(key(1), record);
    const disk = new BroadcastJournal(path); await disk.load();
    const accepted = disk.entries().find(row => row.outpoint === key(0));
    assert.equal(accepted.status, 'accepted');
    assert.equal(accepted.transactionHex, record.transactionHex);
    assert.equal(accepted.transactionHash, record.transactionHash);
    assert.deepEqual(disk.entries(), journal.entries());
  });

  test(`service reports directory ${stage} failure without losing an observed receipt or crediting success`, async t => {
    const { path, journal, failNext } = await fixture(t, stage);
    const receivingAddress = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
    const tip = { height: 100, hash: '22'.repeat(32), mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };
    const tx = parseTransaction('0200000001548c9fc15a3c2bc70e81307961d1350359b8d080130859f526cc1c794bd54eb30000000000ffffffff0138bd9252020000000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000');
    tx.inputs[0].witness = ['02010000220303' + claimChallenge(tx) + '02000000080000000b0000000f000000'];
    const transactionHex = serializeTransaction(tx).toString('hex'), outpoint = `${tx.inputs[0].txid}:0`;
    const saved = { txid: transactionId(tx), receivingAddress, status: 'unknown',
      transactionHex, transactionHash: transactionDigest(transactionHex) };
    await journal.update(outpoint, saved);
    const rpc = new EventEmitter(), calls = [];
    rpc.connect = async () => {}; rpc.close = () => {};
    rpc.request = async (method, params, options) => {
      calls.push(method); options?.beforeSend?.();
      assert.equal(method, 'gettransactionstatus'); assert.equal(params.txid, saved.txid);
      return { tip, txid: saved.txid, status: 'pending', confirmations: 0 };
    };
    const config = { receivingAddress, network: 'main', rpc: { host: 'invalid.example', port: 48190 },
      connectionsPerSecond: 100, concurrency: 100, minExpectedReturn: 1000, lookbackBlocks: 600, feeRate: 1500 };
    const service = new ClaimerService({ config, journal, rpcFactory: () => rpc,
      engineFactory: options => new ClaimsEngine({ ...options, poolFactory: () => ({ async start() {}, async close() {} }) }),
      discover: async () => ({ blocks: new Map(), cursor: 'coherent', tip }),
      setTimer: () => ({ unref() {} }), clearTimer: () => {} });
    t.after(() => service.stop()); await service.start(); failNext();
    await assert.rejects(service.reconcileBroadcasts().catch(error => { service.fail(error); throw error; }), { code: 'EIO', helperFatal: true });
    assert.equal(service.running, false); assert.equal(service.snapshot().claims.completed, 0);
    assert.equal(service.snapshot().claims.attempts, 0); assert.equal(service.reserved.has(outpoint), true);
    assert.deepEqual(calls, ['gettransactionstatus']);
    await service.stop();
    const disk = new BroadcastJournal(path); await disk.load();
    assert.equal(disk.entries()[0].status, 'accepted');
    assert.equal(disk.entries()[0].transactionHex, transactionHex);
    assert.equal(disk.entries()[0].transactionHash, saved.transactionHash);
    assert.deepEqual(journal.entries(), disk.entries());
  });
}
