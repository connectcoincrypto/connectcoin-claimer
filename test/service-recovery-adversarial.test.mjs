import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ClaimerService } from '../src/service.mjs';
import { BroadcastJournal, transactionDigest } from '../src/broadcast-journal.mjs';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { parseTransaction, serializeTransaction, claimChallenge, transactionId } from '../src/core/transaction.mjs';

const receivingAddress = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
const tip = { height: 100, hash: '22'.repeat(32), mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };
const config = { receivingAddress, network: 'main', rpc: { host: 'invalid.example', port: 48190 },
  connectionsPerSecond: 100, concurrency: 100, minExpectedReturn: 1000, lookbackBlocks: 600, feeRate: 1500 };
const pendingReceipt = (record, fields = {}) => ({ tip, txid: record.txid, status: 'pending', confirmations: 0, ...fields });
const confirmedReceipt = (record, receiptTip = tip) => ({ tip: receiptTip, txid: record.txid,
  status: 'confirmed', block_height: receiptTip.height, block_hash: receiptTip.hash, confirmations: 1 });
function publicRecord() {
  // Independently golden public transaction, synthetic proof framing only.
  const tx = parseTransaction('0200000001548c9fc15a3c2bc70e81307961d1350359b8d080130859f526cc1c794bd54eb30000000000ffffffff0138bd9252020000000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000');
  tx.inputs[0].witness = ['02010000220303' + claimChallenge(tx) + '02000000080000000b0000000f000000'];
  const transactionHex = serializeTransaction(tx).toString('hex');
  return { outpoint: `${tx.inputs[0].txid}:0`, txid: transactionId(tx), receivingAddress, status: 'unknown',
    transactionHex, transactionHash: transactionDigest(transactionHex) };
}
async function fixture(t, status = 'unknown', savedFields = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-recovery-adversarial-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.json');
  const journal = new BroadcastJournal(path), record = { ...publicRecord(), status, ...savedFields };
  await journal.load(); await journal.update(record.outpoint, record);
  const calls = [], rpc = new EventEmitter();
  rpc.connect = async () => {};
  rpc.close = () => {};
  rpc.request = async (method, params, options) => {
    assert.notEqual(method, 'gettransaction', 'Recovery must validate saved bytes locally and never fetch a claim witness.');
    calls.push({ method, params }); options?.beforeSend?.();
    return rpc.respond(method, params, options);
  };
  rpc.respond = async method => {
    if (method === 'gettransactionstatus') return pendingReceipt(record);
    assert.equal(method, 'sendrawtransaction');
    return { txid: record.txid };
  };
  const service = new ClaimerService({ config, journal, rpcFactory: () => rpc,
    engineFactory: options => new ClaimsEngine({ ...options, poolFactory: () => ({ async start() {}, async close() {} }) }),
    discover: async () => ({ blocks: new Map(), cursor: 'coherent', tip }),
    setTimer: () => ({ unref() {} }), clearTimer: () => {} });
  t.after(() => service.stop());
  await service.start();
  const recover = () => service.reconcileBroadcasts().catch(error => { service.fail(error); throw error; });
  return { service, journal, rpc, calls, record, recover, path };
}

for (const status of ['unknown', 'accepted']) for (const malformed of [
  { name: 'wrong network', result: record => pendingReceipt(record, { tip: { ...tip, genesis_hash: '00'.repeat(32) } }) },
  { name: 'missing receipt identity', result: () => ({ tip, status: 'pending', confirmations: 0 }) },
  { name: 'malformed saved transaction', savedHex: 'ab'.repeat(50), result: record => pendingReceipt(record) },
  { name: 'conflicting reported transaction ID', result: record => pendingReceipt(record, { txid: 'ab'.repeat(32) }) },
  { name: 'pending transaction with malformed block hash', result: record => pendingReceipt(record, { block_hash: 'bad' }) },
  { name: 'pending transaction with malformed confirmations', result: record => pendingReceipt(record, { confirmations: '1' }) },
  { name: 'false genesis confirmation', result: record => ({ ...confirmedReceipt(record), block_height: 0, confirmations: 101 }) },
  { name: 'malformed saved transaction before a location race', savedHex: 'ab'.repeat(50),
    result: record => pendingReceipt(record, { confirmations: 1 }) },
  { name: 'false genesis inside an orphaned-index race', result: record => ({ ...confirmedReceipt(record), block_height: 0, confirmations: 0 }) },
]) test(`${status} reconciliation fails closed on ${malformed.name}, never sends replacement bytes or counts success`, async t => {
  const savedFields = malformed.savedHex ? { transactionHex: malformed.savedHex, transactionHash: transactionDigest(malformed.savedHex) } : {};
  const { service, journal, rpc, calls, record, recover, path } = await fixture(t, status, savedFields);
  rpc.respond = async () => malformed.result(record);
  await assert.rejects(recover(), { helperFatal: true });
  assert.equal(service.running, false); assert.equal(service.snapshot().claims.completed, 0);
  assert.equal(calls.some(item => item.method === 'sendrawtransaction'), false);
  if (malformed.savedHex) assert.equal(calls.length, 0, 'Damaged local bytes fail before any receipt lookup.');
  assert.equal(journal.entries()[0].transactionHex, record.transactionHex);
  assert.equal(service.reserved.has(record.outpoint), true);
  await service.stop();
  const reloaded = new BroadcastJournal(path); await reloaded.load();
  const saved = reloaded.entries()[0];
  assert.equal(saved.status, status);
  assert.equal(saved.transactionHex, record.transactionHex);
  assert.equal(saved.transactionHash, record.transactionHash);
});

for (const status of ['unknown', 'accepted']) for (const race of [
  { name: 'index pending with positive confirmations', receipt: record => pendingReceipt(record, { confirmations: 1 }) },
  { name: 'index synchronizing during receipt lookup', code: -32001 },
  { name: 'index invalidated during receipt lookup', code: -32011 },
  { name: 'index confirmed with zero confirmations', receipt: record => ({ ...confirmedReceipt(record), confirmations: 0 }) },
  { name: 'index confirmed in another catalog block', receipt: record => ({ ...confirmedReceipt(record), block_height: 99, block_hash: 'ab'.repeat(32), confirmations: 2 }),
    window: { tip, blocks: [{ height: 99, hash: 'cd'.repeat(32) }], window: 600 } },
]) test(`${status} ${race.name} retries without stopping, losing proof, sending bytes or counting success`, async t => {
  const { service, journal, rpc, calls, record, recover, path } = await fixture(t, status);
  if (race.window) service.blockWindow = race.window;
  rpc.respond = async () => {
    if (race.code) throw Object.assign(new Error('Indexed state changed'), { code: race.code });
    return race.receipt(record);
  };
  await recover();
  assert.equal(service.running, true);
  assert.equal(service.snapshot().claims.completed, 0);
  assert.equal(journal.entries()[0].status, status);
  assert.equal(journal.entries()[0].transactionHex, record.transactionHex);
  assert.ok(service.recoveryDue.get(record.outpoint) > Date.now());
  const reloaded = new BroadcastJournal(path); await reloaded.load();
  assert.equal(reloaded.entries()[0].status, status);
  assert.equal(reloaded.entries()[0].transactionHex, record.transactionHex);
  assert.equal(reloaded.entries()[0].transactionHash, record.transactionHash);
  rpc.respond = async () => confirmedReceipt(record);
  service.recoveryDue.clear(); await recover();
  assert.equal(journal.entries()[0].status, 'confirmed');
  assert.equal(service.snapshot().claims.completed, status === 'unknown' ? 1 : 0);
  assert.equal(service.snapshot().claims.attempts, 0);
  assert.equal(calls.some(item => item.method === 'sendrawtransaction'), false);
  assert.equal(service.reserved.has(record.outpoint), true);
});

for (const status of ['unknown', 'accepted']) test(`${status} coherent pending receipt retains proof and later confirmation counts at most once`, async t => {
  const { service, journal, rpc, calls, record, recover, path } = await fixture(t, status);
  rpc.respond = async () => pendingReceipt(record);
  await recover();
  assert.equal(journal.entries()[0].status, 'accepted');
  assert.equal(journal.entries()[0].transactionHex, record.transactionHex);
  assert.equal(service.snapshot().claims.completed, status === 'unknown' ? 1 : 0);
  const reloaded = new BroadcastJournal(path); await reloaded.load();
  assert.equal(reloaded.entries()[0].transactionHex, record.transactionHex);
  rpc.respond = async () => confirmedReceipt(record);
  service.recoveryDue.clear(); await recover();
  assert.equal(journal.entries()[0].status, 'confirmed');
  assert.equal(journal.entries()[0].transactionHex, undefined);
  service.recoveryDue.clear(); await recover();
  assert.equal(service.snapshot().claims.completed, status === 'unknown' ? 1 : 0);
  assert.equal(service.snapshot().claims.attempts, 0);
  assert.equal(calls.some(item => item.method === 'sendrawtransaction'), false);
  assert.equal(service.reserved.has(record.outpoint), true);
});

for (const stage of ['before-replay', 'accepted-receipt']) test(`reconciliation disk I/O failure at ${stage} preserves the durable pending claim`, async t => {
  const { service, journal, rpc, calls, record, recover } = await fixture(t);
  if (stage === 'before-replay') rpc.respond = async () => { throw Object.assign(new Error('Not indexed'), { code: -32004 }); };
  journal.update = async () => { throw Object.assign(new Error('Disk I/O failed'), { code: 'EIO' }); };
  await assert.rejects(recover(), { code: 'EIO', helperFatal: true });
  assert.equal(service.running, false); assert.equal(service.snapshot().claims.completed, 0);
  assert.equal(calls.some(item => item.method === 'sendrawtransaction'), false);
  assert.equal(journal.unresolved()[0].transactionHash, record.transactionHash);
  assert.equal(service.reserved.has(record.outpoint), true);
});

test('a mismatching retry receipt retains identical bytes and cannot complete the recovered claim', async t => {
  const { service, journal, rpc, calls, record, recover } = await fixture(t);
  rpc.respond = async method => {
    if (method === 'gettransactionstatus') throw Object.assign(new Error('Not indexed'), { code: -32004 });
    return { txid: '99'.repeat(32) };
  };
  await assert.rejects(recover(), { helperFatal: true });
  assert.equal(service.running, false); assert.equal(service.snapshot().claims.completed, 0);
  const sends = calls.filter(item => item.method === 'sendrawtransaction');
  assert.equal(sends.length, 1); assert.equal(sends[0].params.transaction_hex, record.transactionHex);
  assert.equal(journal.unresolved()[0].transactionHex, record.transactionHex);
});

test('real replay validation and real engine count one durable recovered receipt, without new capture work', async t => {
  const { service, journal, rpc, calls, record, recover } = await fixture(t);
  rpc.respond = async method => {
    if (method === 'gettransactionstatus') throw Object.assign(new Error('Not indexed'), { code: -32004 });
    return { txid: record.txid };
  };
  await recover(); await recover();
  assert.equal(service.running, true); assert.equal(service.snapshot().claims.completed, 1);
  assert.equal(service.snapshot().claims.attempts, 0);
  assert.equal(journal.unresolved().length, 0); assert.equal(journal.entries()[0].status, 'accepted');
  assert.equal(calls.filter(item => item.method === 'sendrawtransaction').length, 1);
  assert.equal(service.reserved.has(record.outpoint), true);
});

for (const status of ['unknown', 'accepted']) test(`${status} confirmation ahead of local discovery keeps its witness until the block is observed`, async t => {
  const { service, journal, rpc, calls, record, recover, path } = await fixture(t, status);
  const ahead = { ...tip, height: tip.height + 1, hash: 'ab'.repeat(32) };
  service.blockWindow = { tip, blocks: [{ height: tip.height, hash: tip.hash }], window: 600 };
  rpc.respond = async () => confirmedReceipt(record, ahead);
  await recover();
  assert.equal(service.running, true);
  assert.equal(journal.entries()[0].status, status);
  assert.equal(journal.entries()[0].transactionHex, record.transactionHex);
  assert.equal(service.snapshot().claims.completed, 0);
  assert.equal(service.anchoredConfirmations.has(record.outpoint), false);
  const disk = new BroadcastJournal(path); await disk.load();
  assert.equal(disk.entries()[0].transactionHex, record.transactionHex);
  service.discover = async () => ({ blocks: new Map(), cursor: 'caught-up', tip: ahead,
    window: { tip: ahead, blocks: [{ height: ahead.height, hash: ahead.hash }, { height: tip.height, hash: tip.hash }], window: 600 } });
  await service.cycle(); service.recoveryDue.clear(); await recover();
  assert.equal(journal.entries()[0].status, 'confirmed');
  assert.equal(service.anchoredConfirmations.has(record.outpoint), true);
  assert.equal(service.snapshot().claims.completed, status === 'unknown' ? 1 : 0);
  assert.equal(service.snapshot().claims.attempts, 0);
  assert.equal(calls.some(item => item.method === 'sendrawtransaction'), false);
});

test('a freshly compacted confirmation can reopen after an immediate rollback without an intermediate discovery', async t => {
  const { service, journal, rpc, record, recover } = await fixture(t);
  const fundingBlock = 'cd'.repeat(32), fundingHeight = tip.height - 1;
  const bounty = { txid: record.outpoint.split(':')[0], vout: 0, block_hash: fundingBlock, block_height: fundingHeight,
    amount: '10000000000', domain: 'example.com', connection_work_target: 'ff'.repeat(32),
    root_certificates_version: 1, signature_algorithms_mask: 7, status: 'available' };
  let currentTip = tip;
  service.discover = async () => ({ blocks: new Map([[fundingBlock, [bounty]]]), cursor: 'coherent', tip: currentTip,
    window: { tip: currentTip, blocks: currentTip === tip ? [{ height: tip.height, hash: tip.hash }, { height: fundingHeight, hash: fundingBlock }]
      : [{ height: fundingHeight, hash: fundingBlock }], window: 600 } });
  await service.cycle();
  rpc.respond = async () => confirmedReceipt(record);
  await recover();
  assert.equal(journal.entries()[0].status, 'confirmed');
  assert.equal(service.snapshot().claims.completed, 1);
  currentTip = { ...tip, height: fundingHeight, hash: fundingBlock };
  await service.cycle();
  assert.equal(service.reserved.has(record.outpoint), false, 'The already-observed confirmation must not strand the outpoint after rollback');
  assert.equal(journal.entries().length, 0);
  assert.equal(service.engine.queue.has(record.outpoint), true);
  assert.equal(service.snapshot().claims.attempts, 0);
  assert.equal(service.snapshot().claims.completed, 1);
});

for (const changed of ['rollback', 'same-height-reorg']) test(`queued confirmation rechecks the local ${changed} before discarding its witness`, async t => {
  const { service, journal, rpc, record, recover, path } = await fixture(t);
  service.blockWindow = { tip, blocks: [{ height: tip.height, hash: tip.hash }], window: 600 };
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  const update = journal.update.bind(journal);
  journal.update = (key, fields, options) => {
    if (fields?.status === 'confirmed') {
      journal.writing = release.promise;
      const pending = update(key, fields, options);
      entered.resolve();
      return pending;
    }
    return update(key, fields, options);
  };
  rpc.respond = async () => confirmedReceipt(record);
  const pending = recover();
  try {
    await entered.promise;
    service.tip = { ...tip, height: changed === 'rollback' ? tip.height - 1 : tip.height, hash: 'ab'.repeat(32) };
    service.blockWindow = { tip: service.tip, blocks: [{ height: service.tip.height, hash: service.tip.hash }], window: 600 };
  } finally { release.resolve(); }
  await pending;
  assert.equal(service.running, true);
  assert.equal(journal.entries()[0].status, 'unknown');
  assert.equal(journal.entries()[0].transactionHex, record.transactionHex);
  assert.equal(service.snapshot().claims.completed, 0);
  assert.equal(service.anchoredConfirmations.has(record.outpoint), false);
  const disk = new BroadcastJournal(path); await disk.load();
  assert.equal(disk.entries()[0].transactionHex, record.transactionHex);
});
