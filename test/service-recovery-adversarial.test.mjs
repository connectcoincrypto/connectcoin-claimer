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
function publicRecord() {
  // Independently golden public transaction, synthetic proof framing only.
  const tx = parseTransaction('0200000001548c9fc15a3c2bc70e81307961d1350359b8d080130859f526cc1c794bd54eb30000000000ffffffff0138bd9252020000000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000');
  tx.inputs[0].witness = ['02010000220303' + claimChallenge(tx) + '02000000080000000b0000000f000000'];
  const transactionHex = serializeTransaction(tx).toString('hex');
  return { outpoint: `${tx.inputs[0].txid}:0`, txid: transactionId(tx), receivingAddress, status: 'unknown',
    transactionHex, transactionHash: transactionDigest(transactionHex) };
}
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-recovery-adversarial-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = new BroadcastJournal(join(directory, 'state.json')), record = publicRecord();
  await journal.load(); await journal.update(record.outpoint, record);
  const calls = [], rpc = new EventEmitter();
  rpc.connect = async () => {};
  rpc.close = () => {};
  rpc.request = async (method, params, options) => {
    calls.push({ method, params }); options?.beforeSend?.();
    return rpc.respond(method, params, options);
  };
  rpc.respond = async method => {
    if (method === 'gettransaction') return { tip, transaction: { hex: record.transactionHex } };
    return { txid: record.txid };
  };
  const service = new ClaimerService({ config, journal, rpcFactory: () => rpc,
    engineFactory: options => new ClaimsEngine({ ...options, poolFactory: () => ({ async start() {}, async close() {} }) }),
    discover: async () => ({ blocks: new Map(), cursor: 'coherent', tip }),
    setTimer: () => ({ unref() {} }), clearTimer: () => {} });
  t.after(() => service.stop());
  await service.start();
  const recover = () => service.reconcileBroadcasts().catch(error => { service.fail(error); throw error; });
  return { service, journal, rpc, calls, record, recover };
}

for (const malformed of [
  { name: 'wrong network', result: record => ({ tip: { ...tip, genesis_hash: '00'.repeat(32) }, transaction: { hex: record.transactionHex } }) },
  { name: 'missing transaction', result: () => ({ tip }) },
  { name: 'malformed transaction', result: () => ({ tip, transaction: { hex: 'ab'.repeat(50) } }) },
]) test(`reconciliation fails closed on ${malformed.name}, never sends replacement bytes or counts success`, async t => {
  const { service, journal, rpc, calls, record, recover } = await fixture(t);
  rpc.respond = async () => malformed.result(record);
  await assert.rejects(recover(), { helperFatal: true });
  assert.equal(service.running, false); assert.equal(service.snapshot().claims.completed, 0);
  assert.equal(calls.some(item => item.method === 'sendrawtransaction'), false);
  assert.equal(journal.unresolved()[0].transactionHex, record.transactionHex);
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
    if (method === 'gettransaction') throw Object.assign(new Error('Not indexed'), { code: -32004 });
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
    if (method === 'gettransaction') throw Object.assign(new Error('Not indexed'), { code: -32004 });
    return { txid: record.txid };
  };
  await recover(); await recover();
  assert.equal(service.running, true); assert.equal(service.snapshot().claims.completed, 1);
  assert.equal(service.snapshot().claims.attempts, 0);
  assert.equal(journal.unresolved().length, 0); assert.equal(journal.entries()[0].status, 'accepted');
  assert.equal(calls.filter(item => item.method === 'sendrawtransaction').length, 1);
  assert.equal(service.reserved.has(record.outpoint), true);
});
