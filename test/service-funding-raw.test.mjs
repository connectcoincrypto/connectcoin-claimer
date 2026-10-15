import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { ClaimerService } from '../src/service.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { parseTransaction, serializeTransaction, transactionId } from '../src/core/transaction.mjs';

const block = '2'.repeat(64), tip = { height: 100, hash: block, mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };
const config = { receivingAddress: 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya',
  connectionsPerSecond: 800, concurrency: 800, minExpectedReturn: 1000, rpc: { host: 'invalid.example', port: 48190 },
  network: 'main', lookbackBlocks: 600, feeRate: 1500 };
const funding = parseTransaction('02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff0100e40b5402000000020b6578616d706c652e636f6dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000700000000');
const parents = [funding, { ...funding, outputs: [{ ...funding.outputs[0], amount: '20000000000' }] }];
const raws = new Map(parents.map(tx => [transactionId(tx), serializeTransaction(tx).toString('hex')]));
const rows = parents.map(tx => ({ txid: transactionId(tx), vout: 0, block_hash: block, block_height: 100,
  amount: tx.outputs[0].amount, domain: 'example.com', connection_work_target: 'f'.repeat(64),
  root_certificates_version: 1, signature_algorithms_mask: 7, status: 'available' }));

async function fixture(t) {
  const rpc = new EventEmitter(); rpc.calls = []; rpc.connect = async () => {}; rpc.close = () => {};
  rpc.request = async (method, params, options) => {
    rpc.calls.push({ method, params: structuredClone(params), options });
    assert.equal(method, 'gettransaction');
    return rpc.respond ? rpc.respond(params, options) : { tip, transaction: { hex: raws.get(params.txid) } };
  };
  const engine = { enabled: false, queue: new Map(), proposals: new Map(), pendingProofs: new Map(),
    start() { this.enabled = true; }, resume() {}, setCatalogBlocked(blocked) { this.catalogBlocked = blocked; },
    async suspend() {}, async stop() { this.enabled = false; },
    clear() { this.queue.clear(); }, retainCatalog() {},
    enqueue(available) { for (const row of available) this.queue.set(`${row.txid}:${row.vout}`, { bounty: row }); },
    remove(txid, vout) { this.queue.delete(`${txid}:${vout}`); }, hasActive() { return false; } };
  const journal = { loaded: true, async load() { return []; }, entries() { return []; }, unresolved() { return []; },
    awaitingConfirmation() { return []; }, async flush() {} };
  const service = new ClaimerService({ config, rpcFactory: () => rpc, engineFactory: () => engine, journal,
    discover: async () => ({ blocks: new Map([[block, rows]]), cursor: 'cursor', tip }),
    setTimer: () => ({ unref() {} }), clearTimer() {} });
  t.after(() => service.stop()); await service.start();
  assert.equal(service.ready, true); assert.equal(engine.catalogBlocked, false);
  assert.equal(engine.queue.size, rows.length);
  return { rpc, service };
}

test('funding requests raw_only but validates the full original transaction and shares parent reads', async t => {
  const { rpc, service } = await fixture(t);
  const [a, b] = await Promise.all([service.prepare(rows[0]), service.prepare(rows[0])]);
  assert.equal(a.bounty.amount, rows[0].amount); assert.equal(b.bounty.amount, rows[0].amount);
  assert.deepEqual(rpc.calls.map(c => c.params), [{ txid: rows[0].txid, raw_only: true }]);
  assert.equal(service.config.connectionsPerSecond, 800); assert.equal(service.config.concurrency, 800);
});

test('raw_only -32602 retries the same txid and retains capability fallback for later funding in that epoch', async t => {
  const { rpc, service } = await fixture(t);
  rpc.respond = params => { if (params.raw_only) throw Object.assign(new Error('Legacy schema'), { code: -32602 }); return { tip, transaction: { hex: raws.get(params.txid), unused: 'legacy verbose data' } }; };
  await service.prepare(rows[0]); await service.prepare(rows[1]);
  assert.deepEqual(rpc.calls.map(c => c.params), [{ txid: rows[0].txid, raw_only: true }, { txid: rows[0].txid }, { txid: rows[1].txid }]);
  rpc.emit('disconnected'); await service.suspending; await service.cycle();
  await service.prepare(rows[0]); assert.equal(rpc.calls[3].params.raw_only, true);
});

test('cancelling one funding consumer during legacy fallback does not cancel its sibling', async t => {
  const { rpc, service } = await fixture(t); let release;
  rpc.respond = params => {
    if (params.raw_only) throw Object.assign(new Error('Legacy schema'), { code: -32602 });
    return new Promise(resolve => { release = resolve; });
  };
  const controller = new AbortController();
  const cancelled = service.prepare(rows[0], { signal: controller.signal });
  const rejected = assert.rejects(cancelled, error => error.name === 'AbortError');
  const sibling = service.prepare(rows[0]);
  while (!release) await new Promise(resolve => setImmediate(resolve));
  controller.abort(); await rejected; assert.equal(rpc.calls[1].options.signal.aborted, false);
  release({ tip, transaction: { hex: raws.get(rows[0].txid) } });
  assert.equal((await sibling).bounty.amount, rows[0].amount); assert.equal(rpc.calls.length, 2);
});

for (const [label, error] of [['timeout', new Error('RPC request timed out.')],
  ...[-32001, -32002, -32029, -32601].map(code => [String(code), Object.assign(new Error('Backend failure'), { code })])]) {
  test(`funding ${label} never falls back to verbose`, async t => {
    const { rpc, service } = await fixture(t); rpc.respond = () => { throw error; };
    await assert.rejects(service.prepare(rows[0]), failure => failure === error);
    assert.equal(rpc.calls.length, 1); assert.equal(rpc.calls[0].params.raw_only, true);
  });
}

for (const [label, raw] of [['wrong txid', raws.get(rows[1].txid)], ['invalid hex', 'not-hex'],
  ['truncated bytes', raws.get(rows[0].txid).slice(0, -2)]]) test(`raw-only ${label} fails closed without legacy retry`, async t => {
  const { rpc, service } = await fixture(t); rpc.respond = () => ({ tip, transaction: { hex: raw } });
  await assert.rejects(service.prepare(rows[0])); assert.ok(service.fatalError); assert.equal(rpc.calls.length, 1);
});

test('a raw-only rejection crossing an RPC epoch cannot transmit its fallback', async t => {
  const { rpc, service } = await fixture(t);
  rpc.respond = () => { rpc.emit('disconnected'); throw Object.assign(new Error('Legacy schema'), { code: -32602 }); };
  await assert.rejects(service.prepare(rows[0]), error => error.name === 'AbortError'); assert.equal(rpc.calls.length, 1);
});
