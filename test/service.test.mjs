import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ClaimerService } from '../src/service.mjs';
import { BroadcastJournal } from '../src/broadcast-journal.mjs';
import { ClaimMetrics } from '../src/metrics.mjs';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { FundingTransactionCache, parseTransaction, prepareClaim, serializeTransaction, transactionId, transactionIdFromRaw } from '../src/core/transaction.mjs';

const HASH = '1'.repeat(64), BLOCK = '2'.repeat(64), CLAIM = '3'.repeat(64);
const tip = { height: 100, hash: BLOCK, mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };
const bounty = { txid: HASH, vout: 0, block_hash: BLOCK, block_height: 100, amount: '10000000000', domain: 'example.com',
  connection_work_target: 'f'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7, status: 'available' };
const config = { receivingAddress: 'ccpublicreceivingaddress', connectionsPerSecond: 100, concurrency: 100,
  minExpectedReturn: 1000, rpc: { host: 'invalid.example', port: 48190 }, network: 'main', lookbackBlocks: 600, feeRate: 1500 };

class FakeRpc extends EventEmitter {
  constructor() { super(); this.calls = []; this.connections = 0; this.closed = false; }
  async connect() { this.connections++; if (this.connectError) throw this.connectError; }
  async request(method, params, options) {
    this.calls.push({ method, params });
    if (this.respond) return this.respond(method, params, options);
    if (method === 'gettransaction' && params.txid === CLAIM) throw Object.assign(new Error('not found'), { code: -32004 });
    if (method === 'gettransaction') return { tip, transaction: { hex: 'funding-hex' } };
    if (method === 'sendrawtransaction') return { txid: CLAIM };
    throw new Error(`Unexpected fake method: ${method}`);
  }
  close() { this.closed = true; }
}
class FakeEngine {
  constructor(options) { this.options = options; this.enabled = false; this.queue = new Map(); this.proposals = new Map(); this.pendingProofs = new Map(); this.starts = 0; this.suspends = 0; this.stops = 0; }
  start() { this.enabled = true; this.starts++; }
  resume() { this.paused = false; }
  async suspend() { this.paused = true; this.suspends++; }
  async stop() { this.enabled = false; this.stops++; }
  clear() { this.queue.clear(); }
  retainCatalog() {}
  enqueue(rows) { for (const row of rows) this.queue.set(`${row.txid}:${row.vout}`, { bounty: row }); }
  remove(txid, vout) { this.queue.delete(`${txid}:${vout}`); }
  retire(txid, vout) { const job = this.queue.get(`${txid}:${vout}`); if (job) job.retired = true; }
  activeKeys() { return new Set(); }
  hasActive() { return false; }
}
async function fixture(t, overrides = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'connectcoin-claimer-service-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const statePath = join(directory, 'claimer.conf.state.json'), rpc = new FakeRpc(), events = [], timers = [];
  let engine;
  const service = new ClaimerService({ config, statePath, rpcFactory: () => rpc,
    engineFactory: options => (engine = new FakeEngine(options)),
    discover: async () => ({ blocks: new Map([[BLOCK, [bounty]]]), cursor: 'cursor-one', tip }),
    prepare: ({ bounty: row, fee }) => ({ bounty: { ...row, target: row.connection_work_target, rootVersion: 1, mask: 7 }, txid: CLAIM, fee, payout: '9990000000' }),
    attach: () => ({ txid: CLAIM, hex: 'ab'.repeat(50) }), transactionId: () => HASH,
    validateSaved: row => row.transactionHex, validateObserved: () => {},
    setTimer: (callback, delay) => { const timer = { callback, delay, unref() {} }; timers.push(timer); return timer; },
    clearTimer: timer => { timer.cleared = true; }, emit: (event, details) => events.push({ event, details }), ...overrides });
  t.after(() => service.stop());
  return { service, rpc, engine, events, timers, statePath, directory };
}

test('headless service pulls real engine snapshots only on demand and keeps fatal state immediately visible', async t => {
  const { service } = await fixture(t, { engineFactory: options => new ClaimsEngine(options) });
  const engine = service.engine;
  assert.equal(engine.stateNotifications, false);
  let snapshots = 0, notifications = 0;
  const snapshot = engine.snapshot.bind(engine);
  engine.snapshot = () => { snapshots++; return snapshot(); };
  engine.onState = () => notifications++;
  for (let attempts = 1; attempts <= 1000; attempts++) engine.notify({ attempts });
  assert.equal(snapshots, 0); assert.equal(notifications, 0);
  assert.equal(service.snapshot().claims.attempts, 1000);
  assert.equal(snapshots, 1);
  engine.beginDiagnosticRun();
  engine.fatal(new Error('test failure'));
  assert.equal(service.snapshot().status, 'failed');
  assert.equal(service.snapshot().claims.status, 'off');
  assert.equal(service.snapshot().claims.lastError, 'test failure');
  assert.equal(service.running, false);
});

test('custom engines keep their push-state contract even if they have an unrelated snapshot method', async t => {
  const { service, engine } = await fixture(t);
  assert.equal(engine.options.stateNotifications, false);
  engine.snapshot = () => { assert.fail('An engine that did not opt into pull mode must not be queried'); };
  engine.options.onState({ completed: 7, attempts: 12 });
  assert.deepEqual(service.snapshot().claims, { completed: 7, attempts: 12 });
});

test('reuses the processed discovery cursor and validates parent transaction before preparing a public-address claim', async t => {
  const calls = [];
  const { service, rpc, engine } = await fixture(t, { discover: async options => {
    calls.push(options);
    return { blocks: new Map([[BLOCK, [bounty]]]), cursor: `cursor-${calls.length}`, tip };
  } });
  await service.start();
  assert.equal(service.snapshot().ready, true);
  assert.equal(engine.options.minExpectedReturn, 1000);
  await service.cycle();
  assert.equal(calls[0].cursor, null);
  assert.equal(calls[1].cursor, 'cursor-1');
  assert.equal(calls[1].previous.size, 1);
  const prepared = await service.prepare(bounty);
  assert.equal(prepared.context.txid, CLAIM);
  assert.equal(prepared.context.validation_time, tip.mediantime);
  await service.prepare(bounty);
  assert.equal(rpc.calls.filter(call => call.method === 'gettransaction').length, 1);
});

test('production preparation shares full parent validation across outputs and revalidates after an RPC epoch change', async t => {
  const funding = parseTransaction('02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff0100e40b5402000000020b6578616d706c652e636f6dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000700000000');
  funding.outputs.push({ ...funding.outputs[0], amount: '20000000000' });
  const raw = serializeTransaction(funding).toString('hex'), txid = transactionId(funding);
  const rows = funding.outputs.map((output, vout) => ({ ...bounty, txid, vout, amount: output.amount }));
  const { service, rpc } = await fixture(t, {
    config: { ...config, receivingAddress: 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya' },
    prepare: prepareClaim, transactionId: transactionIdFromRaw,
    discover: async () => ({ blocks: new Map([[BLOCK, rows]]), cursor: 'cursor-one', tip }),
  });
  rpc.respond = async method => { assert.equal(method, 'gettransaction'); return { tip, transaction: { hex: raw } }; };
  let parentDecodes = 0, clears = 0;
  const from = Buffer.from, clear = FundingTransactionCache.prototype.clear;
  t.mock.method(Buffer, 'from', function (value, ...args) {
    if (value === raw && args[0] === 'hex') parentDecodes++;
    return from(value, ...args);
  });
  t.mock.method(FundingTransactionCache.prototype, 'clear', function () { clears++; return clear.call(this); });
  await service.start();
  const prepared = await Promise.all(rows.map(row => service.prepare(row)));
  assert.deepEqual(prepared.map(row => row.bounty.amount), ['10000000000', '20000000000']);
  assert.equal(rpc.calls.length, 1); assert.equal(parentDecodes, 1);
  prepared[0].bounty.amount = '1';
  assert.equal((await service.prepare(rows[0])).bounty.amount, rows[0].amount);
  service.outpoints.set(`${txid}:1`, { ...rows[1], domain: 'forged.example' });
  await assert.rejects(service.prepare(rows[1]), /domain differs/);
  service.outpoints.set(`${txid}:1`, rows[1]);
  assert.equal(parentDecodes, 1);
  rpc.emit('disconnected'); await service.suspending; await service.cycle();
  await service.prepare(rows[0]);
  assert.equal(rpc.calls.length, 2); assert.equal(parentDecodes, 2); assert.equal(clears, 1);
  await service.stop(); assert.equal(clears, 2);
});

test('funding cache limits raw retained bytes without changing injected callback contracts', async t => {
  const secondId = '4'.repeat(64), second = { ...bounty, txid: secondId };
  const received = [];
  const { service, rpc } = await fixture(t, {
    transactionId: raw => raw.slice(0, 64),
    prepare: options => {
      received.push(options);
      return { bounty: { ...options.bounty, target: options.bounty.connection_work_target, rootVersion: 1, mask: 7 }, txid: CLAIM, fee: options.fee };
    },
    discover: async () => ({ blocks: new Map([[BLOCK, [bounty, second]]]), cursor: 'cursor-one', tip }),
  });
  // Each raw string is charged as UTF-16 plus entry overhead, so these two
  // individually valid callback responses cannot coexist in the 16 MiB cache.
  const suffix = '0'.repeat(4 * 1024 * 1024);
  rpc.respond = async (method, params) => {
    assert.equal(method, 'gettransaction'); return { tip, transaction: { hex: params.txid + suffix } };
  };
  await service.start();
  await service.prepare(bounty); await service.prepare(second); await service.prepare(bounty);
  assert.equal(rpc.calls.length, 3);
  assert.equal(received.length, 3);
  for (const options of received) {
    assert.equal(typeof options.rawTransaction, 'string');
    assert.equal(options.rawTransaction.slice(0, 64), options.bounty.txid);
    assert.deepEqual(Object.keys(options).sort(), ['bounty', 'fee', 'network', 'rawTransaction', 'rewardAddress']);
  }
});

test('stale or cancelled parent requests cannot refill caches or cancel another output read', async t => {
  const { service, rpc } = await fixture(t);
  const pending = [];
  rpc.respond = () => new Promise(resolve => pending.push(resolve));
  await service.start();
  const signal = new AbortController();
  const cancelled = service.funding(HASH, { signal: signal.signal });
  const shared = service.funding(HASH);
  signal.abort(); await assert.rejects(cancelled, { name: 'AbortError' });
  pending.shift()({ tip, transaction: { hex: 'funding-hex' } });
  assert.equal(await shared, 'funding-hex'); assert.equal(rpc.calls.length, 1);
  rpc.emit('disconnected'); await service.suspending; await service.cycle();
  const stale = service.funding(HASH);
  rpc.emit('disconnected'); await service.suspending; await service.cycle();
  pending.shift()({ tip, transaction: { hex: 'funding-hex' } });
  await assert.rejects(stale, { name: 'AbortError' });
  const fresh = service.funding(HASH);
  assert.equal(rpc.calls.length, 3);
  pending.shift()({ tip, transaction: { hex: 'funding-hex' } });
  assert.equal(await fresh, 'funding-hex');
});

test('writes pending state durably before broadcasting and retains accepted outpoints across restart', async t => {
  const { service, rpc, statePath } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  rpc.respond = async method => {
    assert.equal(method, 'sendrawtransaction');
    const saved = JSON.parse(await readFile(statePath, 'utf8'));
    assert.equal(saved.records[0].status, 'pending');
    assert.equal(saved.records[0].txid, CLAIM);
    assert.deepEqual(Object.keys(saved.records[0]).sort(), ['outpoint', 'receivingAddress', 'status', 'transactionHash', 'transactionHex', 'txid', 'updatedAt']);
    return { txid: CLAIM };
  };
  assert.deepEqual(await service.submit(prepared, 'proof'), { txid: CLAIM });
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).records[0].status, 'accepted');
  await service.stop();
  const fresh = await fixture(t, { statePath });
  await fresh.service.start();
  assert.equal(fresh.service.snapshot().available, 0);
  assert.equal(fresh.engine.queue.size, 0);
});

test('uncertain broadcast reserves only its outpoint and survives restart with exact bytes', async t => {
  const { service, rpc, statePath, timers } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  rpc.respond = async () => { throw Object.assign(new Error('Connection lost after write.'), { unknownOutcome: true }); };
  await assert.rejects(service.submit(prepared, 'proof'), error => error.broadcastDeferred === true);
  assert.equal(service.snapshot().status, 'running');
  assert.equal(service.snapshot().running, true);
  assert.equal(rpc.closed, false);
  assert.equal(timers.at(-1).cleared, undefined);
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).records[0].status, 'unknown');
  const restarted = await fixture(t, { statePath });
  await restarted.service.start();
  assert.equal(restarted.rpc.connections, 1);
  assert.equal(restarted.engine.starts, 1);
  assert.equal(restarted.engine.queue.size, 0);
  assert.equal(restarted.service.journal.unresolved()[0].transactionHex, 'ab'.repeat(50));
});

test('cancellation during durable preflight keeps the verified bytes without transmitting', async t => {
  const controller = new AbortController();
  const { service, rpc } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async (key, row) => { await update(key, row); if (row?.status === 'pending') controller.abort(); };
  await assert.rejects(service.submit(prepared, 'proof', { signal: controller.signal }), { broadcastDeferred: true });
  assert.equal(rpc.calls.some(call => call.method === 'sendrawtransaction'), false);
  assert.equal(service.journal.entries()[0].status, 'pending');
  assert.equal(service.reserved.size, 1);
});

test('a definite node rejection releases the durable reservation; already-known remains uncertain', async t => {
  const { service, rpc } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  rpc.respond = async () => { throw Object.assign(new Error('Rejected'), { code: -32020, data: { node_code: -26 } }); };
  await assert.rejects(service.submit(prepared, 'proof'), { code: -32020 });
  assert.equal(service.journal.entries().length, 0);
  assert.equal(service.running, true);
  rpc.respond = async () => { throw Object.assign(new Error('Already known'), { code: -32020, data: { node_code: -27 } }); };
  await assert.rejects(service.submit(prepared, 'proof'), error => error.broadcastDeferred === true);
  assert.equal(service.running, true);
});

async function uncertainFixture(t, overrides = {}) {
  const result = await fixture(t, overrides);
  await result.service.start();
  const prepared = await result.service.prepare(bounty);
  result.rpc.respond = async () => { throw Object.assign(new Error('Lost response'), { unknownOutcome: true }); };
  await assert.rejects(result.service.submit(prepared, 'proof'), { broadcastDeferred: true });
  return result;
}

test('lost response reconciles an indexed transaction without resending or completing twice', async t => {
  const { service, rpc, engine } = await uncertainFixture(t);
  let completed = 0;
  engine.completeRecoveredClaim = (key, txid) => { assert.equal(key, `${HASH}:0`); assert.equal(txid, CLAIM); completed++; };
  rpc.respond = async (method, params) => {
    assert.equal(method, 'gettransaction'); assert.equal(params.txid, CLAIM);
    return { tip, transaction: { hex: 'ab'.repeat(50) } };
  };
  await Promise.all([service.reconcileBroadcasts(), service.reconcileBroadcasts()]);
  await service.reconcileBroadcasts();
  assert.equal(completed, 1);
  assert.equal(service.journal.unresolved().length, 0);
  assert.equal(service.journal.entries()[0].transactionHex, undefined);
  assert.equal(service.reserved.has(`${HASH}:0`), true);
  assert.equal(rpc.calls.filter(row => row.method === 'sendrawtransaction').length, 1);
});

test('missing index replays exactly the saved public witness and only one request at a time', async t => {
  const { service, rpc, engine } = await uncertainFixture(t);
  const replay = Promise.withResolvers(), sending = Promise.withResolvers();
  const original = service.journal.unresolved()[0]; let completed = 0;
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async (method, params, options) => {
    if (method === 'gettransaction') throw Object.assign(new Error('Not indexed'), { code: -32004 });
    assert.equal(method, 'sendrawtransaction');
    assert.equal(params.transaction_hex, original.transactionHex);
    assert.equal(service.journal.unresolved()[0].status, 'unknown');
    options.beforeSend(); sending.resolve(); return replay.promise;
  };
  const first = service.reconcileBroadcasts(); await sending.promise;
  assert.equal(service.reconcileBroadcasts(), first);
  replay.resolve({ txid: CLAIM }); await first;
  assert.equal(completed, 1);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(rpc.calls.filter(row => row.method === 'sendrawtransaction').length, 2);
});

for (const failure of [
  { code: -32029, data: { retry_after_ms: 45000 } },
  { code: -32002 }, { notSent: true }, { unknownOutcome: true },
  ...[-25, -26, -27].map(node_code => ({ code: -32020, data: { node_code } })),
]) test(`reconciliation preserves an uncertain reservation after ${JSON.stringify(failure)}`, async t => {
  const { service, rpc } = await uncertainFixture(t);
  const original = service.journal.unresolved()[0];
  rpc.respond = async method => {
    if (method === 'gettransaction') throw Object.assign(new Error('Not indexed'), { code: -32004 });
    throw Object.assign(new Error('Retry failed'), failure);
  };
  await service.reconcileBroadcasts();
  const pending = service.journal.unresolved()[0];
  assert.equal(pending.transactionHex, original.transactionHex);
  assert.equal(pending.transactionHash, original.transactionHash);
  assert.equal(pending.txid, original.txid);
  assert.equal(service.reserved.has(`${HASH}:0`), true);
  assert.equal(service.running, true);
  assert.ok(service.recoveryDue.get(`${HASH}:0`) > Date.now());
});

test('legacy unresolved record is isolated while other bounties run and can resolve by indexed receipt', async t => {
  const { directory } = await fixture(t), statePath = join(directory, 'legacy.json');
  await writeFile(statePath, JSON.stringify({ version: 1, records: [{ outpoint: `${HASH}:0`, txid: CLAIM,
    receivingAddress: config.receivingAddress, status: 'unknown', updatedAt: 0 }] }));
  const other = { ...bounty, vout: 1 };
  const { service, rpc, engine } = await fixture(t, { statePath,
    discover: async () => ({ blocks: new Map([[BLOCK, [bounty, other]]]), cursor: 'one', tip }) });
  await service.start(); await service.reconcileBroadcasts();
  assert.equal(service.running, true);
  assert.equal(service.snapshot().reviewRequired, true);
  assert.equal(engine.queue.size, 1);
  assert.equal(engine.queue.has(`${HASH}:1`), true);
  assert.equal(rpc.calls.some(row => row.method === 'sendrawtransaction'), false);
  service.recoveryDue.clear();
  rpc.respond = async () => ({ tip, transaction: { hex: 'ab'.repeat(50) } });
  await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.snapshot().reviewRequired, false);
});

test('pending bytes recover after process restart without generating another claim', async t => {
  const { service, statePath } = await fixture(t);
  await service.start(); const prepared = await service.prepare(bounty);
  const update = service.journal.update.bind(service.journal);
  const signal = new AbortController();
  service.journal.update = async (...args) => { await update(...args); signal.abort(); };
  await assert.rejects(service.submit(prepared, 'proof', { signal: signal.signal }), { broadcastDeferred: true });
  await service.stop();
  const fresh = await fixture(t, { statePath, prepare: () => assert.fail('Must not recreate saved transaction') });
  await fresh.service.start(); await fresh.service.reconcileBroadcasts();
  assert.equal(fresh.service.journal.entries()[0].status, 'accepted');
  assert.equal(fresh.rpc.calls.filter(row => row.method === 'sendrawtransaction').length, 1);
});

test('older quarantined entries cannot starve newly recoverable records', async t => {
  const { service, rpc } = await uncertainFixture(t);
  const template = service.journal.unresolved()[0];
  for (let vout = 1; vout <= 7; vout++) {
    await service.journal.update(`${HASH}:${vout}`, { ...template, status: 'unknown' });
    service.reserved.add(`${HASH}:${vout}`);
  }
  for (let vout = 0; vout < 7; vout++) service.recoveryDue.set(`${HASH}:${vout}`, Date.now() - 1);
  let selected;
  service.reconcileOne = async row => { selected = row.outpoint; };
  const previousCalls = rpc.calls.length;
  await service.reconcileBroadcasts();
  assert.equal(selected, `${HASH}:7`);
  assert.equal(rpc.calls.length, previousCalls);
});

for (const action of ['stop', 'disconnect']) test(`node rejection arriving during ${action} cannot erase the saved proof`, async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); const prepared = await service.prepare(bounty);
  engine.queue.get(`${HASH}:0`).prepared = prepared;
  engine.pendingProofs.set(`${HASH}:0`, { proof: 'proof' });
  const sending = Promise.withResolvers(), result = Promise.withResolvers();
  rpc.respond = async () => { sending.resolve(); return result.promise; };
  const submitted = service.submit(prepared, 'proof');
  const rejected = assert.rejects(submitted, { broadcastDeferred: true });
  await sending.promise;
  engine.stop = engine.suspend = () => submitted.catch(() => {});
  const draining = action === 'stop' ? service.stop() : (rpc.emit('disconnected'), service.suspending);
  result.reject(Object.assign(new Error('Node rejected'), { code: -32020, data: { node_code: -26 } }));
  await rejected; await draining;
  assert.equal(service.journal.unresolved()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(`${HASH}:0`), true);
});

test('disconnect persistence barrier cannot be shortened by another suspend', async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); const prepared = await service.prepare(bounty);
  engine.queue.get(`${HASH}:0`).prepared = prepared;
  engine.pendingProofs.set(`${HASH}:0`, { proof: 'proof' });
  const writing = Promise.withResolvers(), release = Promise.withResolvers();
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async (...args) => { writing.resolve(); await release.promise; return update(...args); };
  rpc.emit('disconnected'); await writing.promise;
  const barrier = service.suspending;
  await service.suspend(); assert.equal(service.suspending, barrier);
  let finished = false; const cycle = service.cycle().then(() => { finished = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(finished, false);
  release.resolve(); await cycle;
  assert.equal(service.journal.unresolved()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(engine.queue.size, 0);
});

test('disconnect suspends claims and invalidates old proposals until a coherent incremental catchup', async t => {
  let calls = 0;
  const { service, rpc, engine } = await fixture(t, { discover: async options => {
    if (++calls === 2) {
      assert.equal(options.cursor, 'cursor-one');
      assert.equal(service.ready, false);
      assert.equal(engine.paused, true);
    }
    return { blocks: new Map([[BLOCK, [bounty]]]), cursor: 'cursor-one', tip };
  } });
  await service.start();
  const old = await service.prepare(bounty);
  rpc.emit('disconnected');
  assert.equal(service.ready, false);
  assert.equal(engine.paused, true);
  await assert.rejects(service.submit(old, 'proof'), { name: 'AbortError' });
  await service.cycle();
  assert.equal(service.ready, true);
  assert.equal(engine.paused, false);
  assert.equal(calls, 2);
  assert.equal(engine.starts, 1);
});

test('rate limits honor retry_after_ms and malformed network identity never retries indefinitely', async t => {
  const limited = await fixture(t, { discover: async () => { throw Object.assign(new Error('Rate limit'), { code: -32029, data: { retry_after_ms: 42000 } }); } });
  await limited.service.start();
  assert.equal(limited.service.ready, false);
  assert.equal(limited.timers.at(-1).delay, 42000);
  assert.equal(limited.engine.starts, 0);
  const invalid = await fixture(t, { discover: async () => ({ blocks: new Map(), cursor: 'cursor', tip: { ...tip, chain: 'testnet4' } }) });
  await assert.rejects(invalid.service.start(), /unexpected network/);
  assert.equal(invalid.service.running, false);
  assert.equal(invalid.timers.length, 0);
});

test('real engine saves verified proofs before clearing old-epoch work on reconnect', async t => {
  const { service, rpc } = await fixture(t, {
    engineFactory: options => new ClaimsEngine(options),
    poolFactory: () => ({ pacesStarts: true, async start() {}, async close() {},
      resolve(_domain, { signal }) { return new Promise((accept, reject) => {
        const cancel = () => reject(Object.assign(new Error('cancelled'), { name: 'AbortError' }));
        if (signal.aborted) cancel(); else signal.addEventListener('abort', cancel, { once: true });
      }); },
      async attempt() { throw new Error('Offline test must never attempt a TLS capture.'); },
    }),
  });
  const key = `${HASH}:0`, engine = service.engine;
  const preparedAtEpoch = async epoch => {
    for (let spin = 0; spin < 100; spin++) {
      if (engine.proposals.get(key)?.epoch === epoch) return engine.proposals.get(key);
      await new Promise(accept => setImmediate(accept));
    }
    assert.fail('Real engine did not prepare a claim at the requested epoch.');
  };
  await service.start();
  await preparedAtEpoch(0);
  engine.successCounts.set(key, 1n);
  const factor = engine.factors.get(key);
  engine.pendingProofs.set(key, { proof: '02ff', due: Infinity });
  rpc.emit('disconnected');
  await service.suspending;
  assert.equal(engine.proposals.size, 0);
  assert.equal(engine.pendingProofs.size, 0);
  assert.equal(engine.queue.size, 0);
  assert.equal(engine.successCounts.get(key), 1n);
  assert.equal(engine.factors.get(key), factor);
  assert.equal(service.journal.unresolved()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(key), true);
  await service.cycle();
  assert.equal(engine.queue.size, 0);
  assert.equal(engine.proposals.size, 0);
  assert.equal(rpc.calls.filter(call => call.method === 'gettransaction').length, 1);
  assert.equal(rpc.calls.some(call => call.method === 'sendrawtransaction'), false);
  await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(engine.state.completed, 1);
  assert.equal(rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 1);
});

test('stop while initial state is being loaded cannot restart the service afterward', async t => {
  let finishLoad;
  const loading = new Promise(accept => { finishLoad = accept; });
  const journal = { load: () => loading, unresolved: () => [], async flush() {} };
  const { service, rpc } = await fixture(t, { journal });
  const starting = service.start();
  await service.stop();
  finishLoad([]);
  await assert.rejects(starting, { name: 'AbortError' });
  assert.equal(service.running, false);
  assert.equal(service.snapshot().status, 'stopped');
  assert.equal(rpc.connections, 0);
});

test('fatal engine failure cannot be silently restarted by the discovery poll', async t => {
  const { service, engine } = await fixture(t);
  await service.start();
  engine.options.onDiagnostic('claims.failed', { error: new Error('Helper failed') });
  await service.cycle();
  assert.equal(service.snapshot().status, 'failed');
  assert.equal(engine.starts, 1);
});

test('malformed funding identity halts instead of repeatedly attempting claims', async t => {
  const { service, rpc } = await fixture(t, { transactionId: () => '4'.repeat(64) });
  await service.start();
  await assert.rejects(service.prepare(bounty), /do not match/);
  assert.equal(service.snapshot().status, 'failed');
  assert.equal(rpc.closed, true);
});

test('production funding rejects invalid sibling keys and clears validation state on fatal failure', async t => {
  const publicKey = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const funding = { version: 2, inputs: [{ txid: '00'.repeat(32), vout: 0xffffffff, scriptSig: '', sequence: 0xffffffff, witness: [] }],
    outputs: [{ type: 2, amount: bounty.amount, domain: bounty.domain, target: bounty.connection_work_target, rootVersion: 1, mask: 7 },
      { type: 1, amount: '100', publicKey }], locktime: 0 };
  const raw = serializeTransaction(funding).toString('hex').replace(publicKey, 'ff'.repeat(32));
  const row = { ...bounty, txid: transactionIdFromRaw(raw) };
  let clears = 0;
  const clear = FundingTransactionCache.prototype.clear;
  t.mock.method(FundingTransactionCache.prototype, 'clear', function () { clears++; return clear.call(this); });
  const { service, rpc } = await fixture(t, {
    prepare: prepareClaim, transactionId: transactionIdFromRaw,
    discover: async () => ({ blocks: new Map([[BLOCK, [row]]]), cursor: 'cursor-one', tip }),
  });
  rpc.respond = async () => ({ tip, transaction: { hex: raw } });
  await service.start();
  await assert.rejects(service.prepare(row), /key|point|field/i);
  assert.equal(service.snapshot().status, 'failed'); assert.equal(rpc.closed, true); assert.equal(clears, 1);
});

test('journal serializes concurrent reservations and fails closed on corrupt state', async t => {
  const { directory } = await fixture(t), path = join(directory, 'journal.json');
  const journal = new BroadcastJournal(path);
  await journal.load();
  await Promise.all([0, 1, 2].map(vout => journal.update(`${HASH}:${vout}`, { txid: CLAIM, receivingAddress: config.receivingAddress, status: 'pending' })));
  const reopened = new BroadcastJournal(path);
  assert.equal((await reopened.load()).length, 3);
  await writeFile(path, '{"version":1,"records":[{}]}');
  await assert.rejects(new BroadcastJournal(path).load(), /Invalid claim broadcast record/);
});

test('metrics count only actual starts, release active requests on rejection, and expire the fixed rate window', async () => {
  let now = 0;
  const metrics = new ClaimMetrics({ now: () => now });
  const pool = metrics.wrap({ async attempt(_context, options) {
    options.onStarted();
    assert.equal(metrics.snapshot().activeConnections, 1);
    options.onResult({ validationPassed: true, verified: true, proof: '02ff', cancelled: false });
    return 'done';
  } });
  await pool.attempt({});
  assert.equal(metrics.snapshot().connectionsStarted, 1);
  assert.equal(metrics.snapshot().connectionsPerSecond, 0.1);
  assert.equal(metrics.snapshot().targetReached, 1);
  assert.equal(metrics.snapshot().activeConnections, 0);
  const failing = metrics.wrap({ async attempt(_context, options) { options.onStarted(); throw Object.assign(new Error('cancelled'), { name: 'AbortError' }); } });
  await assert.rejects(failing.attempt({}));
  assert.equal(metrics.snapshot().cancelled, 1);
  assert.equal(metrics.snapshot().activeConnections, 0);
  now = 11000;
  assert.equal(metrics.snapshot().connectionsPerSecond, 0);
  assert.equal(metrics.buckets.length, 100);
});
