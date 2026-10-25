import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ClaimerService } from '../src/service.mjs';
import { BroadcastJournal, transactionDigest } from '../src/broadcast-journal.mjs';
import { validateObservedClaim, validateSavedClaim } from '../src/broadcast-recovery.mjs';
import { ClaimMetrics } from '../src/metrics.mjs';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { FundingTransactionCache, attachClaimProof, parseTransaction, prepareClaim, serializeTransaction, transactionId, transactionIdFromRaw } from '../src/core/transaction.mjs';

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
    if (method === 'gettransactionstatus') throw Object.assign(new Error('not found'), { code: -32004 });
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
  setCatalogBlocked(blocked) { this.catalogBlocked = blocked; }
  async suspend() { this.paused = true; this.suspends++; }
  async stop() { this.enabled = false; this.stops++; }
  clear() { this.queue.clear(); }
  retainCatalog() {}
  enqueue(rows) { for (const row of rows) this.queue.set(`${row.txid}:${row.vout}`, { bounty: row }); }
  remove(txid, vout) { this.queue.delete(`${txid}:${vout}`); }
  retire(txid, vout) { const job = this.queue.get(`${txid}:${vout}`); if (job) job.retired = true; }
  activeKeys() { return new Set(); }
  hasActive() { return false; }
  canReopenConfirmedClaim() { return true; }
  reopenConfirmedClaim() {}
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

test('bounty wire negotiation is retained within one RPC epoch and discarded on disconnect', async t => {
  const seen = [], owners = [];
  const { service, rpc } = await fixture(t, { discover: async options => {
    owners.push(options.capabilities); seen.push({ ...options.capabilities });
    options.capabilities.compactVersion = 1;
    return { blocks: new Map([[BLOCK, [bounty]]]), cursor: 'cursor-one', tip };
  } });
  await service.start(); await service.cycle();
  assert.deepEqual(seen, [{}, { compactVersion: 1 }]); assert.equal(owners[0], owners[1]);
  rpc.emit('disconnected'); await service.suspending;
  assert.notEqual(service.bountyCapabilities, owners[0]);
  owners[0].compactVersion = 2; // Late old-epoch negotiation cannot affect the replacement.
  await service.cycle(); assert.deepEqual(seen[2], {}); assert.notEqual(owners[2], owners[0]);
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

test('accepted unconfirmed claim survives eviction and restart, replaying identical bytes without double credit', async t => {
  let status = 'available';
  const discover = async () => ({ blocks: new Map([[BLOCK, [{ ...bounty, status }]]]), cursor: `cursor-${status}`, tip });
  const { service, rpc, statePath } = await fixture(t, { discover });
  await service.start();
  const prepared = await service.prepare(bounty);
  await service.submit(prepared, 'proof');
  assert.equal(service.journal.awaitingConfirmation()[0].transactionHex, 'ab'.repeat(50));
  status = 'pending_spend'; await service.cycle(); await service.stop();

  const fresh = await fixture(t, { statePath, discover });
  let completed = 0, indexed = false;
  fresh.engine.completeRecoveredClaim = () => completed++;
  fresh.rpc.respond = async (method, params, options) => {
    if (method === 'gettransactionstatus') {
      assert.equal(params.txid, CLAIM);
      if (!indexed) throw Object.assign(new Error('Not indexed'), { code: -32004 });
      return { tip, status: 'confirmed', block_hash: BLOCK, block_height: 100, txid: CLAIM, confirmations: 1 };
    }
    assert.equal(method, 'sendrawtransaction'); options.beforeSend();
    assert.equal(params.transaction_hex, 'ab'.repeat(50)); return { txid: CLAIM };
  };
  await fresh.service.start(); await fresh.service.reconcileBroadcasts();
  assert.equal(fresh.rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 0, 'Absence alone cannot reopen a pending-spent input');
  status = 'available'; await fresh.service.cycle(); fresh.service.recoveryDue.clear();
  await fresh.service.reconcileBroadcasts();
  assert.equal(fresh.rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 1);
  assert.equal(completed, 0, 'A previously accepted claim must not be credited again after restart');
  assert.equal(fresh.service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  indexed = true; fresh.service.recoveryDue.clear(); await fresh.service.reconcileBroadcasts();
  assert.equal(fresh.service.journal.entries()[0].status, 'confirmed');
  assert.equal(fresh.service.journal.entries()[0].transactionHex, undefined);
  assert.equal(fresh.service.journal.awaitingConfirmation().length, 0);
  assert.equal(completed, 0);
  assert.equal(rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 1);
});

test('confirmed claim orphaned by a coherent reorg becomes eligible again', async t => {
  const key = `${HASH}:0`, confirmationHash = 'a'.repeat(64), replacementHash = 'b'.repeat(64);
  let currentTip = { ...tip, height: 101, hash: confirmationHash }, status = 'available';
  const discover = async () => ({ blocks: new Map([[BLOCK, [{ ...bounty, status }]]]), cursor: 'coherent', tip: currentTip,
    window: { tip: currentTip, blocks: [{ height: 101, hash: currentTip.hash }, { height: 100, hash: BLOCK }], window: 600 } });
  const { service, engine, statePath } = await fixture(t, { discover });
  await service.journal.load();
  await service.journal.update(key, { txid: CLAIM, receivingAddress: config.receivingAddress,
    status: 'confirmed', blockHeight: 101, blockHash: confirmationHash });
  await service.start();
  assert.equal(service.reserved.has(key), true); assert.equal(engine.queue.has(key), false);
  currentTip = { ...currentTip, hash: replacementHash };
  await service.cycle();
  assert.equal(service.reserved.has(key), false);
  assert.equal(engine.queue.has(key), true);
  assert.equal(service.journal.entries().length, 0);
  assert.equal((await new BroadcastJournal(statePath).load()).length, 0);
  await service.prepare(bounty);
});

for (const stage of ['queued', 'before-rename']) for (const invalidation of ['reset', 'disconnect', 'stop']) {
test(`orphan cleanup ${stage} before ${invalidation} preserves the confirmed reservation`, async t => {
  const key = `${HASH}:0`, oldHash = 'a'.repeat(64), newHash = 'b'.repeat(64);
  let currentTip = { ...tip, height: 101, hash: oldHash };
  const { service, rpc, statePath } = await fixture(t, {
    discover: async () => ({ blocks: new Map([[BLOCK, [bounty]]]), cursor: 'coherent', tip: currentTip,
      window: { tip: currentTip, blocks: [{ height: 101, hash: currentTip.hash }, { height: 100, hash: BLOCK }], window: 600 } }),
    engineFactory: options => {
      const engine = new ClaimsEngine(options);
      engine.pump = async () => {}; // No network work is needed to inspect publication/counter ownership.
      return engine;
    },
  });
  const engine = service.engine;
  rpc.socket = { destroyed: false };
  await service.journal.load();
  await service.journal.update(key, { txid: CLAIM, receivingAddress: config.receivingAddress,
    status: 'confirmed', blockHeight: 101, blockHash: oldHash });
  await service.start();
  engine.state.attempts = 7; engine.state.completed = 2; engine.completed.add(key);
  const before = service.journal.entries()[0];
  const queued = Promise.withResolvers(), release = Promise.withResolvers();
  const update = service.journal.update.bind(service.journal);
  service.journal.writing = release.promise;
  let reopened = 0, stopped, invalidated = false, checks = 0;
  const invalidate = () => {
    invalidated = true;
    if (invalidation === 'reset') service.resetCatalog({ reason: 'journal-reset' });
    else if (invalidation === 'disconnect') rpc.emit('disconnected');
    else stopped = service.stop();
  };
  service.journal.update = (outpoint, fields, options = {}) => {
    if (fields !== null) return update(outpoint, fields, options);
    const operation = update(outpoint, fields, { ...options, check: () => {
      if (++checks === 2 && stage === 'before-rename' && !invalidated) invalidate();
      options.check?.();
    } });
    queued.resolve();
    return operation;
  };
  const reopen = engine.reopenConfirmedClaim.bind(engine);
  engine.reopenConfirmedClaim = (...args) => { reopened++; return reopen(...args); };
  currentTip = { ...currentTip, hash: newHash };
  const cycling = service.cycle();
  await queued.promise;
  try {
    if (stage === 'queued') invalidate();
  } finally { release.resolve(); }
  await cycling; await stopped;
  assert.equal(invalidated, true); assert.equal(checks, stage === 'queued' ? 1 : 2);
  assert.deepEqual(service.journal.entries(), [before], 'An invalidated snapshot must not erase the durable confirmation');
  assert.deepEqual(await new BroadcastJournal(statePath).load(), [before]);
  assert.equal(service.reserved.has(key), true);
  assert.equal(engine.queue.has(key), false); assert.equal(reopened, 0);
  assert.equal(engine.completed.has(key), true); assert.equal(engine.reopenedCompletions.has(key), false);
  assert.equal(engine.snapshot().attempts, 7); assert.equal(engine.snapshot().completed, 2);
  assert.equal(service.fatalError, null);
  // A fresh coherent view may still reopen the genuinely orphaned claim.
  if (invalidation !== 'stop') {
    await service.cycle();
    assert.equal(service.journal.entries().length, 0);
    assert.equal(service.reserved.has(key), false); assert.equal(reopened, 1);
    assert.equal(engine.reopenedCompletions.get(key), CLAIM);
    assert.equal(engine.snapshot().attempts, 7); assert.equal(engine.snapshot().completed, 2);
  }
});
}

for (const scenario of ['same-chain', 'aging', 'pending', 'spent', 'no-window', 'lagging-tip', 'capacity', 'storage-failure', 'rollback']) {
  test(`confirmed claim reopening respects ${scenario}`, async t => {
    const key = `${HASH}:0`, oldHash = 'a'.repeat(64), newHash = 'b'.repeat(64);
    let snapshot = { ...tip, height: 101, hash: oldHash }, status = 'available', includeWindow = true;
    const discover = async () => ({ blocks: new Map([[BLOCK, [{ ...bounty, status }]]]), cursor: 'complete', tip: snapshot,
      ...(includeWindow ? { window: { tip: snapshot, blocks: [{ height: snapshot.height, hash: snapshot.hash }], window: 600 } } : {}) });
    const { service, engine } = await fixture(t, { discover });
    await service.journal.load();
    await service.journal.update(key, { txid: CLAIM, receivingAddress: config.receivingAddress,
      status: 'confirmed', blockHeight: 101, blockHash: oldHash });
    if (scenario === 'lagging-tip') snapshot = { ...tip };
    await service.start();
    if (scenario === 'same-chain') { /* Identical coherent snapshot. */ }
    else if (scenario === 'lagging-tip') { /* Never anchored the saved newer receipt locally. */ }
    else if (scenario === 'aging') snapshot = { ...tip, height: 702, hash: newHash };
    else if (scenario === 'rollback') snapshot = { ...tip };
    else snapshot = { ...snapshot, hash: newHash };
    if (scenario === 'pending') status = 'pending_spend';
    if (scenario === 'spent') status = 'spent';
    if (scenario === 'no-window') includeWindow = false;
    if (scenario === 'capacity') engine.canReopenConfirmedClaim = () => false;
    if (scenario === 'storage-failure') {
      const update = service.journal.update.bind(service.journal);
      service.journal.update = (outpoint, fields) => fields === null
        ? Promise.reject(new Error('simulated durable storage failure')) : update(outpoint, fields);
    }
    await service.cycle();
    if (scenario === 'rollback') {
      assert.equal(service.reserved.has(key), false); assert.equal(engine.queue.has(key), true);
      assert.equal(service.journal.entries().length, 0);
    } else {
      assert.equal(service.reserved.has(key), true); assert.equal(engine.queue.has(key), false);
      assert.equal(service.journal.entries()[0].status, 'confirmed');
    }
    assert.equal(Boolean(service.fatalError), scenario === 'storage-failure');
  });
}

test('malformed later catalog row cannot partially reopen an earlier confirmed claim', async t => {
  const key = `${HASH}:0`, oldHash = 'a'.repeat(64), newHash = 'b'.repeat(64);
  const second = { ...bounty, vout: 1 };
  let invalid = false;
  const discover = async () => {
    const currentTip = { ...tip, height: 101, hash: invalid ? newHash : oldHash };
    return { blocks: new Map([[BLOCK, [bounty, invalid ? { ...second, amount: '20000000000' } : second]]]),
      cursor: 'complete', tip: currentTip, window: { tip: currentTip, blocks: [{ height: 101, hash: currentTip.hash }], window: 600 } };
  };
  const { service, engine } = await fixture(t, { discover });
  await service.journal.load();
  await service.journal.update(key, { txid: CLAIM, receivingAddress: config.receivingAddress,
    status: 'confirmed', blockHeight: 101, blockHash: oldHash });
  await service.start(); invalid = true; await service.cycle();
  assert.match(service.fatalError.message, /metadata changed/);
  assert.equal(service.journal.entries()[0].status, 'confirmed');
  assert.equal(service.reserved.has(key), true); assert.equal(engine.queue.has(key), false);
});

test('ACK recovery validates confirmation and retains its witness on malformed metadata', async t => {
  const { service, rpc } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  rpc.respond = async () => ({ tip, status: 'confirmed', block_hash: 'bad', block_height: 100, txid: CLAIM, confirmations: 1 });
  service.recoveryDue.clear();
  await assert.rejects(service.reconcileBroadcasts(), /Invalid claim (confirmation|transaction location)/);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
});

test('reopened ACK replay rechecks catalog after RPC queueing and never loses its saved bytes', async t => {
  const { service, rpc } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  let transmitted = 0;
  rpc.respond = async (method, params, options) => {
    if (method === 'gettransactionstatus') throw Object.assign(new Error('Not indexed'), { code: -32004 });
    service.outpoints.set(`${HASH}:0`, { ...bounty, status: 'pending_spend' });
    options.beforeSend(); transmitted++; return { txid: CLAIM };
  };
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(transmitted, 0);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(`${HASH}:0`), true);
});

test('accepted claim outside the bounded window can replay identical bytes without inventing another winner', async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  let credited = 0;
  engine.completeRecoveredClaim = () => credited++;
  service.discover = async () => ({ blocks: new Map(), cursor: 'aged-cursor', tip: { ...tip, height: 701 } });
  await service.cycle();
  assert.equal(service.outpoints.has(`${HASH}:0`), false);
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  const sends = rpc.calls.filter(call => call.method === 'sendrawtransaction');
  assert.equal(sends.length, 2);
  assert.equal(sends[1].params.transaction_hex, sends[0].params.transaction_hex);
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(`${HASH}:0`), true); assert.equal(credited, 0);
});

test('pending ACK lookup neither rewrites its durable witness nor repeats broadcast or completion counters', async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  let writes = 0, completed = 0;
  const update = service.journal.update.bind(service.journal);
  service.journal.update = (...args) => { writes++; return update(...args); };
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async method => {
    assert.equal(method, 'gettransactionstatus');
    return { tip, status: 'pending', txid: CLAIM, confirmations: 0 };
  };
  for (let i = 0; i < 3; i++) { service.recoveryDue.clear(); await service.reconcileBroadcasts(); }
  assert.equal(writes, 0); assert.equal(completed, 0);
  assert.equal(rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 1);
  assert.equal(service.journal.awaitingConfirmation()[0].transactionHex, 'ab'.repeat(50));
});

async function observedClaimFixture(t) {
  const receivingAddress = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
  const rawTransaction = '02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff0100e40b5402000000020b6578616d706c652e636f6dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000700000000';
  const row = { ...bounty, txid: transactionIdFromRaw(rawTransaction) };
  const prepared = prepareClaim({ bounty: row, rawTransaction, rewardAddress: receivingAddress });
  const message = (type, body) => {
    const header = Buffer.alloc(4); header[0] = type; header.writeUIntBE(body.length, 1, 3);
    return Buffer.concat([header, body]);
  };
  // Synthetic TLS framing tests RPC receipt identity, not native cryptography.
  const proof = extra => Buffer.concat([Buffer.from([2]),
    message(1, Buffer.concat([Buffer.from([3, 3]), Buffer.from(prepared.challenge, 'hex')])),
    ...[2, 8, 11].map(type => message(type, Buffer.alloc(0))), message(15, extra)]).toString('hex');
  const original = attachClaimProof(prepared, proof(Buffer.alloc(0)));
  const alternate = attachClaimProof(prepared, proof(Buffer.from([1])));
  assert.equal(original.txid, alternate.txid); assert.notEqual(original.hex, alternate.hex);
  const setup = await fixture(t, { config: { ...config, receivingAddress },
    validateObserved: validateObservedClaim, validateSaved: validateSavedClaim });
  await setup.service.start();
  const key = `${row.txid}:0`;
  await setup.service.journal.update(key, { txid: original.txid, receivingAddress, status: 'accepted',
    transactionHex: original.hex, transactionHash: transactionDigest(original.hex) });
  setup.service.reserved.add(key);
  return { ...setup, key, original, alternate };
}

test('an older RPC without compact status retains the proof and never falls back to gettransaction', async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  const before = service.journal.entries()[0];
  let completed = 0, queried = 0;
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async method => {
    assert.equal(method, 'gettransactionstatus'); queried++;
    throw Object.assign(new Error('Method not found'), { code: -32601 });
  };
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(queried, 1); assert.equal(completed, 0); assert.equal(service.running, true);
  assert.deepEqual(service.journal.entries(), [before]);
  assert.equal(service.reserved.has(before.outpoint), true);
});

test('compact status cannot accept a different transaction identity or corrupt durable witness', async t => {
  const { service, rpc, original } = await observedClaimFixture(t);
  rpc.respond = async method => {
    assert.equal(method, 'gettransactionstatus');
    return { tip, txid: 'ff'.repeat(32), status: 'confirmed', block_hash: BLOCK, block_height: 100, confirmations: 1 };
  };
  await assert.rejects(service.reconcileBroadcasts(), /conflicting transaction identity/);
  assert.equal(service.journal.entries()[0].transactionHex, original.hex);
  const entries = service.journal.awaitingConfirmation.bind(service.journal);
  service.journal.awaitingConfirmation = () => entries().map(row => ({ ...row, transactionHash: '00'.repeat(32) }));
  rpc.respond = async () => assert.fail('Invalid stored digest must fail before network lookup');
  service.recoveryDue.clear();
  await assert.rejects(service.reconcileBroadcasts(), /durable identity/);
  assert.equal(service.journal.entries()[0].status, 'accepted');
});

test('compact status preserves the original witness until canonical confirmation without downloading another proof', async t => {
  const { service, rpc, engine, key, original, alternate } = await observedClaimFixture(t);
  let completed = 0;
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async method => {
    assert.equal(method, 'gettransactionstatus');
    return { tip, txid: original.txid, status: 'pending', confirmations: 0 };
  };
  await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].transactionHex, original.hex);
  assert.equal(service.journal.entries()[0].transactionHash, transactionDigest(original.hex));
  rpc.respond = async method => {
    assert.equal(method, 'gettransactionstatus');
    return { tip, txid: original.txid, status: 'confirmed', block_hash: BLOCK, block_height: 100, confirmations: 1 };
  };
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'confirmed');
  assert.equal(service.journal.entries()[0].transactionHex, undefined);
  assert.equal(service.reserved.has(key), true);
  assert.equal(completed, 0, 'receipt confirmation must not count a previous ACK twice');
  assert.equal(rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 0);
});

test('same-txid saved witness with a wrong challenge cannot be acknowledged through a compact receipt', async t => {
  const { service, rpc, original, alternate } = await observedClaimFixture(t);
  const tx = parseTransaction(alternate.hex), proof = Buffer.from(tx.inputs[0].witness[0], 'hex');
  proof[7] ^= 1;
  tx.inputs[0].witness[0] = proof.toString('hex');
  const malformed = serializeTransaction(tx).toString('hex');
  assert.equal(transactionIdFromRaw(malformed), original.txid);
  const entries = service.journal.awaitingConfirmation.bind(service.journal);
  service.journal.awaitingConfirmation = () => entries().map(row => ({ ...row,
    transactionHex: malformed, transactionHash: transactionDigest(malformed) }));
  rpc.respond = async () => assert.fail('Damaged local proof must fail before any receipt query');
  await assert.rejects(service.reconcileBroadcasts(), /not bound/);
  assert.equal(service.journal.entries()[0].transactionHex, original.hex);
  assert.equal(service.journal.entries()[0].status, 'accepted');
});

test('receipt reconciliation checks saved proof work against known bounty metadata before compaction', async t => {
  const { service, rpc, key, original, alternate } = await observedClaimFixture(t);
  service.outpoints.set(key, { ...bounty, txid: key.split(':')[0], connection_work_target: '00'.repeat(32) });
  rpc.respond = async () => assert.fail('Invalid local work must fail before any receipt query');
  await assert.rejects(service.reconcileBroadcasts(), /work target/);
  assert.equal(service.journal.entries()[0].transactionHex, original.hex);
  assert.equal(service.journal.entries()[0].status, 'accepted');
});

test('a pending-spend proof being persisted retains its capacity slot and shares concurrent flushes', async t => {
  const second = { ...bounty, vout: 1 }, key = `${HASH}:0`;
  const { service, engine } = await fixture(t, { discover: async () => ({ blocks: new Map([[BLOCK, [bounty, second]]]), cursor: 'cursor', tip }) });
  await service.start();
  service.journal.canRetainAdditionalProofs = count => count <= 1;
  const prepared = await service.prepare(bounty);
  engine.queue.get(key).prepared = prepared;
  engine.pendingProofs.set(key, { proof: 'proof' });
  const release = Promise.withResolvers(), update = service.journal.update.bind(service.journal);
  let writes = 0, first, secondFlush;
  service.journal.update = async (...args) => { writes++; await release.promise; return update(...args); };
  try {
    first = service.persistPendingProofs(key);
    engine.remove(bounty.txid, bounty.vout); engine.pendingProofs.delete(key); engine.proposals.delete(key);
    secondFlush = service.persistPendingProofs();
    assert.equal(service.heldProofs.get(key)?.proof, 'proof');
    assert.equal(writes, 1, 'Concurrent invalidation/shutdown flushes share the atomic write.');
    await assert.rejects(service.prepare(second), /durable proof capacity/);
    assert.equal(service.proofCapacityReservations.has(key), true);
    assert.equal(service.reserved.has(key), true);
  } finally { release.resolve(); }
  await Promise.all([first, secondFlush]);
  assert.equal(service.heldProofs.size, 0);
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.journal.entries()[0].status, 'pending');
});

test('durable-capacity backpressure waits before funding or capture, then resumes after compaction', async t => {
  const second = { ...bounty, vout: 1 }, key = `${HASH}:0`;
  const { service, engine, rpc } = await fixture(t, { discover: async () => ({ blocks: new Map([[BLOCK, [bounty, second]]]), cursor: 'cursor', tip }) });
  await service.start();
  let slots = 1;
  service.journal.canRetainAdditionalProofs = count => count <= slots;
  const first = await service.prepare(bounty);
  engine.proposals.set(key, first);
  await assert.rejects(service.prepare(second), /durable proof capacity/);
  assert.equal(rpc.calls.length, 1, 'Waiting for capacity does not spend another funding lookup');
  await service.submit(first, 'proof'); slots = 0;
  await assert.rejects(service.prepare(second), /durable proof capacity/);
  assert.equal(service.journal.awaitingConfirmation()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.running, true);
  slots = 1; await service.prepare(second);
  assert.equal(service.proofCapacityReservations.has(`${HASH}:1`), true);
  assert.equal(service.proofCapacityReservations.has(key), false);
});

test('cold preparations of spent bounties cannot monopolize durable proof capacity', async t => {
  const key = `${HASH}:0`, second = { ...bounty, vout: 1 };
  let rows = [bounty];
  const { service } = await fixture(t, {
    discover: async () => ({ blocks: new Map([[BLOCK, rows]]), cursor: 'coherent', tip }),
    engineFactory: options => {
      const engine = new ClaimsEngine(options);
      engine.pump = async () => {}; // Drive preparation explicitly; no real socket/helper work.
      return engine;
    },
  });
  const engine = service.engine;
  await service.start();
  service.journal.canRetainAdditionalProofs = count => count <= 1;
  const prepared = await service.prepare(bounty);
  engine.cachePrepared(key, prepared); engine.queue.get(key).prepared = prepared;
  const factor = engine.factors.get(key);
  engine.successCounts.set(key, 0n);
  rows = [{ ...bounty, status: 'spent' }, second];
  await service.cycle();
  assert.equal(engine.hasActive(key), false); assert.equal(engine.pendingProofs.has(key), false);
  assert.equal(engine.proposals.has(key), true, 'The bounded parent/preparation cache may outlive eligibility');
  const nextPrepared = await service.prepare(second);
  engine.cachePrepared(`${HASH}:1`, nextPrepared); engine.queue.get(`${HASH}:1`).prepared = nextPrepared;
  assert.equal(service.proofCapacityReservations.has(key), false);
  assert.equal(engine.proposals.has(key), false, 'A reclaimed slot must invalidate its cached admission too');
  assert.equal(service.proofCapacityReservations.has(`${HASH}:1`), true);
  assert.equal(service.journal.entries().length, 0);
  assert.equal(engine.snapshot().attempts, 0); assert.equal(engine.snapshot().completed, 0);
  assert.equal(engine.factors.get(key), factor); assert.equal(engine.successCounts.get(key), 0n);

  rows = [bounty, second];
  await service.cycle();
  assert.ok(engine.queue.has(key));
  assert.equal(engine.queue.get(key).prepared, undefined, 'Reopened work cannot reuse the reclaimed admission');
  await assert.rejects(service.prepare(bounty), /durable proof capacity/);
  assert.equal(engine.proposals.has(key), false);
  assert.equal(service.proofCapacityReservations.has(key), false);
  assert.equal(engine.snapshot().attempts, 0); assert.equal(engine.snapshot().completed, 0);
  rows = [bounty, { ...second, status: 'spent' }];
  await service.cycle();
  const reopened = await service.prepare(bounty);
  assert.notEqual(reopened, prepared);
  assert.equal(service.proofCapacityReservations.has(key), true);
  assert.equal(service.proofCapacityReservations.has(`${HASH}:1`), false);
  assert.equal(engine.factors.get(key), factor); assert.equal(engine.successCounts.get(key), 0n);
});

for (const owner of ['available', 'active', 'pendingProof', 'winner', 'preparing', 'submitting', 'heldProof', 'inFlight', 'detachedPreparation']) {
test(`capacity reclamation preserves a preparation owned by ${owner}`, async t => {
  const key = `${HASH}:0`, second = { ...bounty, vout: 1 };
  const { service, rpc } = await fixture(t, {
    discover: async () => ({ blocks: new Map([[BLOCK, [bounty, second]]]), cursor: 'coherent', tip }),
    engineFactory: options => {
      const engine = new ClaimsEngine(options);
      engine.pump = async () => {};
      return engine;
    },
  });
  const engine = service.engine;
  await service.start();
  service.journal.canRetainAdditionalProofs = count => count <= 1;
  const prepared = await service.prepare(bounty), job = engine.queue.get(key);
  engine.cachePrepared(key, prepared); job.prepared = prepared;
  if (owner !== 'available') service.outpoints.set(key, { ...bounty, status: 'spent' });
  if (owner === 'active') engine.live.set(key, 1);
  if (owner === 'pendingProof') engine.pendingProofs.set(key, { proof: 'proof', context: prepared.context });
  if (['winner', 'preparing', 'submitting'].includes(owner)) job[owner] = true;
  if (owner === 'heldProof') service.heldProofs.set(key, { proof: 'proof', prepared, writing: null });
  if (owner === 'inFlight') service.inFlightBroadcasts.add(key);
  if (owner === 'detachedPreparation') { engine.queue.delete(key); engine.preparing.add(job); }
  const before = engine.snapshot(), fundingCalls = rpc.calls.length;
  try {
    await assert.rejects(service.prepare(second), /durable proof capacity/);
    assert.equal(service.proofCapacityReservations.has(key), true);
    assert.equal(service.proofCapacityReservations.has(`${HASH}:1`), false);
    assert.equal(engine.proposals.get(key), prepared); assert.equal(job.prepared, prepared);
    assert.equal(rpc.calls.length, fundingCalls, 'Backpressure must precede funding and capture');
    assert.equal(engine.snapshot().attempts, before.attempts);
    assert.equal(engine.snapshot().completed, before.completed);
    if (owner === 'pendingProof') assert.equal(engine.pendingProofs.get(key).proof, 'proof');
    if (owner === 'heldProof') assert.equal(service.heldProofs.get(key).proof, 'proof');
  } finally {
    // Remove only the synthetic owners; no real capture or broadcast was started.
    engine.live.delete(key); engine.pendingProofs.delete(key); engine.preparing.delete(job);
    job.winner = false; job.preparing = false; job.submitting = false;
    service.heldProofs.delete(key); service.inFlightBroadcasts.delete(key);
  }
});
}

test('a queued durable write still occupies admission capacity until its bytes have been committed', async t => {
  const second = { ...bounty, vout: 1 };
  const { service, engine, rpc } = await fixture(t, { discover: async () => ({ blocks: new Map([[BLOCK, [bounty, second]]]), cursor: 'cursor', tip }) });
  await service.start();
  service.journal.canRetainAdditionalProofs = count => count <= 1;
  const prepared = await service.prepare(bounty), gate = Promise.withResolvers();
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async (...args) => { await gate.promise; return update(...args); };
  const submit = service.submit(prepared, 'proof');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(service.reserved.has(`${HASH}:0`), true);
  assert.equal(service.journal.entries().length, 0);
  try { await assert.rejects(service.prepare(second), /durable proof capacity/); }
  finally { gate.resolve(); await submit; }
  assert.equal(service.journal.awaitingConfirmation()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 1);
  assert.equal(engine.pendingProofs.size, 0);
});

for (const finishResetBeforeReply of [false, true]) test(`receipt begun before catalog reset cannot compact its proof (reset finished: ${finishResetBeforeReply})`, async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  let completed = 0;
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async method => {
    assert.equal(method, 'gettransactionstatus'); entered.resolve(); await release.promise;
    return { tip, status: 'confirmed', block_hash: BLOCK, block_height: 100,
      txid: CLAIM, confirmations: 1 };
  };
  service.recoveryDue.clear(); const checking = service.reconcileBroadcasts();
  await entered.promise;
  try {
    service.resetCatalog({ reason: 'journal-reset' });
    if (finishResetBeforeReply) await service.cycle();
  } finally { release.resolve(); }
  await checking;
  assert.equal(service.running, true); assert.equal(service.fatalError, null);
  assert.equal(service.journal.entries()[0].status, 'accepted', 'An old read cannot bypass a reset by using its cleared/replaced window.');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(completed, 0);
  if (!finishResetBeforeReply) await service.cycle();
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'confirmed', 'A fresh read against the coherent replacement may compact it.');
  assert.equal(completed, 0);
});

for (const finishResetBeforeReply of [false, true]) test(`missing receipt begun before catalog reset cannot authorize replay (reset finished: ${finishResetBeforeReply})`, async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  let sent = 0, completed = 0;
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async method => {
    if (method === 'sendrawtransaction') { sent++; return { txid: CLAIM }; }
    assert.equal(method, 'gettransactionstatus'); entered.resolve(); await release.promise;
    throw Object.assign(new Error('not found'), { code: -32004 });
  };
  service.recoveryDue.clear(); const checking = service.reconcileBroadcasts();
  await entered.promise;
  try {
    service.resetCatalog({ reason: 'journal-reset' });
    if (finishResetBeforeReply) await service.cycle();
  } finally { release.resolve(); }
  await checking;
  assert.equal(sent, 0); assert.equal(completed, 0);
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.fatalError, null);
  if (!finishResetBeforeReply) await service.cycle();
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(sent, 1); assert.equal(completed, 0);
  assert.equal(service.journal.entries()[0].status, 'accepted');
});

test('recovery checks the receipt catalog again after waiting for durable pre-send storage', async t => {
  const { service, rpc } = await fixture(t);
  await service.start();
  const key = `${HASH}:0`, raw = 'ab'.repeat(50);
  await service.journal.update(key, { txid: CLAIM, receivingAddress: config.receivingAddress,
    status: 'pending', transactionHex: raw, transactionHash: transactionDigest(raw) });
  service.reserved.add(key);
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async (outpoint, fields) => {
    await update(outpoint, fields);
    if (fields?.status === 'unknown') {
      service.resetCatalog({ reason: 'journal-reset' }); await service.cycle();
    }
  };
  await service.reconcileBroadcasts();
  assert.equal(rpc.calls.some(call => call.method === 'sendrawtransaction'), false);
  assert.equal(service.journal.entries()[0].transactionHex, raw);
  assert.equal(service.journal.entries()[0].status, 'unknown');
  assert.equal(service.fatalError, null);
  service.journal.update = update;
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(rpc.calls.filter(call => call.method === 'sendrawtransaction').length, 1);
  assert.equal(service.journal.entries()[0].status, 'accepted');
});

test('receipt queued for durable compaction rechecks its catalog before replacing the witness', async t => {
  const { service, rpc } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  const update = service.journal.update.bind(service.journal);
  service.journal.writing = release.promise;
  service.journal.update = (...args) => { if (args[1]?.status === 'confirmed') entered.resolve(); return update(...args); };
  rpc.respond = async () => ({ tip, status: 'confirmed', block_hash: BLOCK, block_height: 100,
    txid: CLAIM, confirmations: 1 });
  service.recoveryDue.clear(); const checking = service.reconcileBroadcasts();
  await entered.promise;
  try { service.resetCatalog({ reason: 'journal-reset' }); }
  finally { release.resolve(); }
  await checking;
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.fatalError, null);
  await service.cycle(); service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'confirmed');
});

test('durable confirmation guard also preserves the old file when invalidated just before atomic replacement', async t => {
  const { service, statePath } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  let checks = 0;
  await assert.rejects(service.journal.update(`${HASH}:0`, { txid: CLAIM, receivingAddress: config.receivingAddress,
    status: 'confirmed', blockHash: BLOCK, blockHeight: 100 }, { check: () => {
    if (++checks === 2) throw Object.assign(new Error('snapshot changed'), { code: -32011 });
  } }), /snapshot changed/);
  assert.equal(checks, 2);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  const onDisk = await new BroadcastJournal(statePath).load();
  assert.equal(onDisk[0].transactionHex, 'ab'.repeat(50));
  assert.equal(onDisk[0].status, 'accepted');
});

test('failed first durable write retains the winner for shutdown retry after storage recovers', async t => {
  const { service, engine, rpc, statePath } = await fixture(t);
  await service.start();
  const key = `${HASH}:0`, prepared = await service.prepare(bounty);
  engine.queue.get(key).prepared = prepared;
  engine.pendingProofs.set(key, { proof: 'proof', context: prepared.context });
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async () => { throw Object.assign(new Error('temporary write failure'), { code: 'EIO' }); };
  await assert.rejects(service.submit(prepared, 'proof'), { code: 'EIO', helperFatal: true });
  await service.engineDrain;
  assert.equal(service.reserved.has(key), true);
  assert.equal(service.heldProofs.get(key)?.proof, 'proof');
  assert.equal(rpc.calls.some(call => call.method === 'sendrawtransaction'), false);
  engine.queue.clear(); engine.pendingProofs.clear();
  service.journal.update = update;
  await service.stop();
  const saved = await new BroadcastJournal(statePath).load();
  assert.equal(saved.length, 1, 'Stop must retry the retained proof rather than silently exiting with no durable owner');
  assert.equal(saved[0].status, 'pending');
  assert.equal(saved[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.heldProofs.size, 0);
});

test('a failed shutdown can retry its retained proof after storage recovers without restarting claims', async t => {
  const { service, engine, rpc, statePath } = await fixture(t);
  await service.start();
  const key = `${HASH}:0`, prepared = await service.prepare(bounty);
  engine.queue.get(key).prepared = prepared;
  engine.pendingProofs.set(key, { proof: 'proof', context: prepared.context });
  engine.options.onState({ completed: 7, attempts: 12 });
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async () => { throw Object.assign(new Error('Storage still unavailable during shutdown'), { code: 'EIO' }); };
  const first = service.stop();
  await assert.rejects(first, { code: 'EIO' });
  await service.engineDrain;
  assert.equal(service.heldProofs.get(key)?.proof, 'proof');
  assert.equal(service.reserved.has(key), true);
  engine.queue.clear(); engine.pendingProofs.clear();
  const gate = Promise.withResolvers();
  let writes = 0;
  service.journal.update = async (...args) => { writes++; await gate.promise; return update(...args); };
  const retry = service.stop();
  try {
    assert.notEqual(retry, first, 'A rejected shutdown must not permanently suppress subsequent persistence attempts');
    assert.equal(service.stop(), retry, 'Concurrent shutdown callers must still share the active retry');
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(writes, 1);
  } finally { gate.resolve(); }
  await retry;
  assert.equal(service.stop(), retry, 'A successful shutdown remains idempotent');
  const saved = await new BroadcastJournal(statePath).load();
  assert.equal(saved.length, 1); assert.equal(saved[0].status, 'pending');
  assert.equal(saved[0].transactionHex, 'ab'.repeat(50));
  assert.equal(saved[0].transactionHash, transactionDigest('ab'.repeat(50)));
  assert.equal(service.heldProofs.size, 0); assert.equal(service.running, false);
  assert.equal(engine.starts, 1); assert.equal(rpc.closed, true);
  assert.deepEqual(service.snapshot().claims, { completed: 7, attempts: 12 });
  assert.equal(rpc.calls.some(call => call.method === 'sendrawtransaction'), false);
  await assert.rejects(service.start(), /already been started/);
});

test('confirmation racing a local reorg keeps the witness for a coherent retry instead of stopping', async t => {
  const { service, rpc } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  service.blockWindow = { blocks: [{ height: 99, hash: 'b'.repeat(64) }] };
  rpc.respond = async () => ({ tip, status: 'confirmed', block_hash: 'c'.repeat(64), block_height: 99,
    txid: CLAIM, confirmations: 2 });
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.running, true); assert.equal(service.fatalError, null);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  service.blockWindow.blocks[0].hash = 'c'.repeat(64);
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'confirmed');
});

for (const mode of ['unknown', 'rejected', 'backend']) {
test(`accepted replay preserves the same durable proof and once-counted receipt on ${mode}`, async t => {
  const { service, rpc, engine } = await fixture(t);
  await service.start(); await service.submit(await service.prepare(bounty), 'proof');
  let completed = 0;
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async (method, params, options) => {
    if (method === 'gettransactionstatus') {
      if (mode === 'backend') throw Object.assign(new Error('Backend unavailable'), { code: -32002 });
      throw Object.assign(new Error('Not indexed'), { code: -32004 });
    }
    assert.equal(params.transaction_hex, 'ab'.repeat(50)); options.beforeSend();
    throw Object.assign(new Error('Retry uncertain or rejected'), mode === 'unknown' ? { unknownOutcome: true } : { code: -32020 });
  };
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.running, true); assert.equal(service.reserved.has(`${HASH}:0`), true);
  assert.equal(completed, 0);
  assert.equal(rpc.calls.filter(call => call.method === 'sendrawtransaction').length, mode === 'backend' ? 1 : 2);
});
}

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

test('a definite node rejection retains durable proof ownership; already-known remains uncertain', async t => {
  const { service, rpc } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  rpc.respond = async () => { throw Object.assign(new Error('Rejected'), { code: -32020, data: { node_code: -26 } }); };
  await assert.rejects(service.submit(prepared, 'proof'), error => error.broadcastDeferred === true && error.cause.code === -32020);
  assert.equal(service.journal.entries()[0].status, 'pending');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(`${HASH}:0`), true);
  assert.equal(service.running, true);
  const other = await fixture(t); await other.service.start();
  const another = await other.service.prepare(bounty);
  other.rpc.respond = async () => { throw Object.assign(new Error('Already known'), { code: -32020, data: { node_code: -27 } }); };
  await assert.rejects(other.service.submit(another, 'proof'), error => error.broadcastDeferred === true);
  assert.equal(other.service.journal.entries()[0].status, 'unknown');
  assert.equal(service.running, true);
});

test('failed ACK receipt write retains exact bytes and recovers an evicted transaction without double counting', async t => {
  const { service, rpc } = await fixture(t, {
    engineFactory: options => {
      const engine = new ClaimsEngine(options);
      engine.pump = async () => {}; // Exercise durable recovery, not new TLS captures.
      return engine;
    },
  });
  await service.start();
  const prepared = await service.prepare(bounty), key = `${HASH}:0`;
  const update = service.journal.update.bind(service.journal);
  let failAcknowledgement = true;
  service.journal.update = async (outpoint, fields, options) => {
    if (fields?.status === 'accepted' && failAcknowledgement) {
      failAcknowledgement = false;
      throw Object.assign(new Error('Injected receipt IO failure before rename'), { code: 'EIO' });
    }
    return update(outpoint, fields, options);
  };
  await assert.rejects(service.submit(prepared, 'proof'), error => error.broadcastDeferred === true && error.txid === CLAIM);
  assert.equal(service.journal.entries()[0].status, 'unknown');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(key), true); assert.equal(service.fatalError, null);
  assert.equal(service.engine.snapshot().completed, 0);
  rpc.respond = async (method, params, options) => {
    if (method === 'gettransactionstatus') throw Object.assign(new Error('Previously accepted transaction evicted'), { code: -32004 });
    assert.equal(method, 'sendrawtransaction'); options.beforeSend();
    assert.equal(params.transaction_hex, 'ab'.repeat(50));
    return { txid: CLAIM };
  };
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.engine.snapshot().completed, 1);
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(service.engine.snapshot().completed, 1, 'Replaying an accepted receipt cannot credit it again');
  assert.equal(service.engine.snapshot().attempts, 0, 'Reconciliation does not capture a replacement proof');
  const sends = rpc.calls.filter(call => call.method === 'sendrawtransaction');
  assert.equal(sends.length, 3);
  assert.deepEqual(sends.map(call => call.params.transaction_hex), Array(3).fill('ab'.repeat(50)));
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(key), true); assert.equal(service.running, true);
});

test('real engine keeps a rejected winning proof through pending-spend and available-again catalog changes', async t => {
  let catalogStatus = 'available';
  const { service, rpc } = await fixture(t, {
    engineFactory: options => new ClaimsEngine(options),
    discover: async () => ({ blocks: new Map([[BLOCK, [{ ...bounty, status: catalogStatus }]]]), cursor: `cursor-${catalogStatus}`, tip }),
    poolFactory: () => ({ pacesStarts: true, async start() {}, async close() {},
      resolve(_domain, { signal }) { return new Promise((_resolve, reject) => {
        const cancel = () => reject(Object.assign(new Error('cancelled'), { name: 'AbortError' }));
        if (signal.aborted) cancel(); else signal.addEventListener('abort', cancel, { once: true });
      }); },
      async attempt() { assert.fail('Recovery must not recapture a TLS proof'); },
    }),
  });
  const key = `${HASH}:0`, engine = service.engine;
  await service.start();
  for (let i = 0; i < 100 && !engine.proposals.has(key); i++) await new Promise(resolve => setImmediate(resolve));
  assert.ok(engine.proposals.has(key));
  const job = engine.queue.get(key), prepared = engine.proposals.get(key);
  job.winner = true;
  engine.pendingProofs.set(key, { proof: '02ff', context: prepared.context, due: Infinity, failures: 0 });
  engine.state.attempts = 7;
  let reject = true, transmitted = 0;
  rpc.respond = async (method, params, options) => {
    if (method === 'gettransactionstatus') {
      assert.equal(params.txid, CLAIM);
      throw Object.assign(new Error('Claim absent'), { code: -32004 });
    }
    assert.equal(method, 'sendrawtransaction'); options.beforeSend(); transmitted++;
    assert.equal(params.transaction_hex, 'ab'.repeat(50));
    if (reject) throw Object.assign(new Error('Policy rejected claim'), { code: -32020, data: { node_code: -26 } });
    return { txid: CLAIM };
  };
  await engine.submitVerified(job, new AbortController(), engine.generation);
  assert.equal(service.journal.entries()[0]?.transactionHex, 'ab'.repeat(50), 'Rejected proof must retain durable ownership');
  assert.equal(service.reserved.has(key), true);
  catalogStatus = 'pending_spend'; await service.cycle(); service.recoveryDue.clear();
  await service.reconcileBroadcasts(); assert.equal(transmitted, 1, 'Competing pending spend must not be bypassed');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  catalogStatus = 'available'; reject = false; await service.cycle(); service.recoveryDue.clear();
  await service.reconcileBroadcasts();
  assert.equal(transmitted, 2); assert.equal(engine.state.completed, 1); assert.equal(engine.state.attempts, 7);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
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
    assert.equal(method, 'gettransactionstatus'); assert.equal(params.txid, CLAIM);
    return { tip, status: 'pending', txid: CLAIM, confirmations: 0 };
  };
  await Promise.all([service.reconcileBroadcasts(), service.reconcileBroadcasts()]);
  await service.reconcileBroadcasts();
  assert.equal(completed, 1);
  assert.equal(service.journal.unresolved().length, 0);
  assert.equal(service.journal.entries()[0].transactionHex, 'ab'.repeat(50));
  assert.equal(service.reserved.has(`${HASH}:0`), true);
  assert.equal(rpc.calls.filter(row => row.method === 'sendrawtransaction').length, 1);
});

test('missing index replays exactly the saved public witness and only one request at a time', async t => {
  const { service, rpc, engine } = await uncertainFixture(t);
  const replay = Promise.withResolvers(), sending = Promise.withResolvers();
  const original = service.journal.unresolved()[0]; let completed = 0;
  engine.completeRecoveredClaim = () => completed++;
  rpc.respond = async (method, params, options) => {
    if (method === 'gettransactionstatus') throw Object.assign(new Error('Not indexed'), { code: -32004 });
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
    if (method === 'gettransactionstatus') throw Object.assign(new Error('Not indexed'), { code: -32004 });
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

test('legacy unresolved record without bytes stays isolated without fetching a replacement proof', async t => {
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
  rpc.respond = async () => assert.fail('A legacy row cannot be authenticated by a compact receipt');
  await service.reconcileBroadcasts();
  assert.equal(service.journal.entries()[0].status, 'unknown');
  assert.equal(service.snapshot().reviewRequired, true);
  assert.equal(service.reserved.has(`${HASH}:0`), true);
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

test('legacy compacted ACK backlog cannot starve new retained witnesses and still receives fair checks', async t => {
  const { service } = await uncertainFixture(t), template = service.journal.unresolved()[0];
  const { transactionHex, transactionHash, ...legacy } = template;
  for (let vout = 1; vout <= 20; vout++) {
    await service.journal.update(`${HASH}:${vout}`, { ...legacy, status: 'accepted' });
    service.reserved.add(`${HASH}:${vout}`);
  }
  const selected = [];
  service.reconcileOne = async row => { selected.push(row.outpoint); };
  for (let i = 0; i < 10; i++) {
    service.recoveryDue.set(template.outpoint, Date.now() - 1);
    await service.reconcileBroadcasts();
  }
  assert.equal(selected.filter(key => key === template.outpoint).length, 8);
  assert.equal(selected.filter(key => key !== template.outpoint).length, 2);
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

for (const reason of ['disconnect', 'stream-timeout', 'stream-deadline']) {
test(`real engine saves verified proofs before clearing old-epoch work on reconnect (${reason})`, async t => {
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
  engine.notify({ attempts: 3 });
  engine.successCounts.set(key, 1n);
  service.metrics.started();
  service.metrics.finished({ validationPassed: true, verified: true, proof: '02ff' });
  const metrics = service.metrics.snapshot();
  const factor = engine.factors.get(key);
  const attempts = engine.state.attempts;
  engine.pendingProofs.set(key, { proof: '02ff', due: Infinity });
  if (reason !== 'disconnect') {
    const discover = service.discover;
    service.discover = async () => {
      rpc.emit('disconnected');
      throw new Error(reason === 'stream-timeout' ? 'Bounty transfer timed out.' : 'Bounty transfer exceeded its total time limit.');
    };
    await service.cycle();
    service.discover = discover;
    assert.equal(service.running, true); assert.equal(service.fatalError, null);
    assert.equal(service.status, 'reconnecting');
  } else rpc.emit('disconnected');
  await service.suspending;
  assert.equal(engine.proposals.size, 0);
  assert.equal(engine.pendingProofs.size, 0);
  assert.equal(engine.queue.size, 0);
  assert.equal(engine.successCounts.get(key), 1n);
  assert.equal(engine.state.attempts, attempts);
  for (const field of ['connectionsStarted', 'attemptsFinished', 'valid', 'invalid', 'targetReached']) {
    assert.equal(service.metrics.snapshot()[field], metrics[field]);
  }
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
  assert.equal(engine.successCounts.get(key), 1n);
  assert.equal(engine.state.attempts, attempts);
  await service.reconcileBroadcasts();
  const sends = rpc.calls.filter(call => call.method === 'sendrawtransaction');
  assert.equal(sends.length, 1);
  assert.equal(sends[0].params.transaction_hex, 'ab'.repeat(50));
});
}

for (const marker of ['unknownOutcome', 'helperFatal']) {
  test(`stream timeout classification cannot override ${marker}`, async t => {
    const { service } = await fixture(t, { discover: async () => {
      throw Object.assign(new Error('Bounty transfer timed out.'), { [marker]: true });
    } });
    await assert.rejects(service.start(), /Bounty transfer timed out/);
    assert.equal(service.running, false);
    assert.equal(service.status, marker === 'unknownOutcome' ? 'review-required' : 'failed');
    assert.equal(service.fatalError[marker], true);
  });
}

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

test('failed shutdown remains a startup barrier while allowing a later flush retry', async t => {
  const loading = Promise.withResolvers();
  let failFlush = true, flushes = 0;
  const journal = { load: () => loading.promise, unresolved: () => [], async flush() {
    flushes++;
    if (failFlush) throw Object.assign(new Error('Temporary journal flush failure'), { code: 'EIO' });
  } };
  const { service, rpc, engine } = await fixture(t, { journal });
  const starting = service.start();
  const stopped = service.stop();
  await assert.rejects(stopped, { code: 'EIO' });
  loading.resolve([]);
  await assert.rejects(starting, { name: 'AbortError' });
  assert.equal(service.running, false); assert.equal(service.fatalError, null);
  assert.equal(rpc.connections, 0); assert.equal(engine.starts, 0);
  failFlush = false;
  const retried = service.stop();
  assert.notEqual(retried, stopped);
  await retried;
  assert.equal(flushes, 2); assert.equal(service.status, 'stopped');
  assert.equal(service.stop(), retried); assert.equal(service.running, false);
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

test('early target misses finish once without inflating valid, failed or winning proof counters', async () => {
  const metrics = new ClaimMetrics({ now: () => 0 });
  const miss = { started: true, captured: false, targetMiss: true, validationPassed: null,
    proof: null, verified: false, cancelled: false };
  const pool = metrics.wrap({ async attempt(_context, options) {
    options.onStarted(); options.onResult(miss); return miss;
  } });
  await pool.attempt({});
  assert.deepEqual(metrics.snapshot(), { connectionsStarted: 1, activeConnections: 0, connectionsPerSecond: 0.1,
    attemptsFinished: 1, valid: 0, invalid: 0, cancelled: 0, targetReached: 0, targetMisses: 1 });
  const cancelled = metrics.wrap({ async attempt(_context, options) {
    options.onStarted(); options.onResult({ ...miss, cancelled: true });
    throw Object.assign(new Error('cancelled'), { name: 'AbortError' });
  } });
  await assert.rejects(cancelled.attempt({}), /cancelled/);
  assert.equal(metrics.snapshot().attemptsFinished, 2);
  assert.equal(metrics.snapshot().targetMisses, 2);
  assert.equal(metrics.snapshot().cancelled, 1);
  assert.equal(metrics.snapshot().activeConnections, 0);
});
