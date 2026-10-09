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
    attach: () => ({ txid: CLAIM, hex: 'claim-hex' }), transactionId: () => HASH,
    setTimer: (callback, delay) => { const timer = { callback, delay, unref() {} }; timers.push(timer); return timer; },
    clearTimer: timer => { timer.cleared = true; }, emit: (event, details) => events.push({ event, details }), ...overrides });
  t.after(() => service.stop());
  return { service, rpc, engine, events, timers, statePath, directory };
}

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

test('writes pending state durably before broadcasting and retains accepted outpoints across restart', async t => {
  const { service, rpc, statePath } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  rpc.respond = async method => {
    assert.equal(method, 'sendrawtransaction');
    const saved = JSON.parse(await readFile(statePath, 'utf8'));
    assert.equal(saved.records[0].status, 'pending');
    assert.equal(saved.records[0].txid, CLAIM);
    assert.deepEqual(Object.keys(saved.records[0]).sort(), ['outpoint', 'receivingAddress', 'status', 'txid', 'updatedAt']);
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

test('uncertain broadcast stops all work and the next process refuses to connect before review', async t => {
  const { service, rpc, statePath, timers } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  rpc.respond = async () => { throw Object.assign(new Error('Connection lost after write.'), { unknownOutcome: true }); };
  await assert.rejects(service.submit(prepared, 'proof'), error => error.unknownOutcome === true);
  assert.equal(service.snapshot().status, 'review-required');
  assert.equal(service.snapshot().running, false);
  assert.equal(rpc.closed, true);
  assert.equal(timers.at(-1).cleared, true);
  assert.equal(JSON.parse(await readFile(statePath, 'utf8')).records[0].status, 'unknown');
  const restarted = await fixture(t, { statePath });
  await assert.rejects(restarted.service.start(), /previous claim broadcast needs review/);
  assert.equal(restarted.rpc.connections, 0);
  assert.equal(restarted.engine.starts, 0);
});

test('cancellation during durable preflight removes the record without transmitting', async t => {
  const controller = new AbortController();
  const { service, rpc } = await fixture(t);
  await service.start();
  const prepared = await service.prepare(bounty);
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async (key, row) => { await update(key, row); if (row?.status === 'pending') controller.abort(); };
  await assert.rejects(service.submit(prepared, 'proof', { signal: controller.signal }), { name: 'AbortError', notSent: true });
  assert.equal(rpc.calls.some(call => call.method === 'sendrawtransaction'), false);
  assert.equal(service.journal.entries().length, 0);
  assert.equal(service.reserved.size, 0);
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
  await assert.rejects(service.submit(prepared, 'proof'), error => error.unknownOutcome === true);
  assert.equal(service.running, false);
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

test('real engine discards old-epoch proposals and verified proofs before reconnect while preserving its work budget', async t => {
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
  const old = await preparedAtEpoch(0);
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
  await service.cycle();
  const fresh = await preparedAtEpoch(1);
  assert.notEqual(fresh, old);
  assert.equal(fresh.epoch, service.epoch);
  assert.equal(rpc.calls.filter(call => call.method === 'gettransaction').length, 2);
  assert.equal(rpc.calls.some(call => call.method === 'sendrawtransaction'), false);
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
