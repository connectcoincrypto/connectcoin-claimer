import test from 'node:test';
import assert from 'node:assert/strict';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';

const keyOf = bounty => `${bounty.txid}:${bounty.vout}`;
const row = vout => ({ txid: 'a'.repeat(64), vout, amount: '100000000', domain: 'alpha.example',
  status: 'available', connection_work_target: `0001${'f'.repeat(60)}`,
  signature_algorithms_mask: 6, root_certificates_version: 1 });
const prepared = bounty => ({ bounty, payout: '75283000', context: {
  domain: bounty.domain, txid: 'b'.repeat(64), input_index: 0,
  connection_work_target: bounty.connection_work_target, signature_algorithms_mask: 6,
  root_certificates_version: 1, validation_time: 1800000000,
} });
async function settle() { for (let i = 0; i < 30; i++) await new Promise(resolve => setImmediate(resolve)); }

// Exercise the real scheduler/pump and public invalidation/lifecycle methods.
// Only preparation completion and connection lifetime are controlled here; no
// waiting/preparing flag or scheduler entry is injected, and no network is used.
function fixture(t, { concurrency = 800, warmVout = 99 } = {}) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: 1800000000000 });
  const pending = new Map(), prepareCalls = [], requests = [];
  let activePreparations = 0, peakPreparations = 0;
  const pool = { pacesStarts: true, async start() {}, async close() {}, async resolve() {},
    attempt(context, callbacks) {
      return new Promise(resolve => {
        const request = { context, callbacks, settled: false };
        const abort = () => request.finish({ captured: false, cancelled: true, validationPassed: null });
        request.finish = (changes = {}) => {
          if (request.settled) return;
          request.settled = true; callbacks.signal.removeEventListener('abort', abort);
          const result = { started: true, captured: true, cancelled: false, validationPassed: true,
            seconds: 0.05, proof: null, verified: false, ...changes };
          callbacks.onCapture(result); callbacks.onResult(result); resolve(result);
        };
        requests.push(request); callbacks.onStarted();
        if (callbacks.signal.aborted) abort(); else callbacks.signal.addEventListener('abort', abort, { once: true });
      });
    },
  };
  const engine = new ClaimsEngine({
    isUnlocked: () => true, randomIndex: () => 0, poolFactory: () => pool,
    getNetReward: () => 75283000n, options: { connectionsPerSecond: 800, concurrency },
    submit: async () => assert.fail('queue preparation tests must not submit a claim'),
    prepare: (bounty, { signal }) => {
      if (bounty.vout === warmVout) return Promise.resolve(prepared(bounty));
      prepareCalls.push(bounty.vout); peakPreparations = Math.max(peakPreparations, ++activePreparations);
      return new Promise((resolve, reject) => {
        const finish = (error) => {
          if (!pending.has(bounty.vout)) return;
          pending.delete(bounty.vout); activePreparations--; signal.removeEventListener('abort', abort);
          if (error) reject(error); else resolve(prepared(bounty));
        };
        const abort = () => finish(Object.assign(new Error('Controlled preparation cancellation'), { name: 'AbortError' }));
        pending.set(bounty.vout, finish);
        if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
      });
    },
  });
  t.after(() => engine.stop());
  return { engine, pending, prepareCalls, requests, get peakPreparations() { return peakPreparations; } };
}

async function parkBehindLiveCapture(f) {
  const rows = Array.from({ length: 17 }, (_, i) => row(i)), warm = row(99);
  f.engine.enqueue([warm]); f.engine.start(); await settle();
  assert.equal(f.requests.length, f.engine.options.concurrency);
  f.engine.enqueue(rows); f.requests[0].finish(); await settle();
  assert.deepEqual(f.prepareCalls, [0, 1, 2, 3]);
  assert.equal(f.engine.preparing.size, 4);
  assert.equal(f.engine.scheduler.entries.size, 18);
  assert.equal(f.engine.scheduler.groups.get(warm.domain).ready.total, 14,
    'queued preparations remain indexed while the prepared leader can still capture');
  assert.equal(f.engine.connections.size, f.engine.options.concurrency);
  return { rows, warm };
}

for (const invalidation of ['remove', 'retire']) {
  test(`${invalidation} of previously awakened candidates cannot strand preparation waiters at 800/800`, async t => {
    const f = fixture(t), { engine } = f;
    const { rows, warm } = await parkBehindLiveCapture(f);
    for (const finish of [...f.pending.values()]) finish();
    await settle();
    assert.equal(engine.preparing.size, 0);
    assert.equal(engine.connections.size, 800, 'occupied capture slots delay further preparation');
    // The old completion-only policy awoke just candidates 4..7. Invalidate
    // exactly those, then remove/retire all prepared leaders. The untouched
    // candidates 8..16 must progress without a new prepare completion to help.
    for (const bounty of rows.slice(4, 8)) engine[invalidation](bounty.txid, bounty.vout);
    for (const bounty of [...rows.slice(0, 4), warm]) engine[invalidation](bounty.txid, bounty.vout);
    if (invalidation === 'retire') {
      assert.ok(f.requests.filter(request => !request.settled).every(request => !request.callbacks.signal.aborted),
        'normal window exit must not cancel already-started captures');
      for (const request of f.requests) request.finish();
    }
    await settle();
    const remaining = rows.slice(8);
    assert.equal(engine.queue.size, 9);
    assert.deepEqual(f.prepareCalls.slice(4), [8, 9, 10, 11], 'free preparation slots follow the original priority order');
    assert.equal(engine.preparing.size, 4);
    assert.equal(f.peakPreparations, 4);
    for (let cycle = 0; cycle < 3; cycle++) {
      engine.retainCatalog(remaining); engine.enqueue(remaining); engine.resume();
      t.mock.timers.tick(5000); await settle();
    }
    assert.equal(f.prepareCalls.length, 8, 'discovery/refresh must not duplicate live preparations');
    for (const finish of [...f.pending.values()]) finish();
    await settle();
    assert.equal(engine.connections.size, 800, 'captures resume without a restart or manual wake');
    assert.ok(f.requests.slice(801).every(request => request.callbacks.bountyId === keyOf(rows[8])),
      'all same-domain captures stay on the best ready candidate');
    assert.ok(remaining.every(bounty => !engine.successCounts.has(keyOf(bounty))), 'preparing/admitting cannot invent successful captures');
    assert.equal(engine.snapshot().attempts, f.requests.length, 'every actual start is counted exactly once');
    assert.equal(engine.pendingProofs.size, 0);
    assert.equal(engine.completed.size, 0);
  });
}

test('preparation failures release capacity without removing per-job backoff or exceeding four preparations', async t => {
  const f = fixture(t), { engine } = f;
  const { rows } = await parkBehindLiveCapture(f);
  for (const finish of [...f.pending.values()]) finish(new Error('Controlled temporary preparation failure'));
  await settle();
  const deadlines = rows.slice(0, 4).map(bounty => engine.queue.get(keyOf(bounty)).due);
  assert.deepEqual(deadlines, Array(4).fill(Date.now() + 30000));
  f.requests.find(request => !request.settled).finish(); await settle();
  assert.deepEqual(f.prepareCalls, [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.equal(engine.preparing.size, 4); assert.equal(f.peakPreparations, 4);
  t.mock.timers.tick(29999); await settle();
  assert.equal(f.prepareCalls.length, 8, 'failed jobs retain their backoff and cannot bypass occupied preparation slots');
  for (const finish of [...f.pending.values()]) finish();
  await settle();
  assert.equal(f.peakPreparations, 4);
  assert.deepEqual(rows.slice(0, 4).map(bounty => engine.queue.get(keyOf(bounty)).due), deadlines);
});

for (const action of ['stop', 'suspend']) {
  test(`${action} drains parked preparations without starting replacements; restart resumes safely`, async t => {
    const f = fixture(t), { engine } = f;
    await parkBehindLiveCapture(f);
    const starts = f.requests.length;
    await engine[action]();
    t.mock.timers.tick(120000); await settle();
    assert.equal(f.requests.length, starts); assert.equal(f.prepareCalls.length, 4);
    assert.equal(engine.preparing.size, 0);
    assert.equal(engine.connections.size, 0); assert.equal(f.pending.size, 0);
    if (action === 'stop') engine.start(); else engine.resume();
    await settle();
    assert.equal(engine.preparing.size, 4);
    assert.deepEqual(f.prepareCalls, [0, 1, 2, 3, 0, 1, 2, 3]);
    assert.equal(f.peakPreparations, 4);
  });
}

test('20,000 candidates: each preparation vacancy touches only the replacement and completed job', async t => {
  const f = fixture(t, { concurrency: 4, warmVout: 65535 }), { engine } = f;
  const warm = row(65535), rows = Array.from({ length: 19999 }, (_, index) => row(index));
  engine.enqueue([warm]); engine.start(); await settle();
  const setReady = t.mock.method(engine.scheduler, 'setReady');
  const next = t.mock.method(engine.scheduler, 'next');
  engine.enqueue(rows); f.requests[0].finish(); await settle();
  assert.equal(engine.queue.size, 20000);
  assert.deepEqual(f.prepareCalls, [0, 1, 2, 3]);
  assert.ok(setReady.mock.callCount() <= 8, 'initial saturation must not park the full backlog');
  assert.ok(next.mock.callCount() <= 12, 'prepared captures bypass the indexed preparation backlog');
  for (let cycle = 0; cycle < 6; cycle++) {
    const writes = setReady.mock.callCount(), selections = next.mock.callCount();
    f.pending.values().next().value(new Error('Controlled retry'));
    await settle();
    assert.equal(engine.preparing.size, 3, 'full capture capacity still delays preparation');
    f.requests.find(request => !request.settled).finish(); await settle();
    assert.equal(engine.preparing.size, 4);
    assert.equal(f.prepareCalls.at(-1), 4 + cycle);
    assert.ok(setReady.mock.callCount() - writes <= 4, 'one vacancy must not wake/repark 20,000 jobs');
    assert.ok(next.mock.callCount() - selections <= 6, 'selection work must be independent of queue length');
  }
  assert.equal(f.peakPreparations, 4);
  assert.equal(engine.snapshot().attempts, f.requests.length);
  assert.equal(engine.successCounts.size, 1, 'only the warm bounty produced actual captures');
  assert.equal(engine.pendingProofs.size, 0); assert.equal(engine.completed.size, 0);
});
