import test from 'node:test';
import assert from 'node:assert/strict';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';

const keyOf = row => `${row.txid}:${row.vout}`;
const row = vout => ({ txid: 'a'.repeat(64), vout, amount: '100000000',
  domain: `${String.fromCharCode(97 + vout)}.example`, status: 'available',
  connection_work_target: `0001${'f'.repeat(60)}`, signature_algorithms_mask: 6,
  root_certificates_version: 1 });
async function settle() { for (let i = 0; i < 40; i++) await new Promise(resolve => setImmediate(resolve)); }

function fixture(t) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: 1800000000000 });
  const pending = new Map(), resolutions = [], requests = [];
  let peakResolutions = 0;
  const pool = { pacesStarts: true, async start() {}, async close() {},
    resolve(domain, { signal }) {
      resolutions.push(domain);
      return new Promise((resolve, reject) => {
        const finish = error => {
          if (!pending.has(domain)) return;
          pending.delete(domain); signal.removeEventListener('abort', abort);
          if (error) reject(error); else resolve();
        };
        const abort = () => finish(Object.assign(new Error('Controlled DNS cancellation'), { name: 'AbortError' }));
        pending.set(domain, finish); peakResolutions = Math.max(peakResolutions, pending.size);
        if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
      });
    },
    attempt(context, callbacks) {
      return new Promise(resolve => {
        const request = { context, settled: false };
        request.finish = (changes = {}) => {
          if (request.settled) return;
          request.settled = true; callbacks.signal.removeEventListener('abort', abort);
          const result = { started: true, captured: false, cancelled: true, validationPassed: null,
            seconds: 0.01, proof: null, verified: false, ...changes };
          callbacks.onCapture(result); callbacks.onResult(result); resolve(result);
        };
        const abort = () => request.finish();
        requests.push(request); callbacks.onStarted();
        if (callbacks.signal.aborted) request.finish();
        else callbacks.signal.addEventListener('abort', abort, { once: true });
      });
    },
  };
  const engine = new ClaimsEngine({ isUnlocked: () => true, randomIndex: () => 0,
    poolFactory: () => pool, getNetReward: () => 75283000n,
    options: { connectionsPerSecond: 100, concurrency: 2 },
    submit: async () => assert.fail('DNS queue tests must not submit a claim'),
    prepare: async bounty => ({ bounty, payout: '75283000', context: {
      domain: bounty.domain, txid: 'b'.repeat(64), input_index: 0,
      connection_work_target: bounty.connection_work_target, signature_algorithms_mask: 6,
      root_certificates_version: 1, validation_time: 1800000000,
    } }),
  });
  t.after(() => engine.stop());
  return { engine, pending, resolutions, requests, get peakResolutions() { return peakResolutions; } };
}

for (const invalidation of ['remove', 'retire']) {
  test(`${invalidation} of awakened DNS candidates cannot strand remaining domains`, async t => {
    const f = fixture(t), { engine } = f, rows = Array.from({ length: 6 }, (_, i) => row(i));
    engine.enqueue(rows); engine.start(); await settle();
    assert.deepEqual(f.resolutions, ['a.example', 'b.example']);
    assert.deepEqual([...engine.waitingDns], ['c.example', 'd.example', 'e.example', 'f.example']);
    for (const finish of [...f.pending.values()]) finish();
    await settle();
    assert.equal(engine.connections.size, 2, 'live captures delay admission of the woken domains');
    assert.equal(engine.resolving.size, 0);
    for (const bounty of rows.slice(0, 4)) engine[invalidation](bounty.txid, bounty.vout);
    if (invalidation === 'retire') for (const request of f.requests) request.finish();
    await settle();
    assert.deepEqual(f.resolutions, ['a.example', 'b.example', 'e.example', 'f.example'],
      'free DNS slots must progress without another completion to wake parked domains');
    assert.equal(engine.resolving.size, 2); assert.equal(f.peakResolutions, 2);
    for (let repeat = 0; repeat < 3; repeat++) {
      engine.retainCatalog(rows.slice(4)); engine.enqueue(rows.slice(4)); engine.resume();
      t.mock.timers.tick(5000); await settle();
    }
    assert.equal(f.resolutions.length, 4, 'catalog refresh must not duplicate live resolutions');
    for (const finish of [...f.pending.values()]) finish();
    await settle();
    assert.equal(engine.connections.size, 2); assert.equal(engine.resolving.size, 0);
    assert.equal(f.peakResolutions, 2);
    assert.equal(engine.snapshot().attempts, f.requests.length, 'only actual socket starts count');
    assert.ok(rows.every(bounty => !engine.successCounts.has(keyOf(bounty))));
  });
}

for (const outcome of ['success', 'failure']) {
  test(`DNS ${outcome} after budget exhaustion and periodic rebuild does not strand a new bounty`, async t => {
    const f = fixture(t), { engine } = f;
    const exhausted = { ...row(0), connection_work_target: 'f'.repeat(64) };
    const replacement = { ...exhausted, vout: 1 };
    const invalidCapture = { captured: true, cancelled: false, validationPassed: false };
    engine.enqueue([exhausted]); engine.start(); await settle();
    f.pending.get(exhausted.domain)(); await settle();
    assert.equal(f.requests.length, 2);
    // Keep each capture younger than the native watchdog while the first DNS
    // cache expires. Only completed raw captures consume the exact budget.
    t.mock.timers.tick(30000);
    f.requests[0].finish(invalidCapture); f.requests[1].finish(invalidCapture); await settle();
    assert.equal(engine.successCounts.get(keyOf(exhausted)), 2n);
    t.mock.timers.tick(29000);
    f.requests[2].finish(); f.requests[3].finish(); await settle();
    t.mock.timers.tick(2000);
    f.requests[4].finish(); await settle();
    assert.equal(f.resolutions.length, 2);
    assert.equal(engine.resolving.size, 1, 'DNS renewal is outstanding while another capture is active');
    f.requests[5].finish(invalidCapture); await settle();
    assert.equal(engine.successCounts.get(keyOf(exhausted)), 3n);
    assert.equal(engine.queue.get(keyOf(exhausted)).budgetExceeded, true);
    t.mock.timers.tick(5000); await settle(); // Use the real periodic rebuild.
    assert.equal(engine.scheduler.groups.size, 0);
    assert.deepEqual(engine.scheduler.domainGates.get(exhausted.domain), { ready: false, due: 0 });
    const dnsCompletedAt = Date.now();
    f.pending.get(exhausted.domain)(outcome === 'failure' ? new Error('Controlled DNS renewal failure') : undefined);
    await settle();
    assert.equal(engine.resolving.size, 0);
    assert.equal(engine.scheduler.groups.size, 0, 'DNS does not reopen exhausted work');
    assert.deepEqual(engine.scheduler.domainGates.get(exhausted.domain),
      { ready: true, due: outcome === 'failure' ? dnsCompletedAt + 2000 : 0 });
    engine.enqueue([replacement]); await settle();
    if (outcome === 'failure') {
      assert.equal(f.requests.length, 6);
      t.mock.timers.tick(1999); await settle();
      assert.equal(f.resolutions.length, 2, 'failed resolution retains its two-second retry');
      assert.equal(f.requests.length, 6);
      t.mock.timers.tick(1); await settle();
      assert.equal(f.resolutions.length, 3);
      f.pending.get(exhausted.domain)(); await settle();
    }
    assert.equal(f.requests.length, 8, 'the new bounty fills both slots without stop/start');
    assert.equal(engine.connections.size, 2);
    assert.equal(engine.resolving.size, 0);
    assert.equal(engine.state.attempts, 8);
    assert.equal(engine.successCounts.get(keyOf(exhausted)), 3n, 'old capture budget is unchanged');
    assert.equal(engine.successCounts.has(keyOf(replacement)), false, 'new starts are not fabricated captures');
    assert.equal(engine.completed.size, 0);
    assert.equal(engine.domainStats.get(`${exhausted.domain}:6`).completed, 3);
  });
}

test('a late DNS completion after full domain removal cannot leave a scheduler gate or revive work', async t => {
  const f = fixture(t), { engine } = f, bounty = row(0);
  engine.enqueue([bounty]); engine.start(); await settle();
  assert.equal(engine.resolving.size, 1);
  engine.remove(bounty.txid, bounty.vout);
  t.mock.timers.tick(5000); await settle();
  assert.equal(engine.queue.size, 0);
  assert.equal(engine.scheduler.groups.size, 0);
  assert.equal(engine.scheduler.domainGates.size, 0);
  f.pending.get(bounty.domain)(); await settle();
  assert.equal(engine.resolving.size, 0);
  assert.equal(engine.scheduler.domainGates.size, 0);
  assert.equal(f.requests.length, 0);
  assert.equal(engine.state.attempts, 0);
});

test('reopening DNS capacity preserves failed-resolution retry deadlines and cancellation', async t => {
  const f = fixture(t), { engine } = f, rows = [row(0), row(1), row(2)];
  engine.enqueue(rows); engine.start(); await settle();
  for (const finish of [...f.pending.values()]) finish(new Error('Controlled DNS failure'));
  await settle();
  assert.deepEqual(f.resolutions, ['a.example', 'b.example', 'c.example']);
  assert.equal(engine.dns.get('a.example').expires, Date.now() + 2000);
  assert.equal(engine.dns.get('b.example').expires, Date.now() + 2000);
  t.mock.timers.tick(1999); await settle();
  assert.equal(f.resolutions.length, 3);
  t.mock.timers.tick(1); await settle();
  assert.equal(f.resolutions.length, 4, 'one free resolution slot retries at the original deadline');
  assert.equal(engine.resolving.size, 2); assert.equal(f.peakResolutions, 2);
  await engine.stop(); t.mock.timers.tick(60000); await settle();
  assert.equal(f.pending.size, 0); assert.equal(engine.resolving.size, 0);
  assert.equal(engine.waitingDns.size, 0); assert.equal(f.resolutions.length, 4);
  assert.equal(engine.snapshot().attempts, 0);
});
