import test from 'node:test';
import assert from 'node:assert/strict';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { ClaimConnectionPolicy, BOOTSTRAP_PROBE_COUNT, BOOTSTRAP_PROBE_INTERVAL_MS,
  RECOVERY_PROBE_INTERVAL_MS, MAX_RECOVERY_POLICIES } from '../src/core/claim-connection-policy.mjs';
import { isWorthAttempting } from '../src/core/claim-priority.mjs';

const hash = id => id.toString(16).padStart(64, '0');
const key = row => `${row.txid}:${row.vout}`;
const row = (id, domain = 'alpha.example', extra = {}) => ({ txid: hash(id), vout: 0,
  domain, amount: '100000000', status: 'available', connection_work_target: `00000${'f'.repeat(59)}`,
  root_certificates_version: 1, signature_algorithms_mask: 7, ...extra });
async function settle() { for (let i = 0; i < 40; i++) await new Promise(resolve => setImmediate(resolve)); }

function fixture(t, { concurrency = 4, minExpectedReturn, netReward = 75283000n } = {}) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: 1800000000000 });
  const requests = [];
  const pool = { pacesStarts: true, async start() {}, async close() {}, async resolve() {},
    attempt(context, callbacks) {
      return new Promise(resolve => {
        const request = { context, callbacks, started: false, done: false };
        request.start = () => { assert.equal(request.started, false); request.started = true; request.startedAt = Date.now(); callbacks.onStarted(); };
        request.finish = (overrides = {}) => {
          if (request.done) return;
          request.done = true; callbacks.signal.removeEventListener('abort', abort);
          const result = { started: request.started, captured: false, cancelled: true, validationPassed: null,
            seconds: 0, proof: null, verified: false, ...overrides };
          if (request.started) callbacks.onCapture(result);
          callbacks.onResult(result); resolve(result);
        };
        const abort = () => request.finish();
        callbacks.signal.addEventListener('abort', abort, { once: true });
        requests.push(request); if (callbacks.signal.aborted) abort();
      });
    },
  };
  const engine = new ClaimsEngine({ isUnlocked: () => true, randomIndex: () => 0,
    getNetReward: () => netReward, ...(minExpectedReturn === undefined ? {} : { minExpectedReturn }),
    prepare: async bounty => ({ bounty, payout: String(netReward), context: { domain: bounty.domain,
      txid: hash(10000 + Number(BigInt(`0x${bounty.txid}`))), input_index: 0,
      connection_work_target: bounty.connection_work_target, signature_algorithms_mask: bounty.signature_algorithms_mask,
      root_certificates_version: 1, validation_time: 1800000000 } }),
    submit: async () => assert.fail('bootstrap tests do not broadcast'),
    poolFactory: () => pool, options: { connectionsPerSecond: 100, concurrency },
  });
  t.after(() => engine.stop());
  return { engine, requests, async advance(ms) { t.mock.timers.tick(ms); await settle(); } };
}

test('policy samples 32 starts at 250ms and then one per minute, without idle credit', () => {
  const policy = new ClaimConnectionPolicy();
  assert.equal(BOOTSTRAP_PROBE_COUNT, 32); assert.equal(BOOTSTRAP_PROBE_INTERVAL_MS, 250);
  let now = 10000;
  for (let i = 0; i < 32; i++) {
    assert.equal(policy.reserveProbe('alpha:7', i, now), true);
    assert.equal(policy.reserveProbe('beta:7', 'other', now + 100000), false, 'only one unacknowledged probe globally');
    assert.equal(policy.releaseProbe('wrong-token'), false);
    const due = policy.probeStarted('alpha:7', now, i);
    assert.equal(policy.probes.get('alpha:7').started, i + 1);
    assert.equal(due, now + (i === 31 ? RECOVERY_PROBE_INTERVAL_MS : 250));
    assert.equal(policy.reserveProbe('alpha:7', 'early', due - 1), false);
    now = due;
  }
  assert.equal(policy.reserveProbe('alpha:7', 'minute', now), true);
  policy.probeStarted('alpha:7', now, 'minute');
  now += 1000000;
  assert.equal(policy.reserveProbe('beta:7', 'after-idle', now), true);
  policy.probeStarted('beta:7', now, 'after-idle');
  assert.equal(policy.reserveProbe('gamma:7', 'burst', now), false, 'idle does not earn a catch-up burst');
  assert.equal(policy.probeDue('gamma:7', now), now + 250);
});

test('cancelled reservations and policy eviction cannot consume counters or reset the global gate', () => {
  const policy = new ClaimConnectionPolicy();
  assert.equal(policy.reserveProbe('alpha:7', 1, 1000), true);
  for (let i = 0; i < MAX_RECOVERY_POLICIES + 50; i++) policy.probeDue(`d${i}:7`, 1000);
  assert.equal(policy.probes.size, MAX_RECOVERY_POLICIES);
  assert.equal(policy.probes.has('alpha:7'), true, 'pending reservation survives bounded eviction');
  policy.retain(new Set()); assert.equal(policy.probes.size, 1);
  assert.equal(policy.releaseProbe(1), true);
  assert.equal(policy.probes.get('alpha:7').started, 0);
  assert.equal(policy.reserveProbe('beta:7', 2, 1000), true);
  policy.probeStarted('beta:7', 1000, 2);
  policy.clear(); policy.retain(new Set());
  assert.equal(policy.reserveProbe('new:6', 3, 1249), false);
  assert.equal(policy.reserveProbe('new:6', 3, 1250), true);
  policy.probeStarted('new:6', 1250, 3);
  assert.equal(policy.nextGlobalStart, 1500);
});

test('200 cold 20-bit bounties receive bounded sampling without bypassing the normal floor', async t => {
  const { engine, requests } = fixture(t);
  const rows = Array.from({ length: 200 }, (_, i) => row(i + 1));
  engine.enqueue(rows); engine.start(); await settle();
  assert.equal(engine.queue.size, 1, 'one representative samples this domain/mask');
  const job = engine.queue.values().next().value;
  assert.equal(isWorthAttempting(job.rawPriority, engine.connectionRate(job)), false);
  assert.equal(job.recoveryProbe, true); assert.equal(requests.length, 1);
  assert.equal(engine.state.attempts, 0); assert.equal(engine.domainStats.size, 0);
  assert.equal(engine.successCounts.size, 0); assert.equal(engine.connectionPolicy.probes.get('alpha.example:7').started, 0);
  requests[0].start(); await settle();
  assert.equal(engine.state.attempts, 1); assert.equal(engine.domainStats.size, 0);
  requests[0].finish({ captured: true, cancelled: false, validationPassed: true, seconds: 0.01 }); await settle();
  assert.equal(engine.domainStats.get('alpha.example:7').completed, 1);
  assert.equal(engine.successCounts.get(key(job.bounty)), 1n);
});

test('cross-domain pending ACK blocks only probes; cancellation releases it without a fabricated sample', async t => {
  const f = fixture(t), rows = [row(1), row(2, 'beta.example'), row(3, 'gamma.example')];
  f.engine.enqueue(rows); f.engine.start(); await settle();
  assert.equal(f.requests.length, 1);
  await f.advance(10000);
  f.engine.rebuild(); f.engine.kick(); await settle();
  assert.equal(f.requests.length, 1, 'time and rebuild cannot duplicate the global reservation');
  f.requests[0].finish(); await settle();
  assert.equal(f.requests.length, 2);
  assert.equal(f.engine.state.attempts, 0); assert.equal(f.engine.domainStats.size, 0);
  f.requests[1].start(); f.requests[1].finish(); await settle();
  assert.equal(f.engine.state.attempts, 1); assert.equal(f.requests.length, 2);
  for (let i = 0; i < 3; i++) { f.engine.retainCatalog(rows); f.engine.enqueue(rows); f.engine.rebuild(); f.engine.kick(); await settle(); }
  await f.advance(249); assert.equal(f.requests.length, 2);
  await f.advance(1); assert.equal(f.requests.length, 3, 'other policies resume at the fresh global deadline');
  assert.equal(f.engine.pendingRecovery.size, 1);
  const normal = row(4, 'normal.example', { connection_work_target: 'f'.repeat(64) });
  f.engine.enqueue([normal]); f.engine.kick(); await settle();
  assert.ok(f.requests.some(request => request.context.domain === 'normal.example'), 'economic work can run while a probe awaits its ACK');
});

test('global probe starts remain 250ms apart across policies, churn, and idle periods', async t => {
  const f = fixture(t, { concurrency: 100 });
  let rows = Array.from({ length: 20 }, (_, i) => row(i + 1, `d${i}.example`));
  f.engine.enqueue(rows); f.engine.start(); await settle();
  const times = [];
  for (let i = 0; i < 10; i++) {
    assert.equal(f.requests.length, i + 1);
    const request = f.requests[i]; request.start(); times.push(request.startedAt); request.finish(); await settle();
    for (const bounty of rows) f.engine.remove(bounty.txid, bounty.vout);
    rows = Array.from({ length: 20 }, (_, j) => row(100 + i * 20 + j, `new${i}-${j}.example`));
    f.engine.retainCatalog(rows); f.engine.enqueue(rows); f.engine.rebuild(); f.engine.kick(); await settle();
    await f.advance(249); assert.equal(f.requests.length, i + 1);
    await f.advance(1);
  }
  assert.ok(times.every((time, i) => !i || time - times[i - 1] >= 250));
  await f.advance(1000000); assert.equal(f.requests.length, 11, 'unacknowledged work still owns the sole probe reservation');
  f.requests[10].start(); f.requests[10].finish(); await settle();
  assert.equal(f.requests.length, 11);
  await f.advance(249); assert.equal(f.requests.length, 11);
  await f.advance(1); assert.equal(f.requests.length, 12, 'long idle produces no burst credit');
});

test('bootstrap declines zero payout and exhausted capture budget; zero floor stays economic', async t => {
  const zero = fixture(t, { netReward: 0n });
  assert.equal(zero.engine.enqueue([row(1)]), 0);
  zero.engine.start(); await settle(); assert.equal(zero.requests.length, 0);
  const policy = new ClaimsEngine({ isUnlocked: () => true, randomIndex: () => 0,
    prepare: async () => assert.fail(), submit: async () => assert.fail(), minExpectedReturn: 0 });
  const bounty = row(2); policy.enqueue([bounty]); policy.rebuild();
  assert.equal(policy.queue.get(key(bounty)).recoveryProbe, false);
  assert.equal(policy.connectionPolicy.probes.size, 0);
  policy.successCounts.set(key(row(3)), (1n << 64n) - 1n);
  assert.equal(policy.enqueue([row(3)]), 0);
});

test('engine exhausts 32 acknowledged bootstrap probes before entering minute recovery', async t => {
  const f = fixture(t, { concurrency: 100 });
  f.engine.enqueue([row(1)]); f.engine.start(); await settle();
  for (let i = 0; i < 32; i++) {
    assert.equal(f.requests.length, i + 1);
    f.requests[i].start(); f.requests[i].finish(); await settle();
    f.engine.rebuild(); f.engine.kick(); await settle();
    if (i < 31) { await f.advance(249); assert.equal(f.requests.length, i + 1); await f.advance(1); }
  }
  assert.equal(f.engine.connectionPolicy.probes.get('alpha.example:7').started, 32);
  assert.equal(f.engine.state.attempts, 32); assert.equal(f.engine.domainStats.size, 0);
  assert.equal(f.engine.successCounts.size, 0);
  await f.advance(59999); assert.equal(f.requests.length, 32);
  await f.advance(1); assert.equal(f.requests.length, 33);
});

test('real fast validated samples promote a cold domain into normal configured capacity', async t => {
  const f = fixture(t, { concurrency: 4 });
  f.engine.enqueue([row(1)]); f.engine.start(); await settle();
  const job = f.engine.queue.values().next().value;
  let observations = 0;
  while (!isWorthAttempting(job.rawPriority, f.engine.connectionRate(job))) {
    assert.ok(observations < 32, 'fast enough real samples must qualify during bootstrap');
    assert.equal(f.requests.length, observations + 1);
    f.requests[observations].start();
    f.requests[observations].finish({ captured: true, cancelled: false, validationPassed: true, seconds: 0.01 });
    observations++; await settle();
    await f.advance(250);
  }
  f.engine.rebuild(); f.engine.kick(); await settle();
  assert.equal(job.recoveryProbe, false);
  assert.equal(f.engine.connections.size, 4, 'normal user concurrency resumes after observed profitability');
  assert.equal(f.engine.domainStats.get('alpha.example:7').completed, observations);
  assert.equal(f.engine.successCounts.get(key(job.bounty)), BigInt(observations));
  assert.equal(f.engine.state.attempts, observations, 'queued normal work still needs actual start acknowledgements');
});
