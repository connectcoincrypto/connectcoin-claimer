import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { P2CDomainStats } from '../src/core/claim-priority.mjs';

const hash = value => value.toString(16).padStart(64, '0');
const key = bounty => `${bounty.txid}:${bounty.vout}`;
const row = (id, domain, amount = '1000000') => ({ txid: hash(id), vout: 0, domain, amount,
  status: 'available', connection_work_target: 'f'.repeat(64), root_certificates_version: 1,
  signature_algorithms_mask: 7 });
const context = bounty => ({ domain: bounty.domain, txid: hash(BigInt(`0x${bounty.txid}`) + 1000n), input_index: 0,
  connection_work_target: bounty.connection_work_target, root_certificates_version: 1,
  signature_algorithms_mask: bounty.signature_algorithms_mask, validation_time: 1800000000 });
const domains = requests => requests.map(request => request.context.domain);
async function settle() { for (let i = 0; i < 30; i++) await new Promise(resolve => setImmediate(resolve)); }

// The pool owns socket pacing, but does not acknowledge any admission until the
// test tells it to. No helper, socket, proof generation or broadcast is used.
function fixture(t, { concurrency = 6, rate = 100, holdAbort = false, pacesStarts = true } = {}) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: 1800000000000 });
  const requests = [];
  let active = 0, peak = 0;
  const pool = { pacesStarts, async start() {}, async close() {}, async resolve() {},
    attempt(publicContext, callbacks) {
      return new Promise(resolve => {
        const request = { context: publicContext, callbacks, started: false, settled: false, dispatchedAt: performance.now() };
        request.start = () => {
          assert.equal(request.started, false, 'fixture cannot acknowledge a start twice');
          assert.equal(request.settled, false, 'start must precede the terminal response');
          request.started = true; callbacks.onStarted();
        };
        request.finish = (changes = {}) => {
          if (request.settled) return;
          request.settled = true; active--;
          callbacks.signal.removeEventListener('abort', abort);
          const result = { started: request.started, captured: false, cancelled: true,
            validationPassed: null, seconds: 0, proof: null, verified: false, ...changes };
          if (request.started) callbacks.onCapture(result);
          callbacks.onResult(result); resolve(result);
        };
        const abort = () => { if (!holdAbort) request.finish(); };
        callbacks.signal.addEventListener('abort', abort, { once: true });
        requests.push(request); peak = Math.max(peak, ++active);
        if (callbacks.signal.aborted) abort();
      });
    } };
  const engine = new ClaimsEngine({ isUnlocked: () => true, randomIndex: () => 0,
    prepare: async bounty => ({ bounty, context: context(bounty), payout: bounty.amount }),
    submit: async () => assert.fail('admission tests must never submit a claim'),
    poolFactory: () => pool, options: { connectionsPerSecond: rate, concurrency } });
  t.after(async () => {
    const stopped = engine.stop();
    for (const request of requests) request.finish();
    await stopped;
  });
  function ready(bounties) {
    engine.enqueue(bounties);
    for (const bounty of bounties) {
      const job = engine.queue.get(key(bounty));
      if (job) job.prepared = { bounty, context: context(bounty), payout: bounty.amount };
      engine.dns.set(bounty.domain, { ok: true, expires: Date.now() + 60000 });
    }
  }
  return { engine, requests, ready, get active() { return active; }, get peak() { return peak; } };
}

const ordinary = () => [row(1, 'alpha.example', '3000000'), row(2, 'beta.example'), row(3, 'gamma.example')];

test('a delayed start acknowledgement does not block other domains or exceed global capacity', async t => {
  const f = fixture(t);
  f.ready(ordinary()); f.engine.start(); await settle();
  assert.equal(f.requests.length, 6, 'unacknowledged admissions may fill available global slots');
  assert.deepEqual(domains(f.requests), ['alpha.example', 'alpha.example', 'beta.example', 'alpha.example', 'gamma.example', 'alpha.example']);
  assert.equal(f.engine.snapshot().attempts, 0, 'dispatch is not a TCP start observation');
  assert.equal(f.engine.snapshot().active, 6); assert.equal(f.active, 6); assert.equal(f.peak, 6);
  f.requests[2].start(); await settle();
  assert.equal(f.engine.snapshot().attempts, 1, 'another domain can start while the first remains unacknowledged');
  assert.equal(f.requests[0].started, false); assert.equal(f.requests.length, 6);
  t.mock.timers.tick(5000); await settle();
  assert.equal(f.requests.length, 6, 'refresh must not bypass occupied admission slots');
});

for (const [rate, limit, concurrency = 100] of [[1, 2], [100, 10], [256, 26], [1, 2, 1000], [1000, 100, 1000], [2147483647, 128, 2147483647]]) {
  test(`unacknowledged admissions at ${rate}/second stay within the short lookahead of ${limit}`, async t => {
    const f = fixture(t, { concurrency, rate });
    f.ready(ordinary()); f.engine.start(); await settle();
    assert.equal(f.requests.length, limit, 'available concurrency must not become a long queue of unstarted requests');
    assert.equal(f.engine.snapshot().attempts, 0);
    f.requests[0].start(); await settle();
    assert.equal(f.requests.length, limit + 1, 'an acknowledged start releases one lookahead slot while remaining active');
    assert.equal(f.requests.filter(request => !request.started).length, limit);
    assert.equal(f.active, limit + 1);
    t.mock.timers.tick(5000); await settle();
    assert.equal(f.requests.length, limit + 1, 'elapsed time must not grow the unacknowledged backlog');
  });
}

test('bounded start lookahead permits active concurrency above 512 as TCP starts are acknowledged', async t => {
  const f = fixture(t, { concurrency: 1000, rate: 10000 });
  f.ready(ordinary()); f.engine.start(); await settle();
  assert.equal(f.requests.length, 128);
  let acknowledged = 0;
  while (f.requests.length < 1000) {
    const batch = f.requests.slice(acknowledged);
    for (const request of batch) { request.start(); acknowledged++; }
    await settle();
    assert.ok(f.requests.length - acknowledged <= 128, 'only IPC admissions have a fixed bound');
  }
  assert.equal(f.active, 1000);
  assert.equal(f.engine.connections.size, 1000);
  assert.equal(f.peak, 1000);
  assert.equal(f.engine.enabled, true);
});

test('out-of-order start acknowledgements do not reorder subsequent fair and economic admissions', async t => {
  const f = fixture(t);
  f.ready(ordinary()); f.engine.start(); await settle();
  assert.equal(f.requests.length, 6);
  for (const index of [5, 2, 4, 1, 3, 0]) f.requests[index].start();
  assert.equal(f.engine.snapshot().attempts, 6);
  for (const index of [5, 2, 0]) f.requests[index].finish();
  await settle();
  assert.deepEqual(domains(f.requests.slice(6)), ['alpha.example', 'alpha.example', 'beta.example'],
    'callback arrival order must not consume extra turns or move the fair cursor backwards');
  assert.equal(f.engine.snapshot().attempts, 6, 'replacement admissions still await their own TCP acknowledgements');
  assert.equal(f.active, 6); assert.equal(f.peak, 6);
});

test('cancellation before start releases an admission without inventing attempts or domain observations', async t => {
  const f = fixture(t, { concurrency: 3 });
  f.ready(ordinary()); f.engine.start(); await settle();
  assert.equal(f.requests.length, 3);
  f.requests[0].finish(); await settle();
  assert.equal(f.requests.length, 4, 'a cancelled pre-start request must return its global slot');
  assert.equal(f.engine.snapshot().attempts, 0);
  assert.equal(f.engine.domainStats.size, 0); assert.equal(f.engine.successCounts.size, 0);
  assert.equal(f.active, 3); assert.equal(f.peak, 3);
  f.requests[3].start();
  assert.equal(f.engine.snapshot().attempts, 1);
});

function failedStats() {
  const stats = new P2CDomainStats();
  for (let i = 0; i < 10; i++) stats.record(false, 10);
  return stats;
}

test('one pending recovery probe owns its policy across representative replacement and elapsed minutes', async t => {
  const f = fixture(t, { concurrency: 3 });
  f.engine.domainStats.set('alpha.example:7', failedStats());
  const first = row(1, 'alpha.example', '1000'), replacement = row(2, 'alpha.example', '1100');
  f.ready([first]); f.engine.start(); await settle();
  assert.equal(f.requests.length, 0);
  t.mock.timers.tick(60000); await settle();
  assert.equal(f.requests.length, 1, 'one due recovery policy cannot occupy all free slots');
  f.ready([replacement]); f.engine.rebuild(); f.engine.kick(); await settle();
  assert.equal(f.engine.queue.get(key(replacement)).recoveryProbe, true);
  t.mock.timers.tick(60000); await settle();
  assert.equal(f.requests.length, 1, 'a new representative and another elapsed minute cannot duplicate an unacknowledged probe');
  f.requests[0].start(); f.requests[0].finish(); await settle();
  assert.equal(f.engine.snapshot().attempts, 1);
  t.mock.timers.tick(59999); await settle(); assert.equal(f.requests.length, 1);
  t.mock.timers.tick(1); await settle();
  assert.equal(f.requests.length, 2, 'the minute starts at the acknowledged TCP start');
  assert.equal(f.requests[1].context.txid, context(replacement).txid);
});

test('a recovery probe cancelled before start releases its policy without spending the next minute', async t => {
  const f = fixture(t, { concurrency: 3 });
  f.engine.domainStats.set('alpha.example:7', failedStats());
  f.ready([row(1, 'alpha.example', '1000')]); f.engine.start(); await settle();
  t.mock.timers.tick(60000); await settle(); assert.equal(f.requests.length, 1);
  f.requests[0].finish(); await settle();
  assert.equal(f.requests.length, 2, 'a no-start cancellation must not leave the recovery policy reserved');
  assert.equal(f.engine.snapshot().attempts, 0);
  assert.equal(f.active, 1); assert.equal(f.peak, 1);
});

test('stop cancels started and unacknowledged admissions and late acknowledgements cannot restart dispatch', async t => {
  const f = fixture(t, { concurrency: 4, holdAbort: true });
  f.ready(ordinary()); f.engine.start(); await settle();
  assert.equal(f.requests.length, 4);
  f.requests[1].start(); f.requests[3].start();
  const stopped = f.engine.stop(); await settle();
  assert.ok(f.requests.every(request => request.callbacks.signal.aborted));
  f.requests[0].start(); await settle();
  assert.equal(f.engine.snapshot().enabled, false); assert.equal(f.engine.snapshot().status, 'off');
  assert.equal(f.engine.snapshot().attempts, 3, 'a late real start remains counted without reopening admission');
  assert.equal(f.requests.length, 4, 'a real late TCP acknowledgement must not reopen admission');
  for (const request of f.requests) request.finish();
  await stopped;
  t.mock.timers.tick(120000); await settle(); f.engine.kick(); await settle();
  assert.equal(f.requests.length, 4); assert.equal(f.engine.snapshot().active, 0); assert.equal(f.active, 0);
});

test('adapters without native pacing retain serialized acknowledgements and recover delayed starts', async t => {
  let now = 0; t.mock.method(performance, 'now', () => now);
  const f = fixture(t, { concurrency: 4, rate: 10, pacesStarts: false });
  const advance = async milliseconds => { now += milliseconds; t.mock.timers.tick(milliseconds); await settle(); };
  f.ready(ordinary()); f.engine.start(); await settle();
  assert.equal(f.requests.length, 1);
  await advance(250);
  assert.equal(f.requests.length, 1, 'an adapter without a socket rate gate must not queue simultaneous future starts');
  f.requests[0].start();
  await advance(99); assert.equal(f.requests.length, 1);
  await advance(1); assert.equal(f.requests.length, 2);
  await advance(1000); assert.equal(f.requests.length, 2, 'the fallback still waits for its second real start');
  f.requests[1].start();
  await settle(); assert.equal(f.requests.length, 3, 'late starts recover the shared schedule instead of adding a new full interval');
  assert.equal(f.engine.nextStart, 450, 'advance the prior deadline before applying the one-second bound');
  assert.deepEqual(f.requests.map(request => request.dispatchedAt), [0, 350, 1350]);
  assert.equal(f.engine.snapshot().attempts, 2); assert.equal(f.peak, 3);
});

for (const rate of [1, 7, 10, 50, 100, 256]) {
  for (const offset of [-0.000001, 0, 0.000001]) {
    test(`fallback ${rate}/s advances before its one-second debt boundary (${offset}ms)`, async t => {
      let now = 0; t.mock.method(performance, 'now', () => now);
      const f = fixture(t, { concurrency: 4, rate, pacesStarts: false });
      f.ready(ordinary()); f.engine.start(); await settle();
      f.requests[0].start(); await settle();
      const interval = 1000 / rate;
      assert.equal(f.engine.nextStart, interval);
      now = interval; f.engine.kick(); await settle();
      assert.equal(f.requests.length, 2);
      now = 2 * interval + 1000 + offset;
      f.requests[1].start(); await settle();
      assert.ok(Math.abs(f.engine.nextStart - Math.max(2 * interval, now - 1000)) < 1e-9);
      assert.ok(f.engine.nextStart >= now - 1000, 'debt never exceeds one second after a start');
      assert.equal(f.engine.snapshot().attempts, 2, 'admission does not invent a TCP acknowledgement');
    });
  }
}

test('fallback discards true idle credit but preserves an unexpired deadline', async t => {
  let now = 0; t.mock.method(performance, 'now', () => now);
  const f = fixture(t, { rate: 10, pacesStarts: false });
  f.ready(ordinary()); f.engine.start(); await settle(); f.requests[0].start(); await settle();
  f.engine.clear(); await settle();
  now = 50; f.ready(ordinary()); await settle(); f.engine.kick(); await settle();
  assert.equal(f.requests.length, 1, 'clearing work cannot bypass the future rate deadline');
  now = 3000; f.engine.kick(); await settle();
  assert.equal(f.requests.length, 2); f.requests[1].start(); await settle();
  assert.equal(f.engine.nextStart, 3100, 'idle time cannot become a one-second catch-up burst');
  assert.equal(f.requests.length, 2);
});

test('a cancelled late fallback start cannot consume the pending idle reset', async t => {
  let now = 0; t.mock.method(performance, 'now', () => now);
  const f = fixture(t, { concurrency: 1, rate: 10, holdAbort: true, pacesStarts: false });
  f.ready(ordinary()); f.engine.start(); await settle();
  f.engine.clear(); await settle();
  assert.equal(f.requests[0].callbacks.signal.aborted, true);
  f.requests[0].start(); await settle();
  assert.equal(f.engine.snapshot().attempts, 1, 'the cancelled request still reports its real start');
  now = 5000; f.ready(ordinary()); f.engine.kick(); await settle();
  assert.equal(f.requests.length, 1, 'the cancelled request still occupies capacity until drained');
  f.requests[0].finish(); await settle();
  assert.equal(f.requests.length, 2); f.requests[1].start(); await settle();
  assert.equal(f.engine.nextStart, 5100, 'the next live admission rebases after the idle interval');
  assert.equal(f.engine.snapshot().attempts, 2);
});

test('cancelled-only fallback capacity does not bridge idle after removing its bounty', async t => {
  let now = 0; t.mock.method(performance, 'now', () => now);
  const f = fixture(t, { concurrency: 1, rate: 10, holdAbort: true, pacesStarts: false });
  const first = row(1, 'alpha.example');
  f.ready([first]); f.engine.start(); await settle();
  f.requests[0].start(); await settle(); f.engine.remove(first.txid, first.vout); await settle();
  assert.equal(f.requests[0].callbacks.signal.aborted, true);
  now = 5000; f.ready([row(2, 'beta.example')]); f.engine.kick(); await settle();
  assert.equal(f.requests.length, 1);
  f.requests[0].finish(); await settle(); f.requests[1].start(); await settle();
  assert.equal(f.engine.nextStart, 5100);
  assert.equal(f.requests.length, 2, 'resumed work must not inherit cancelled-only capacity debt');
});

test('restart after draining stop can fill fresh slots without retaining old pending admissions', async t => {
  const f = fixture(t);
  f.ready(ordinary()); f.engine.start(); await settle();
  assert.equal(f.requests.length, 6);
  f.requests[1].start(); f.requests[3].start();
  await f.engine.stop();
  assert.equal(f.active, 0); assert.ok(f.requests.every(request => request.callbacks.signal.aborted));
  f.engine.start(); await settle();
  assert.equal(f.requests.length, 12, 'the new session must recover all slots, including those that previously lacked an acknowledgement');
  assert.ok(f.requests.slice(6).every(request => !request.callbacks.signal.aborted && !request.started));
  assert.equal(f.active, 6); assert.equal(f.peak, 6);
  const before = f.engine.snapshot().attempts;
  f.requests[8].start();
  assert.equal(f.engine.snapshot().attempts, before + 1);
});

test('recovery restart releases an unstarted probe but preserves cooldown after a real start', async t => {
  const f = fixture(t, { concurrency: 3 });
  f.engine.domainStats.set('alpha.example:7', failedStats());
  f.ready([row(1, 'alpha.example', '1000')]); f.engine.start(); await settle();
  t.mock.timers.tick(60000); await settle(); assert.equal(f.requests.length, 1);
  await f.engine.stop();
  assert.equal(f.engine.snapshot().attempts, 0); assert.equal(f.active, 0);
  f.engine.start(); await settle();
  assert.equal(f.requests.length, 2, 'an unstarted probe in the prior session must not reserve the new session or spend its minute');
  f.requests[1].start(); await f.engine.stop();
  f.engine.start(); await settle(); assert.equal(f.requests.length, 2);
  t.mock.timers.tick(59999); await settle(); assert.equal(f.requests.length, 2);
  t.mock.timers.tick(1); await settle();
  assert.equal(f.requests.length, 3, 'a stopped session must not erase the minute consumed by an acknowledged probe');
  assert.equal(f.engine.snapshot().attempts, 1); assert.equal(f.active, 1); assert.equal(f.peak, 1);
});
