import test from 'node:test';
import assert from 'node:assert/strict';
import { ClaimsEngine } from '../src/core/claims.mjs';
import {
  claimPriority, selectionPriority, domainPriority, isWorthAttempting,
  compareClaimPriority, P2CDomainStats, PRIORITY_FACTOR_SCALE,
  PRIORITY_FACTOR_MAX, MIN_EXPECTED_RETURN,
} from '../src/core/claim-priority.mjs';

const SPACE = 1n << 256n;
const MAX_TARGET = 'f'.repeat(64);
const hash = value => value.toString(16).padStart(64, '0');
const bounty = (id, amount = '1000000', vout = 0, extra = {}) => ({
  txid: hash(id), vout, amount, domain: 'example.com', status: 'available',
  connection_work_target: MAX_TARGET, signature_algorithms_mask: 7,
  root_certificates_version: 1, ...extra,
});
const key = item => `${item.txid}:${item.vout}`;
const context = item => ({ domain: item.domain, txid: hash(900), input_index: 0,
  connection_work_target: item.connection_work_target, root_certificates_version: 1,
  signature_algorithms_mask: item.signature_algorithms_mask, validation_time: 1800000000 });
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {
  let resolve;
  const promise = new Promise(accept => { resolve = accept; });
  return { promise, resolve };
};
async function until(predicate) {
  for (let attempt = 0; attempt < 500; attempt++) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 2));
  }
  throw new Error('Timed out waiting for deterministic claim scheduling');
}
function fixture(t, options = {}) {
  const starts = [], submissions = [], draws = [];
  const engine = new ClaimsEngine({
    isUnlocked: () => true, retryDelayMs: 300000,
    options: { connectionsPerSecond: 256, concurrency: 1 },
    randomIndex: length => { draws.push(length); return 0; },
    prepare: async item => { starts.push(key(item)); return { item, context: context(item) }; },
    generateProof: async () => '020100',
    submit: async prepared => { submissions.push(key(prepared.item)); return prepared.context.txid; },
    ...options,
  });
  t.after(() => engine.stop());
  return { engine, starts, submissions, draws };
}
function take(engine, now = Date.now()) {
  const next = engine.nextReady(now);
  if (next) engine.markAssigned(next[1]);
  return next?.[0];
}
const stat = (success, seconds, count = 1) => {
  const result = new P2CDomainStats();
  for (let i = 0; i < count; i++) result.record(success, seconds);
  return result;
};

test('economic numerator includes target+1 and positive net payout with exact maximum arithmetic', () => {
  assert.equal(claimPriority(MAX_TARGET, 1000000000000000000n), SPACE * 1000000000000000000n);
  assert.equal(claimPriority('0'.repeat(64), 1n), 1n);
  assert.equal(claimPriority(hash(255), 123n), 256n * 123n);
  assert.equal(claimPriority(MAX_TARGET, 0n), 0n);
  assert.equal(claimPriority(MAX_TARGET, -1n), 0n);
  assert.equal(claimPriority(MAX_TARGET, 1000000000000000001n), 0n);
  assert.equal(PRIORITY_FACTOR_SCALE, 1000000);
  assert.equal(PRIORITY_FACTOR_MAX, 1100000);
  assert.equal(selectionPriority(SPACE * 123n, PRIORITY_FACTOR_MAX), SPACE * 123n * 1100000n);
});

test('raw expected return floor is inclusive and independent of random factor', () => {
  assert.equal(MIN_EXPECTED_RETURN, 1000);
  assert.equal(domainPriority(claimPriority(MAX_TARGET, 200n), 5), 1000);
  assert.equal(isWorthAttempting(claimPriority(MAX_TARGET, 200n), 5), true);
  assert.equal(isWorthAttempting(claimPriority(MAX_TARGET, 199n), 5), false);
  assert.equal(isWorthAttempting(claimPriority(hash((1n << 255n) - 1n), 400n), 5), true);
  for (const rate of [NaN, Infinity, -Infinity, -1, 0]) assert.equal(isWorthAttempting(SPACE, rate), false);
});

test('domain statistics use the requested EMA with a decaying initial 5/s prior', () => {
  const stats = new P2CDomainStats();
  assert.equal(stats.connectionRate(), 5);
  assert.equal(stats.connections, 0.1); assert.equal(stats.totalTime, 0.02);
  stats.record(true, 0.2); stats.record(false, 0.8);
  const connections = 0.1 * 0.999 ** 2 + 0.001 * 0.999;
  const seconds = 0.02 * 0.999 ** 2 + 0.001 * (0.2 * 0.999 + 0.8);
  assert.ok(Math.abs(stats.connections - connections) < 1e-15);
  assert.ok(Math.abs(stats.totalTime - seconds) < 1e-15);
  assert.ok(Math.abs(stats.connectionRate() - connections / seconds) < 1e-12);
  const before = { ...stats };
  for (const seconds of [-1, NaN, Infinity, -Infinity]) stats.record(true, seconds);
  for (const success of [0, 1, null, undefined, 'true']) stats.record(success, 0.1);
  assert.deepEqual({ ...stats }, before);
  assert.equal(stats.completed, 2);
});

test('persistent failures keep decaying beyond 100 observations and cross the profitability floor', () => {
  const stats = new P2CDomainStats(), priority = claimPriority(MAX_TARGET, 1000000n);
  let previous = stats.connectionRate();
  for (let n = 1; n <= 20000; n++) {
    stats.record(false, 0.1);
    const rate = stats.connectionRate();
    assert.ok(rate > 0 && rate < previous);
    previous = rate;
    if ([100, 1000, 10000, 20000].includes(n)) {
      const weight = 0.999 ** n;
      const expected = (0.1 * weight) / (0.02 * weight + 0.1 * (1 - weight));
      assert.ok(Math.abs(rate / expected - 1) < 1e-11);
    }
  }
  assert.equal(stats.completed, 20000);
  assert.equal(isWorthAttempting(priority, stats.connectionRate()), false);
  assert.equal(isWorthAttempting(priority, 0.1 / (0.02 + 100 * 0.1)), true, 'old permanent prior incorrectly stays eligible');
  for (let n = 0; n < 20000; n++) stats.record(true, 0.1);
  assert.ok(Math.abs(stats.connectionRate() - 10) < 1e-6, 'real later successes can recover an observed policy');
});

test('failed domain EMA survives catalog refresh and admits only a delayed recovery probe without restoring the prior', t => {
  const { engine, starts } = fixture(t);
  const failed = bounty(1, '1000000', 0, { domain: 'failed.example' });
  const fresh = bounty(2, '1000000', 0, { domain: 'fresh.example' });
  engine.enqueue([failed, fresh]);
  const job = engine.queue.get(key(failed));
  for (let i = 0; i < 20000; i++) {
    engine.observeResult({ job, started: true, observed: false }, { started: true, captured: false, validationPassed: false, cancelled: false, seconds: 0.1 });
  }
  const stats = engine.domainStats.get('failed.example:7'), rate = stats.connectionRate();
  assert.equal(isWorthAttempting(job.rawPriority, rate), false);
  engine.rebuild();
  for (let i = 0; i < 4; i++) assert.equal(take(engine), key(fresh));
  engine.retainCatalog([failed, fresh]);
  engine.enqueue([failed, fresh]);
  assert.strictEqual(engine.domainStats.get('failed.example:7'), stats);
  assert.equal(stats.connectionRate(), rate);
  const due = engine.connectionPolicy.probes.get('failed.example:7');
  assert.ok(due >= Date.now() + 59000);
  for (let i = 0; i < 4; i++) assert.equal(take(engine, due - 1), key(fresh), 'the failed policy stays gated before the probe deadline');
  assert.equal(take(engine, due), key(failed), 'one representative becomes eligible for a recovery observation after one minute');
  assert.strictEqual(engine.domainStats.get('failed.example:7'), stats);
  assert.equal(stats.connectionRate(), rate, 'probe admission does not reset or rewrite the EMA');
  assert.equal(stats.completed, 20000);
  assert.deepEqual(starts, [], 'the test must not open connections');
});

test('EMA preserves older observations, zero durations, and finite positive extremes', () => {
  const old = stat(false, 10), fresh = new P2CDomainStats();
  for (let n = 0; n < 101; n++) { old.record(true, 0.1); fresh.record(true, 0.1); }
  assert.ok(old.connectionRate() < fresh.connectionRate(), 'older observations decay but do not fall out at 100');
  const failed = new P2CDomainStats(), instant = new P2CDomainStats();
  for (let n = 0; n < 800000; n++) { failed.record(false, Number.MAX_VALUE); instant.record(true, 0); }
  assert.ok(Number.isFinite(failed.connectionRate()) && failed.connectionRate() > 0);
  assert.ok(Number.isFinite(instant.connectionRate()) && instant.connectionRate() > 5005);
  const priority = claimPriority(MAX_TARGET, 1000000000000000000n);
  assert.equal(isWorthAttempting(priority, failed.connectionRate()), false);
  assert.equal(isWorthAttempting(priority, instant.connectionRate()), true);
  assert.ok(Number.isFinite(domainPriority(selectionPriority(priority, PRIORITY_FACTOR_MAX), instant.connectionRate(), PRIORITY_FACTOR_SCALE)));
  assert.ok(Number.isFinite(domainPriority(SPACE * 2n, Number.MAX_VALUE, 4)), 'scaled finite products survive intermediate overflow');
  assert.equal(domainPriority(SPACE * 2n, Number.MAX_VALUE, 4), Number.MAX_VALUE / 2);
});

test('exact ties use Core outpoint order: reversed TXID bytes then numeric vout, never a tie lottery', () => {
  const jobs = [bounty(1, '1000', 10), bounty(256, '1000'), bounty(1, '1000', 2)]
    .map(item => ({ bounty: item, priority: 999n }));
  jobs.sort(compareClaimPriority);
  assert.deepEqual(jobs.map(job => key(job.bounty)), [bounty(256), bounty(1, '1000', 2), bounty(1, '1000', 10)].map(key));
});

test('queue selection ranks expected net value, not nominal reward, Number rounding or easy targets alone', async t => {
  const { engine, starts } = fixture(t, { getNetReward: item => BigInt(item.net ?? item.amount) });
  const entries = [
    bounty(1, '9007199254740992'), bounty(2, '9007199254740993'),
    bounty(3, '1000000000000000000', 0, { connection_work_target: hash((1n << 192n) - 1n) }),
    bounty(4, '1000000000000000000', 0, { net: '200' }),
    bounty(5, '1000', 0, { connection_work_target: hash((1n << 255n) - 1n) }),
  ];
  assert.equal(Number(entries[0].amount), Number(entries[1].amount));
  engine.enqueue(entries); engine.start();
  await until(() => !engine.running && engine.snapshot().completed === 4);
  assert.deepEqual(starts, [entries[1], entries[0], entries[4], entries[3]].map(key));
});

test('bounded random factor can reverse close expected values but never a gap greater than 10%', t => {
  let index = 0;
  const { engine, draws } = fixture(t, { randomIndex: length => { draws.push(length); return [100000, 0, 0][index++]; } });
  const entries = [bounty(1, '10000'), bounty(2, '10999'), bounty(3, '11001')];
  engine.enqueue(entries);
  assert.deepEqual(entries.map(item => engine.queue.get(key(item)).factor), [1100000, 1000000, 1000000]);
  assert.deepEqual(Array.from({ length: 3 }, () => take(engine)), Array(3).fill(key(entries[2])));
  engine.scheduler.setReady(key(entries[2]), false);
  assert.deepEqual(Array.from({ length: 3 }, () => take(engine)), Array(3).fill(key(entries[0])));
  assert.deepEqual(draws, [100001, 100001, 100001]);
});

test('maximum factor cannot admit a bounty below the unrandomized profitability floor', t => {
  const { engine } = fixture(t, { randomIndex: length => length - 1 });
  const low = bounty(1, '199', 0, { domain: 'alpha.example' });
  const equal = bounty(2, '200', 0, { domain: 'zeta.example' });
  engine.enqueue([low, equal]);
  assert.equal(take(engine), key(equal));
  assert.equal(take(engine), key(equal));
});

for (const permutation of [[0, 1, 2], [2, 1, 0], [1, 2, 0]]) {
  test(`same factors produce stable Core tie order across enqueue permutation ${permutation.join('')}`, t => {
    const { engine, draws } = fixture(t);
    const entries = [bounty(1, '1000', 10), bounty(256, '1000'), bounty(1, '1000', 2)];
    engine.enqueue(permutation.map(index => entries[index]));
    const expected = [entries[1], entries[2], entries[0]].map(key);
    for (const best of expected) {
      assert.deepEqual(Array.from({ length: 3 }, () => take(engine)), Array(3).fill(best));
      engine.scheduler.remove(best);
    }
    assert.equal(take(engine), undefined);
    assert.deepEqual(draws, [100001, 100001, 100001], 'selection never redraws or shuffles ties');
  });
}

test('nextReady is pure until an assignment is committed after preparation', t => {
  const { engine, draws } = fixture(t);
  const entries = [bounty(1, '1000'), bounty(2, '2000')];
  engine.enqueue(entries);
  for (let index = 0; index < 5; index++) assert.equal(engine.nextReady(Date.now())[0], key(entries[1]));
  engine.markAssigned(engine.nextReady(Date.now())[1]);
  assert.equal(engine.nextReady(Date.now())[0], key(entries[1]), 'committing a connection does not rotate away from the best bounty');
  assert.deepEqual(draws, [100001, 100001]);
});

test('fair domain turns alternate with economic domain turns and both select the domain best bounty', t => {
  const { engine } = fixture(t);
  const a1 = bounty(1, '2000', 0, { domain: 'alpha.example' });
  const a2 = bounty(2, '1000', 0, { domain: 'alpha.example' });
  const b1 = bounty(3, '10000', 0, { domain: 'beta.example' });
  const b2 = bounty(4, '8000', 0, { domain: 'beta.example' });
  const c1 = bounty(5, '5000', 0, { domain: 'gamma.example' });
  engine.enqueue([c1, b2, a2, b1, a1]);
  assert.deepEqual(Array.from({ length: 8 }, () => take(engine)), [a1, b1, b1, b1, c1, b1, a1, b1].map(key));
});

test('economic domain ranking uses measured TLS throughput, not only the nominal domain leader', t => {
  const { engine } = fixture(t);
  const alpha = bounty(1, '10000', 0, { domain: 'alpha.example' });
  const beta = bounty(2, '2000', 0, { domain: 'beta.example' });
  engine.domainStats.set('beta.example:7', stat(true, 0.01, 1000));
  engine.enqueue([beta, alpha]);
  assert.equal(take(engine), key(alpha), 'first assignment is fair, not economic');
  assert.equal(take(engine), key(beta), 'faster beta outranks larger but slower alpha economically');
});

test('TLS statistics are separate for each exact signature mask; untried masks retain their prior', t => {
  const { engine } = fixture(t);
  const blocked = bounty(1, '1000', 0, { domain: 'alpha.example', signature_algorithms_mask: 1 });
  const fresh = bounty(2, '1000', 0, { domain: 'alpha.example', signature_algorithms_mask: 2 });
  const beta = bounty(3, '500', 0, { domain: 'beta.example' });
  engine.domainStats.set('alpha.example:1', stat(false, 10, 100));
  engine.enqueue([blocked, fresh, beta]);
  assert.equal(take(engine), key(fresh));
  assert.equal(take(engine), key(fresh));
  assert.equal(engine.domainStats.get('alpha.example:1').completed, 100);
});

test('a domain selects its best rate-weighted exact-mask leader on fair turns too', t => {
  const { engine } = fixture(t);
  const slowLeader = bounty(1, '100000', 0, { domain: 'alpha.example', signature_algorithms_mask: 1 });
  const fastLower = bounty(2, '5000', 0, { domain: 'alpha.example', signature_algorithms_mask: 2 });
  const beta = bounty(3, '8000', 0, { domain: 'beta.example' });
  engine.domainStats.set('alpha.example:1', stat(false, 5, 1000)); // About 0.012 captures/s; still eligible.
  engine.enqueue([slowLeader, fastLower, beta]);
  assert.equal(take(engine), key(fastLower));
  assert.equal(take(engine), key(beta));
});

test('skipped cooling domains neither block a ready domain nor consume an extra turn', t => {
  const { engine } = fixture(t);
  const alpha = bounty(1, '1000', 0, { domain: 'alpha.example' });
  const beta = bounty(2, '10000', 0, { domain: 'beta.example' });
  engine.enqueue([alpha, beta]);
  const waiting = engine.queue.get(key(alpha)); waiting.due = Date.now() + 300000; waiting.failures = 4;
  assert.equal(take(engine), key(beta));
  assert.equal(waiting.failures, 4);
  waiting.due = 0;
  engine.dirty = true; // Internal fixture mutation requires a fresh indexed snapshot.
  assert.equal(take(engine), key(beta), 'after the usable fair turn comes one economic turn');
  assert.equal(take(engine), key(alpha), 'fair cursor resumes from the domain actually assigned');
});

test('random factors remain stable across snapshots, retry cooldown, fee refresh and stop/start', async t => {
  let fee = 0n, draw = 0;
  const bounds = [];
  const { engine } = fixture(t, {
    randomIndex: length => { bounds.push(length); return ++draw; },
    getNetReward: item => BigInt(item.amount) - fee,
  });
  const entries = [bounty(1, '1000'), bounty(2, '2000')];
  engine.enqueue(entries);
  const jobs = entries.map(item => engine.queue.get(key(item)));
  const factors = jobs.map(job => job.factor);
  jobs[0].failures = 3; jobs[0].due = Date.now() + 300000;
  const priorityBefore = jobs[1].priority;
  fee = 500n; engine.enqueue([...entries].reverse()); await engine.stop(); engine.enqueue(entries);
  assert.deepEqual(entries.map(item => engine.queue.get(key(item)).factor), factors);
  assert.ok(engine.queue.get(key(entries[1])).priority < priorityBefore, 'fresh net payout updates economics, not randomness');
  assert.strictEqual(engine.queue.get(key(entries[0])), jobs[0]);
  assert.equal(jobs[0].failures, 3); assert.ok(jobs[0].due > Date.now());
  assert.deepEqual(bounds, [100001, 100001]);
});

test('capacity admission uses the same exact scored order without lottery and remembers rejected factors', t => {
  const draws = [];
  const { engine } = fixture(t, { maxQueue: 2, randomIndex: length => { draws.push(length); return 0; } });
  const entries = [bounty(1, '1000'), bounty(2, '2000'), bounty(3, '3000'), bounty(4, '4000')];
  engine.enqueue(entries);
  assert.deepEqual([...engine.queue.keys()].sort(), [entries[2], entries[3]].map(key).sort());
  const factors = entries.map(item => engine.factors.get(key(item)));
  engine.enqueue([...entries].reverse());
  assert.deepEqual(entries.map(item => engine.factors.get(key(item))), factors);
  assert.deepEqual(draws, [100001, 100001, 100001, 100001]);
});

test('admission protects active and cooling work while replacing only unstarted lower scores', t => {
  const { engine } = fixture(t, { maxQueue: 3 });
  const active = bounty(1, '3000'), cooling = bounty(2, '2000'), low = bounty(3, '1000'), high = bounty(4, '10000');
  engine.enqueue([active, cooling, low]);
  const activeJob = engine.queue.get(key(active)), coolingJob = engine.queue.get(key(cooling));
  engine.activeKey = key(active); engine.controller = new AbortController();
  coolingJob.due = Date.now() + 300000; coolingJob.failures = 3;
  engine.enqueue([high]);
  assert.strictEqual(engine.queue.get(key(active)), activeJob);
  assert.strictEqual(engine.queue.get(key(cooling)), coolingJob);
  assert.equal(engine.queue.has(key(low)), false); assert.equal(engine.queue.has(key(high)), true);
  assert.equal(coolingJob.failures, 3); assert.equal(engine.controller.signal.aborted, false);
});

test('new prepared higher scores leave live work running and win the next same-domain assignment', async t => {
  const gate = deferred(); let activeSignal;
  t.after(() => gate.resolve());
  const { engine, starts, submissions } = fixture(t, {
    generateProof: async (_context, { signal }) => { if (!activeSignal) { activeSignal = signal; await gate.promise; } return '020100'; },
  });
  const active = bounty(1, '5000'), low = bounty(2, '1000'), high = bounty(3, '10000');
  engine.enqueue([active, low]); engine.start(); await until(() => activeSignal);
  engine.proposals.set(key(high), { item: high, context: context(high), payout: high.amount });
  engine.enqueue([high]);
  assert.equal(engine.activeKey, key(active)); assert.equal(activeSignal.aborted, false);
  assert.equal(engine.nextReady(Date.now())[0], key(high));
  gate.resolve(); await until(() => engine.snapshot().completed === 3 && !engine.running);
  assert.deepEqual(starts, [active, low].map(key), 'the new leader reuses its already authenticated proposal');
  assert.deepEqual(submissions, [active, high, low].map(key));
});

test('simultaneous same-domain connections all target the highest ready score', async t => {
  const attempts = [];
  const { engine } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 3 },
    poolFactory: () => ({ pacesStarts: true, async start() {}, async resolve() {}, async close() {},
      async attempt(_context, { bountyId, signal, onStarted }) {
        attempts.push(bountyId); onStarted();
        return new Promise(resolve => signal.addEventListener('abort', () => resolve({
          started: true, captured: false, validationPassed: null, cancelled: true, seconds: 0, proof: null, verified: false,
        }), { once: true }));
      },
    }),
  });
  const best = bounty(1, '10000'), lower = bounty(2, '1000');
  engine.enqueue([lower, best]); engine.start();
  await until(() => attempts.length === 3);
  assert.deepEqual(attempts, Array(3).fill(key(best)));
  assert.equal(engine.connections.size, 3);
  await engine.stop();
});

test('invalid metadata and nonpositive net rewards cannot acquire a scheduling position', t => {
  const { engine } = fixture(t, { getNetReward: item => BigInt(item.amount) - 300n });
  const invalidAmounts = [undefined, null, false, 0, 100, 1n, [], {}, '', '-1', '+1', '1.0', '1e3', ' 1', '1 ', '1\n', '1\r', '1\u2028', '١', '０', '0'.repeat(20), '1000000000000000001'];
  const invalid = invalidAmounts.map((amount, index) => bounty(index + 1, '1000', 0, { amount }));
  invalid.push(...[
    { connection_work_target: undefined }, { connection_work_target: 'f'.repeat(63) },
    { connection_work_target: 'x'.repeat(64) }, { signature_algorithms_mask: 0 },
    { signature_algorithms_mask: 8 }, { signature_algorithms_mask: 1.5 },
  ].map((extra, index) => bounty(index + 100, '1000', 0, extra)));
  invalid.push(bounty(200, '299'), bounty(201, '300'));
  engine.enqueue(invalid);
  assert.equal(engine.nextReady(Date.now()), undefined);
});

test('drawing local factors never enables Automatic Claims or restarts a stopped engine', async t => {
  const { engine, starts, draws } = fixture(t);
  engine.enqueue([bounty(1), bounty(2)]); await tick();
  assert.equal(engine.enabled, false); assert.deepEqual(starts, []);
  assert.deepEqual(draws, [100001, 100001]);
  engine.start(); await until(() => engine.snapshot().completed === 2 && !engine.running);
  await engine.stop(); engine.enqueue([bounty(3)]); await tick();
  assert.equal(engine.enabled, false); assert.equal(starts.length, 2);
});

test('injected factor draws must be bounded integer indexes', t => {
  for (const invalid of [-1, 100001, 1.5, NaN, Infinity, '1']) {
    const { engine } = fixture(t, { randomIndex: () => invalid });
    assert.throws(() => engine.enqueue([bounty(1)]), /random|factor|index/i);
  }
});

test('an authenticated fixed payout below the raw floor never reaches TLS or consumes a scheduling turn', async t => {
  let prepares = 0, proofs = 0;
  const { engine } = fixture(t, { randomIndex: length => length - 1,
    prepare: async item => { prepares++; return { item, context: context(item), payout: '199' }; },
    generateProof: async () => { proofs++; throw new Error('Must not start below the raw floor'); },
  });
  const item = bounty(1, '1000'); engine.enqueue([item]); engine.start();
  await until(() => prepares === 1 && !engine.running);
  await tick();
  assert.equal(proofs, 0); assert.equal(prepares, 1);
  assert.equal(engine.preferReward, false);
  assert.equal(engine.scheduler.domainAfter, null);
  assert.equal(engine.timer, null, 'an ineligible zero-due job cannot create a busy polling loop');
});

test('a retry keeps the prepared payout and per-bounty factor despite a changed fee estimate', async t => {
  let fee = 0n, prepares = 0, attempts = 0;
  const { engine, draws } = fixture(t, {
    getNetReward: item => BigInt(item.amount) - fee,
    prepare: async item => { prepares++; return { item, context: context(item), payout: '700' }; },
    poolFactory: () => ({ async start() {}, async resolve() {}, async close() {},
      async attempt(_context, { signal, onStarted, onCapture }) {
        attempts++; onStarted();
        if (attempts === 1) {
          const result = { started: true, captured: true, validationPassed: true, cancelled: false, seconds: 0.1, proof: null, verified: false };
          onCapture(result); return result;
        }
        return new Promise(resolve => signal.addEventListener('abort', () => resolve({ started: true, captured: false, validationPassed: null, cancelled: true, seconds: 0, proof: null, verified: false }), { once: true }));
      },
    }),
  });
  const item = bounty(1, '1000'); engine.enqueue([item]); engine.start();
  await until(() => attempts === 2);
  const job = engine.queue.get(key(item)), prepared = job.prepared, firstPriority = job.priority;
  fee = 999n; engine.enqueue([item]);
  assert.equal(job.priority, firstPriority, 'prepared payout wins over a new discovery fee estimate');
  assert.equal(prepares, 1, 'each connection reuses the authenticated public proposal');
  assert.strictEqual(engine.proposals.get(key(item)), prepared);
  assert.deepEqual(draws, [100001]);
});

test('an unprotected old bounty below the raw floor cannot occupy capacity using its random boost', t => {
  let draw = 0;
  const { engine } = fixture(t, { maxQueue: 1, randomIndex: () => draw++ === 0 ? 100000 : 0 });
  const old = bounty(1, '200', 0, { domain: 'alpha.example' });
  const fresh = bounty(2, '200', 0, { domain: 'beta.example' });
  engine.enqueue([old]);
  engine.domainStats.set('alpha.example:7', stat(false, 0.1));
  assert.equal(engine.enqueue([fresh]), 1);
  assert.equal(engine.queue.has(key(old)), false);
  assert.equal(engine.queue.has(key(fresh)), true);
});

test('verified funding policy replaces discovery policy before TLS and is reselected without a failed attempt', async t => {
  const preparedDomains = [], proofDomains = [];
  const initial = bounty(1, '10000', 0, { domain: 'alpha.example' });
  const other = bounty(2, '5000', 0, { domain: 'beta.example' });
  const { engine, draws } = fixture(t, {
    prepare: async item => {
      preparedDomains.push(item.domain);
      if (item.txid === initial.txid) {
        const actual = { ...item, domain: 'zeta.example', amount: '9999',
          connection_work_target: hash((1n << 255n) - 1n), signature_algorithms_mask: 1 };
        return { item: actual, bounty: actual, payout: '9000', context: context(actual) };
      }
      return { item, bounty: item, payout: item.amount, context: context(item) };
    },
    generateProof: async (verified, { onProgress }) => {
      proofDomains.push(verified.domain);
      onProgress({ attempts: 1, elapsed: 0.1, attemptStats: { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 0.1]] } });
      return '020100';
    },
  });
  engine.enqueue([initial, other]); engine.start();
  await until(() => engine.snapshot().completed === 2 && !engine.running);
  assert.deepEqual(preparedDomains, ['alpha.example', 'beta.example']);
  assert.deepEqual(proofDomains, ['beta.example', 'zeta.example']);
  assert.equal(engine.domainStats.has('alpha.example:7'), false);
  assert.equal(engine.domainStats.get('zeta.example:1').completed, 1);
  assert.equal(engine.snapshot().lastError, null);
  assert.deepEqual(draws, [100001, 100001]);
});

test('authenticated harder target cannot start TLS based on easier untrusted discovery economics', async t => {
  let proofs = 0, prepares = 0;
  const { engine } = fixture(t, {
    prepare: async item => {
      prepares++;
      const actual = { ...item, connection_work_target: hash((1n << 192n) - 1n) };
      return { item: actual, bounty: actual, payout: item.amount, context: context(actual) };
    },
    generateProof: async () => { proofs++; return '020100'; },
  });
  const entry = bounty(1); engine.enqueue([entry]); engine.start();
  await until(() => prepares === 1 && !engine.running);
  assert.equal(proofs, 0);
  assert.equal(engine.queue.get(key(entry)).bounty.connection_work_target, hash((1n << 192n) - 1n));
  assert.equal(engine.preferReward, false);
});

for (const wrong of [{ txid: hash(9) }, { vout: 1 }]) test(`a prepared outpoint mismatch ${Object.keys(wrong)[0]} cannot consume or submit the queued bounty`, async t => {
  let proofs = 0;
  const { engine, submissions } = fixture(t, {
    prepare: async item => ({ item, bounty: { ...item, ...wrong }, payout: item.amount, context: context(item) }),
    generateProof: async () => { proofs++; return '020100'; },
  });
  const entry = bounty(1); engine.enqueue([entry]); engine.start();
  await until(() => Boolean(engine.snapshot().lastError) && !engine.running);
  assert.equal(proofs, 0); assert.deepEqual(submissions, []);
  assert.equal(engine.queue.has(key(entry)), true);
});

test('DNS resolution failure before TCP does not consume a fair or economic turn', async t => {
  const { engine } = fixture(t, {
    poolFactory: () => ({ async start() {}, async close() {},
      async resolve() { throw new Error('Controlled DNS failure without TCP/TLS effort'); },
      async attempt() { throw new Error('DNS failure must not reach a TCP attempt'); },
    }),
  });
  engine.enqueue([bounty(1)]); engine.start();
  await until(() => engine.dns.get('example.com')?.ok === false && !engine.running);
  assert.equal(engine.preferReward, false);
  assert.equal(engine.scheduler.domainAfter, null);
});

test('a real failed TLS capture consumes exactly one turn at its TCP start', async t => {
  const { engine } = fixture(t, {
    poolFactory: () => ({ async start() {}, async resolve() {}, async close() {},
      async attempt(_context, { onStarted, onCapture }) {
        onStarted(); const result = { started: true, captured: false, validationPassed: false, cancelled: false, seconds: 0.1, proof: null, verified: false };
        onCapture(result); return result;
      },
    }),
  });
  let assignments = 0;
  const mark = engine.scheduler.commit.bind(engine.scheduler);
  engine.scheduler.commit = selection => { assignments++; return mark(selection); };
  engine.enqueue([bounty(1)]); engine.start();
  await until(() => engine.domainStats.get('example.com:7')?.completed === 1);
  await engine.stop();
  assert.equal(assignments, 1); assert.equal(engine.preferReward, true);
  assert.equal(engine.scheduler.domainAfter, 'example.com');
  assert.equal(engine.domainStats.get('example.com:7').completed, 1);
  assert.equal(engine.domainStats.get('example.com:7').connectionRate(), (0.999 * 0.1) / (0.999 * 0.02 + 0.001 * 0.1));
});

test('a verified proof from an injected runner without progress still consumes exactly one turn', async t => {
  const { engine } = fixture(t);
  let assignments = 0;
  const mark = engine.scheduler.commit.bind(engine.scheduler);
  engine.scheduler.commit = selection => { assignments++; return mark(selection); };
  engine.enqueue([bounty(1)]); engine.start();
  await until(() => engine.snapshot().completed === 1 && !engine.running);
  assert.equal(assignments, 1); assert.equal(engine.preferReward, true);
  assert.equal(engine.scheduler.domainAfter, 'example.com');
});
