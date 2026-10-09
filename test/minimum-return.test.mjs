import assert from 'node:assert/strict';
import test from 'node:test';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { ClaimScheduler } from '../src/core/claim-scheduler.mjs';
import { claimPriority, selectionPriority, isWorthAttempting, validateMinExpectedReturn,
  MIN_EXPECTED_RETURN, PRIORITY_FACTOR_SCALE, P2CDomainStats } from '../src/core/claim-priority.mjs';

const hash = value => value.toString(16).padStart(64, '0');
const row = (amount, id = Number(amount)) => ({
  txid: hash(id), vout: 0, amount: String(amount), domain: 'example.com', status: 'available',
  connection_work_target: 'ff'.repeat(32), signature_algorithms_mask: 7, root_certificates_version: 1,
});
const key = bounty => `${bounty.txid}:${bounty.vout}`;
const context = bounty => ({
  domain: bounty.domain, txid: hash(999), input_index: 0, connection_work_target: bounty.connection_work_target,
  signature_algorithms_mask: 7, root_certificates_version: 1, validation_time: 1800000000,
});
const createEngine = options => new ClaimsEngine({
  isUnlocked: () => true, randomIndex: () => 0,
  prepare: async bounty => ({ bounty, payout: bounty.amount, context: context(bounty) }),
  submit: async () => hash(999), generateProof: async () => '020100',
  options: { concurrency: 1, connectionsPerSecond: 100 }, ...options,
});
const job = amount => {
  const bounty = row(amount), rawPriority = claimPriority(bounty.connection_work_target, BigInt(amount));
  return { bounty, rawPriority, priority: selectionPriority(rawPriority, PRIORITY_FACTOR_SCALE), due: 0 };
};
async function settle() { for (let i = 0; i < 40; i++) await new Promise(resolve => setImmediate(resolve)); }

test('default return floor remains the inclusive desktop value of 1000 connects per second', () => {
  assert.equal(MIN_EXPECTED_RETURN, 1000);
  assert.equal(validateMinExpectedReturn(), 1000);
  assert.equal(isWorthAttempting(claimPriority('ff'.repeat(32), 199n), 5), false);
  assert.equal(isWorthAttempting(claimPriority('ff'.repeat(32), 200n), 5), true);
  const engine = createEngine();
  assert.equal(engine.minExpectedReturn, 1000);
  assert.equal(engine.scheduler.minExpectedReturn, 1000);
  assert.equal(engine.enqueue([row(199), row(200)]), 1);
  assert.equal(engine.nextReady()[0], key(row(200)));
});

test('zero disables the economic floor while requiring positive reward and valid rates', () => {
  assert.equal(isWorthAttempting(claimPriority('ff'.repeat(32), 1n), 0.0001, 0), true);
  assert.equal(isWorthAttempting(0n, 5, 0), false);
  for (const rate of [0, -1, NaN, Infinity]) assert.equal(isWorthAttempting(1n, rate, 0), false);
  const engine = createEngine({ minExpectedReturn: 0 });
  assert.equal(engine.enqueue([row(1)]), 1);
  assert.equal(engine.nextReady()[0], key(row(1)));
  assert.equal(engine.queue.get(key(row(1))).recoveryProbe, false);
});

test('fractional and maximum finite thresholds are supported and invalid values fail at construction', () => {
  for (const threshold of [0, 0.25, 1000, Number.MAX_SAFE_INTEGER]) {
    assert.equal(validateMinExpectedReturn(threshold), threshold);
    assert.equal(createEngine({ minExpectedReturn: threshold }).minExpectedReturn, threshold);
    assert.equal(new ClaimScheduler({ minExpectedReturn: threshold }).minExpectedReturn, threshold);
  }
  for (const threshold of [null, '1000', true, {}, NaN, Infinity, -Infinity, -1, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => validateMinExpectedReturn(threshold), /Minimum expected return/);
    assert.throws(() => createEngine({ minExpectedReturn: threshold }), /Minimum expected return/);
    assert.throws(() => new ClaimScheduler({ minExpectedReturn: threshold }), /Minimum expected return/);
    assert.throws(() => isWorthAttempting(1n, 5, threshold), /Minimum expected return/);
  }
  assert.equal(isWorthAttempting(claimPriority('ff'.repeat(32), 1n), 0.25, 0.25), true);
  assert.equal(isWorthAttempting(claimPriority('ff'.repeat(32), 1n), 0.25, 0.251), false);
});

test('scheduler thresholds are independent per instance and rebuild after rate changes', () => {
  let rate = 5;
  const zero = new ClaimScheduler({ minExpectedReturn: 0, connectionRate: () => rate });
  const normal = new ClaimScheduler({ connectionRate: () => rate });
  const custom = new ClaimScheduler({ minExpectedReturn: 2000, connectionRate: () => rate });
  const jobs = [job(1), job(200), job(400)];
  for (const scheduler of [zero, normal, custom]) scheduler.rebuild(jobs);
  assert.equal(zero.entries.size, 3);
  assert.equal(normal.entries.size, 2);
  assert.equal(custom.entries.size, 1);
  rate = 2.5;
  for (const scheduler of [zero, normal, custom]) scheduler.rebuild(jobs);
  assert.equal(zero.entries.size, 3);
  assert.equal(normal.entries.size, 1);
  assert.equal(custom.entries.size, 0);
  assert.equal(normal.next()[0], key(row(400)));
  assert.equal(custom.next(), undefined);
});

for (const [threshold, amount] of [[0, 1], [600, 150], [1000, 200], [3000, 600]]) {
  test(`engine dispatch, proof and submit preserve configured threshold ${threshold}`, async t => {
    const engine = createEngine({ minExpectedReturn: threshold });
    t.after(() => engine.stop());
    assert.equal(engine.enqueue([row(amount)]), 1);
    engine.start(); await settle();
    assert.equal(engine.state.completed, 1);
    assert.equal(engine.state.attempts, 1);
    assert.equal(engine.pendingProofs.size, 0);
    assert.equal(engine.state.lastError, null);
  });
}

test('EMA decline uses custom recovery threshold for admission and scheduler rebuild', () => {
  const stats = new P2CDomainStats();
  const custom = createEngine({ minExpectedReturn: 600 });
  const normal = createEngine();
  const zero = createEngine({ minExpectedReturn: 0 });
  for (const engine of [custom, normal, zero]) engine.domainStats.set('example.com:7', stats);
  assert.equal(custom.enqueue([row(150)]), 1);
  assert.equal(normal.enqueue([row(150)]), 0);
  assert.equal(zero.enqueue([row(150)]), 1);
  custom.rebuild(); zero.rebuild();
  assert.equal(custom.queue.get(key(row(150))).recoveryProbe, false);
  stats.record(false, 30);
  assert.ok(stats.connectionRate() < 4);
  custom.rebuild(); zero.rebuild();
  const selected = custom.queue.get(key(row(150)));
  assert.equal(selected.recoveryProbe, true);
  assert.equal(custom.recoveryJobs.size, 1);
  assert.equal(custom.scheduler.entries.has(key(row(150))), true);
  assert.equal(zero.queue.get(key(row(150))).recoveryProbe, false);
  assert.equal(zero.recoveryJobs.size, 0);
  const fresh = createEngine({ minExpectedReturn: 600 });
  fresh.domainStats.set('example.com:7', stats);
  assert.equal(fresh.enqueue([row(150)]), 1, 'recovery admission applies the custom prior threshold');
  assert.equal(normal.enqueue([row(150)]), 0, 'instances retain independent return floors');
  for (let i = 0; i < 100; i++) stats.record(true, 0.01);
  assert.ok(stats.connectionRate() > 4);
  custom.rebuild();
  assert.equal(selected.recoveryProbe, false);
  assert.equal(custom.recoveryJobs.size, 0);
  assert.equal(custom.nextReady()[0], key(row(150)));
});

test('below custom prior remains excluded when candidates and recovery policies are rebuilt', () => {
  const custom = createEngine({ minExpectedReturn: 2000 });
  assert.equal(custom.enqueue([row(300), row(400)]), 1);
  const stats = new P2CDomainStats(); stats.record(false, 30);
  custom.domainStats.set('example.com:7', stats);
  custom.rebuild();
  assert.equal(custom.queue.has(key(row(300))), false);
  assert.equal(custom.queue.get(key(row(400))).recoveryProbe, true);
  assert.equal(custom.enqueue([row(301), row(401)]), 1);
  custom.rebuild();
  assert.equal([...custom.queue.values()].some(item => BigInt(item.bounty.amount) < 400n), false);
  assert.equal(custom.recoveryJobs.size, 1);
});

test('custom recovery dispatch succeeds after its one-minute probe gate', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: 1800000000000 });
  const engine = createEngine({ minExpectedReturn: 600 });
  t.after(() => engine.stop());
  const stats = new P2CDomainStats(); stats.record(false, 30);
  engine.domainStats.set('example.com:7', stats);
  engine.enqueue([row(150)]); engine.start(); await settle();
  assert.equal(engine.state.attempts, 0);
  t.mock.timers.tick(60000); await settle();
  assert.equal(engine.state.completed, 1);
  assert.equal(engine.state.attempts, 1);
});
