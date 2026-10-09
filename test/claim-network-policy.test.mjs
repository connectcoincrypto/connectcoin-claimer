import test from 'node:test';
import assert from 'node:assert/strict';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { ClaimConnectionPolicy, MAX_RECOVERY_POLICIES } from '../src/core/claim-connection-policy.mjs';
import { P2CDomainStats } from '../src/core/claim-priority.mjs';

const hash = id => id.toString(16).padStart(64, '0');
const row = (id, domain = 'alpha.example', extra = {}) => ({ txid: hash(id), vout: 0, domain,
  amount: '1000000000', status: 'available', connection_work_target: `00${'f'.repeat(62)}`,
  signature_algorithms_mask: 7, root_certificates_version: 1, ...extra });
const key = bounty => `${bounty.txid}:${bounty.vout}`;
const context = bounty => ({ domain: bounty.domain, txid: hash(Number(BigInt(`0x${bounty.txid}`)) + 1000), input_index: 0,
  connection_work_target: bounty.connection_work_target, signature_algorithms_mask: bounty.signature_algorithms_mask,
  root_certificates_version: 1, validation_time: 1800000000 });
async function settle() { for (let i = 0; i < 30; i++) await new Promise(resolve => setImmediate(resolve)); }

function fixture(t, options = {}) {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout', 'setInterval'], now: 1800000000000 });
  const attempts = [];
  const pool = { pacesStarts: true, async start() {}, async close() {}, async resolve() {},
    attempt(ctx, callbacks) {
      return new Promise(resolve => {
        const attempt = { ctx, callbacks, settled: false };
        attempt.finish = (changes = {}) => {
          if (attempt.settled) return;
          attempt.settled = true; callbacks.signal.removeEventListener('abort', abort);
          const result = { started: true, captured: false, validationPassed: false, cancelled: false, seconds: 10,
            proof: null, verified: false, ...changes };
          callbacks.onCapture(result);
          callbacks.onResult(result); resolve(result);
        };
        const abort = () => attempt.finish({ cancelled: true, validationPassed: null });
        callbacks.signal.addEventListener('abort', abort, { once: true });
        attempts.push(attempt); callbacks.onStarted();
      });
    },
  };
  const engine = new ClaimsEngine({ isUnlocked: () => true, randomIndex: () => 0,
    prepare: async bounty => ({ bounty, context: context(bounty), payout: bounty.amount }), submit: async () => hash(999),
    poolFactory: () => pool, options: { connectionsPerSecond: 100, concurrency: 100 }, ...options });
  t.after(() => engine.stop());
  return { engine, attempts };
}

test('configured global capacity is shared across domains without a separate domain cap', async t => {
  const { engine, attempts } = fixture(t);
  const bounties = Array.from({ length: 14 }, (_, i) => row(i + 1, `d${String(i).padStart(2, '0')}.example`));
  engine.enqueue(bounties);
  // All domains are ready so preparation and DNS slot limits do not affect
  // this check of connection assignment and the global capacity limit.
  for (const bounty of bounties) {
    engine.queue.get(key(bounty)).prepared = { context: context(bounty), payout: bounty.amount };
    engine.dns.set(bounty.domain, { ok: true, expires: Date.now() + 60000 });
  }
  engine.start(); await settle();
  assert.equal(attempts.length, 100); assert.equal(engine.connections.size, 100);
  const counts = new Map();
  for (const attempt of attempts) counts.set(attempt.ctx.domain, (counts.get(attempt.ctx.domain) ?? 0) + 1);
  assert.equal(counts.size, 14); assert.ok([...counts.values()].some(count => count > 8));
  assert.deepEqual(engine.options, { connectionsPerSecond: 100, concurrency: 100 });
});

for (const concurrency of [3, 100, 256]) test(`one domain can use all ${concurrency} configured global connection slots`, async t => {
  const { engine, attempts } = fixture(t, { options: { connectionsPerSecond: 100, concurrency } });
  engine.enqueue([row(1)]); engine.start(); await settle();
  assert.equal(attempts.length, concurrency); assert.equal(engine.connections.size, concurrency);
  assert.ok(attempts.every(attempt => attempt.ctx.domain === 'alpha.example'));
  await settle(); assert.equal(attempts.length, concurrency, 'the global limit still bounds pending connections');
});

test('repeated TCP failures replenish all global slots without introducing a domain cooldown', async t => {
  const { engine, attempts } = fixture(t);
  engine.enqueue([row(1)]); engine.start(); await settle();
  for (let batch = 0; batch < 3; batch++) {
    assert.equal(attempts.length, (batch + 1) * 100);
    for (const attempt of attempts.slice(batch * 100)) attempt.finish({ message: 'TLS connection timed out' });
    await settle();
    t.mock.timers.tick(999); await settle();
    assert.equal(attempts.length, (batch + 1) * 100, 'the original one-second worker pause is preserved');
    t.mock.timers.tick(1); await settle();
    assert.equal(attempts.length, (batch + 2) * 100, 'no new per-domain delay or one-connection recovery gate is applied');
    assert.equal(engine.connections.size, 100);
  }
  assert.equal(engine.connectionPolicy.probes.size, 0, 'still-profitable domains do not enter recovery probing');
});

function failedStats() { const stats = new P2CDomainStats(); for (let i = 0; i < 10; i++) stats.record(false, 10); return stats; }

test('below-floor domain gets at most one recovery TCP start per minute without resetting EMA', async t => {
  const { engine, attempts } = fixture(t);
  const stats = failedStats(); engine.domainStats.set('alpha.example:7', stats);
  const bounties = Array.from({ length: 20 }, (_, i) => row(i + 1, 'alpha.example', { amount: '1000', connection_work_target: 'f'.repeat(64) }));
  engine.enqueue(bounties); engine.start(); await settle();
  assert.equal(engine.queue.size, 1); assert.equal(attempts.length, 0);
  t.mock.timers.tick(59999); await settle(); assert.equal(attempts.length, 0);
  t.mock.timers.tick(1); await settle(); assert.equal(attempts.length, 1);
  assert.equal(engine.domainStats.get('alpha.example:7'), stats); assert.equal(stats.completed, 10);
  attempts[0].finish({ message: 'TLS connection timed out' }); await settle();
  const nextDue = engine.connectionPolicy.probes.get('alpha.example:7');
  await engine.suspend(); engine.clear({ preserveSelection: true }); engine.enqueue(bounties); engine.retainCatalog(bounties); engine.resume();
  t.mock.timers.tick(59999); await settle(); assert.equal(attempts.length, 1);
  assert.equal(engine.connectionPolicy.probes.get('alpha.example:7'), nextDue);
  t.mock.timers.tick(1); await settle(); assert.equal(attempts.length, 2);
  assert.equal(stats.completed, 11);
});

test('recovery never admits intrinsically below-floor candidates and admission remains bounded', async t => {
  const { engine } = fixture(t, { maxQueue: 10 });
  for (let i = 0; i < 20; i++) engine.domainStats.set(`d${i}.example:7`, failedStats());
  const unhealthy = Array.from({ length: 20 }, (_, i) => row(i + 1, `d${i}.example`, { amount: '1000', connection_work_target: 'f'.repeat(64) }));
  const cheap = row(100, 'cheap.example', { amount: '199', connection_work_target: 'f'.repeat(64) });
  const normal = Array.from({ length: 20 }, (_, i) => row(i + 200, 'healthy.example'));
  engine.enqueue([...unhealthy, cheap, ...normal]); engine.rebuild();
  assert.equal(engine.queue.size, 10); assert.equal(engine.queue.has(key(cheap)), false);
  assert.equal([...engine.queue.values()].filter(job => job.recoveryProbe).length, 1);
  const policy = new ClaimConnectionPolicy();
  for (let i = 0; i < MAX_RECOVERY_POLICIES + 50; i++) policy.probeStarted(`p${i}:7`, 0);
  assert.equal(policy.probes.size, MAX_RECOVERY_POLICIES);
  assert.equal(policy.probeDue('p0:7', 10000), 70000, 'evicted policies wait before probing again');
});

test('full reset clears recovery history after connections drain', async t => {
  const { engine, attempts } = fixture(t, { options: { connectionsPerSecond: 100, concurrency: 3 } });
  engine.enqueue([row(1)]); engine.start(); await settle();
  for (const attempt of attempts) attempt.finish({ message: 'TLS connection timed out' }); await settle();
  engine.connectionPolicy.probeStarted('alpha.example:7');
  await engine.stop(); engine.clear();
  assert.equal(engine.connectionPolicy.probes.size, 0);
});

test('recovery admission never displaces verified pending proofs during catalog resync', async t => {
  const { engine } = fixture(t, { maxQueue: 2 });
  const winners = [row(1, 'winner.example'), row(2, 'winner.example')];
  for (const bounty of winners) engine.pendingProofs.set(key(bounty), { proof: '020100', context: context(bounty), due: 0, failures: 0 });
  engine.domainStats.set('alpha.example:7', failedStats());
  engine.enqueue([...winners, row(3, 'alpha.example', { amount: '1000', connection_work_target: 'f'.repeat(64) })]);
  assert.equal(engine.queue.size, 2);
  for (const bounty of winners) assert.equal(engine.queue.get(key(bounty)).winner, true);
});

test('a normally eligible bounty supplies observations without an extra probe of the same domain/mask', async t => {
  const { engine } = fixture(t);
  engine.domainStats.set('alpha.example:7', failedStats());
  engine.enqueue([row(1, 'alpha.example', { amount: '1000', connection_work_target: 'f'.repeat(64) }), row(2)]);
  engine.rebuild();
  assert.equal(engine.queue.size, 1); assert.equal(engine.connectionPolicy.probes.size, 0);
  assert.equal(engine.queue.get(key(row(2))).recoveryProbe, false);
});

test('replacing the probe bounty before its TCP acknowledgement cannot spend a second probe in that minute', async t => {
  const requests = [];
  const pool = { pacesStarts: true, async start() {}, async close() {}, async resolve() {},
    attempt(ctx, callbacks) {
      return new Promise(resolve => {
        const request = { ctx, callbacks, started: false };
        request.start = () => { request.started = true; callbacks.onStarted(); };
        callbacks.signal.addEventListener('abort', () => {
          const result = { started: request.started, captured: false, cancelled: true, validationPassed: null, seconds: 0, proof: null, verified: false };
          if (request.started) callbacks.onCapture(result);
          callbacks.onResult(result); resolve(result);
        }, { once: true });
        requests.push(request);
      });
    } };
  const { engine } = fixture(t, { poolFactory: () => pool });
  engine.domainStats.set('alpha.example:7', failedStats());
  const first = row(1, 'alpha.example', { amount: '1000', connection_work_target: 'f'.repeat(64) });
  const replacement = row(2, 'alpha.example', { amount: '1100', connection_work_target: 'f'.repeat(64) });
  engine.enqueue([first]); engine.start(); await settle();
  t.mock.timers.tick(60000); await settle(); assert.equal(requests.length, 1);
  engine.enqueue([replacement]); engine.rebuild();
  assert.equal(engine.queue.get(key(first)).recoveryProbe, false);
  assert.equal(engine.queue.get(key(replacement)).recoveryProbe, true);
  requests[0].start(); await settle();
  assert.equal(engine.state.attempts, 1); assert.equal(requests.length, 1);
  t.mock.timers.tick(59999); await settle(); assert.equal(requests.length, 1);
  t.mock.timers.tick(1); await settle(); assert.equal(requests.length, 2);
  assert.equal(requests[1].ctx.txid, context(replacement).txid);
});
