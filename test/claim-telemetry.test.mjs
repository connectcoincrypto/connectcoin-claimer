import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { ClaimsEngine, createProofRunner } from '../src/core/claims.mjs';
import { ConnectionPool } from '../src/core/claim-pool.mjs';
import { validateAttemptStats } from '../src/core/claim-priority.mjs';

const context = { domain: 'example.com', txid: '01'.repeat(32), input_index: 0,
  connection_work_target: 'ff'.repeat(32), root_certificates_version: 1,
  signature_algorithms_mask: 7, validation_time: 1800000000 };
const bounty = (vout = 0, extra = {}) => ({ txid: '02'.repeat(32), vout, amount: '1000000000',
  domain: 'example.com', status: 'available', connection_work_target: 'ff'.repeat(32),
  root_certificates_version: 1, signature_algorithms_mask: 7, ...extra });
const progress = (completed, recent, extra = {}) => ({ type: 'progress', attempts: completed,
  elapsed: 1, attemptStats: { validation: 'certificate-proof-v1', completed, recent }, ...extra });
// Closed-form weighted sum, independent of the production accumulator updates.
function expectedRate(samples) {
  const priorWeight = 0.999 ** samples.length;
  let success = 0.1 * priorWeight, seconds = 0.02 * priorWeight;
  for (let index = 0; index < samples.length; index++) {
    const weight = 0.001 * 0.999 ** (samples.length - index - 1);
    success += Number(samples[index][0]) * weight;
    seconds += samples[index][1] * weight;
  }
  return success / seconds;
}
function assertRate(stats, samples) {
  const expected = expectedRate(samples);
  assert.ok(Math.abs(stats.connectionRate() - expected) <= Math.max(1, expected) * 1e-12,
    `expected rate ${expected}, received ${stats.connectionRate()}`);
}
function runner(messages, resultExtra = {}) {
  const spawnProcess = () => {
    const child = new EventEmitter();
    child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.killed = false;
    child.kill = () => { child.killed = true; setImmediate(() => child.emit('close', null)); return true; };
    child.stdin.on('finish', () => {
      for (const message of messages) {
        if (child.killed) break;
        child.stdout.write(JSON.stringify(message) + '\n');
      }
      if (!child.killed) {
        child.stdout.write(JSON.stringify({ type: 'result', context, proof: '020100', verified: true, attempts: messages.at(-1)?.attempts ?? 0, ...resultExtra }) + '\n');
        setImmediate(() => child.emit('close', 0));
      }
    });
    return child;
  };
  return createProofRunner({ helper: { command: 'isolated-mock-helper' }, spawnProcess });
}
function engineFixture(t) {
  const engine = new ClaimsEngine({ isUnlocked: () => true, randomIndex: () => 0,
    prepare: async () => ({ context }), submit: async () => context.txid, generateProof: async () => '020100' });
  t.after(() => engine.stop());
  engine.enqueue([bounty(), bounty(1, { signature_algorithms_mask: 1 })]);
  return engine;
}
function persistentPoolFixture(t) {
  let child;
  const commands = [];
  const pool = new ConnectionPool({ helper: { command: 'isolated-protocol4-helper' }, spawnProcess: () => {
    child = new EventEmitter();
    child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.killed = false;
    child.kill = () => { child.killed = true; setImmediate(() => child.emit('close', null)); return true; };
    child.stdin.on('data', data => {
      const command = JSON.parse(data.toString());
      if (command.type === 'start') queueMicrotask(() => child.stdout.write(JSON.stringify({
        type: 'ready', protocol: 4, roots: 1, security: { rsaPublicExponentMaxBits: 64 },
      }) + '\n'));
      else if (command.type === 'shutdown') setImmediate(() => child.emit('close', 0));
      else commands.push(command);
    });
    return child;
  } });
  t.after(() => pool.close());
  return { pool, commands, write: frames => child.stdout.write(frames.map(frame => JSON.stringify(frame)).join('\n') + '\n') };
}

test('TLS helper forwards valid cumulative completion snapshots, including zero duration and duplicate snapshots', async () => {
  const messages = [
    progress(0, []), progress(1, [[true, 0]]), progress(1, [[true, 0]]),
    progress(2, [[true, 0], [false, 3600]]),
  ];
  const observed = [];
  assert.equal(await runner(messages)(context, { onProgress: value => observed.push(value) }), '020100');
  assert.deepEqual(observed.map(value => value.attemptStats), messages.map(value => value.attemptStats));
});

test('legacy proof generation accepts high-rate bounded progress without importing incomplete EMA history', async () => {
  const messages = [progress(1, [[true, 0.1]]), progress(150, Array(100).fill([false, 0.1]))];
  const observed = [];
  assert.equal(await runner(messages)(context, { onProgress: value => observed.push(value) }), '020100');
  assert.deepEqual(observed.map(value => value.attemptStats), messages.map(value => value.attemptStats));
});

test('statistics validator rejects malformed or oversized completion records', () => {
  const invalid = [
    null, false, [], {}, { validation: 'certificate-proof-v1', completed: -1, recent: [] }, { validation: 'certificate-proof-v1', completed: 1.5, recent: [] },
    { validation: 'certificate-proof-v1', completed: NaN, recent: [] }, { validation: 'certificate-proof-v1', completed: Infinity, recent: [] },
    { validation: 'certificate-proof-v1', completed: 1001, recent: Array(100).fill([false, 0]) },
    { validation: 'certificate-proof-v1', completed: 0, recent: [[true, 0]] }, { validation: 'certificate-proof-v1', completed: 1, recent: [] },
    { validation: 'certificate-proof-v1', completed: 2, recent: [[true, 1]] }, { validation: 'certificate-proof-v1', completed: 1, recent: [null] },
    { validation: 'certificate-proof-v1', completed: 1, recent: [[true]] }, { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 1, 2]] },
    { validation: 'certificate-proof-v1', completed: 1, recent: [[1, 0]] }, { validation: 'certificate-proof-v1', completed: 1, recent: [['true', 0]] },
    { validation: 'certificate-proof-v1', completed: 1, recent: [[true, -1]] }, { validation: 'certificate-proof-v1', completed: 1, recent: [[true, Infinity]] },
    { validation: 'certificate-proof-v1', completed: 1, recent: [[true, NaN]] }, { validation: 'certificate-proof-v1', completed: 1, recent: [[true, '1']] },
    { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 3600.000001]] },
    { validation: 'certificate-proof-v1', completed: 101, recent: Array(101).fill([true, 0]) },
  ];
  for (const value of invalid) assert.throws(() => validateAttemptStats(value, 1000), /statistics/);
});

for (const [name, messages] of [
  ['mismatched total', [progress(1, [[true, 0.1]], { attempts: 2 })]],
  ['decreasing completed count', [progress(2, [[true, 0.1], [false, 0.2]]), progress(1, [[true, 0.1]])]],
  ['wrong history length', [progress(2, [[true, 0.1]])]],
  ['non-boolean capture outcome', [progress(1, [[1, 0.1]])]],
  ['negative capture time', [progress(1, [[true, -0.1]])]],
  ['over-budget capture time', [progress(1, [[true, 3601]])]],
  ['count outside configured attempt budget', [progress(1001, Array(100).fill([true, 0]))]],
]) test(`TLS helper rejects hostile ${name} instead of using it to rank domains`, async () => {
  await assert.rejects(runner(messages)(context), /attempt|statistics|sequence|progress/);
});

test('duplicate cumulative snapshots count each completed connection once and never combine exact masks', t => {
  const engine = engineFixture(t);
  const job = engine.queue.get(bounty().txid + ':0');
  let completed = engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 2, recent: [[true, 0.1], [false, 0.2]] }, 0);
  completed = engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 2, recent: [[true, 0.1], [false, 0.2]] }, completed);
  completed = engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 3, recent: [[true, 0.1], [false, 0.2], [true, 0.3]] }, completed);
  assert.equal(completed, 3);
  const stats = engine.domainStats.get('example.com:7');
  const samples = [[true, 0.1], [false, 0.2], [true, 0.3]];
  assertRate(stats, samples);
  assert.equal(engine.domainStats.has('example.com:1'), false);
  assert.throws(() => engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 1]] }, completed), /sequence/);
  assertRate(stats, samples);
});

test('a telemetry gap larger than the window fails before changing the EMA', t => {
  const engine = engineFixture(t), job = engine.queue.get(bounty().txid + ':0');
  engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 1, recent: [[false, 300]] }, 0);
  const samples = Array.from({ length: 100 }, (_, index) => [index % 2 === 0, index / 1000]);
  assert.throws(() => engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 150, recent: samples }, 1), /statistics|sequence|gap/);
  assertRate(engine.domainStats.get('example.com:7'), [[false, 300]]);
  engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 101, recent: samples }, 1);
  assertRate(engine.domainStats.get('example.com:7'), [[false, 300], ...samples]);
  const next = [...samples.slice(1), [true, 0.5]];
  engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 102, recent: next }, 101);
  assertRate(engine.domainStats.get('example.com:7'), [[false, 300], ...samples, [true, 0.5]]);
});

test('a new helper run restarts its local completion counter without resetting shared domain history', t => {
  const engine = engineFixture(t), job = engine.queue.get(bounty().txid + ':0');
  engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 2, recent: [[true, 0.1], [false, 0.2]] }, 0);
  engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 0.3]] }, 0);
  assertRate(engine.domainStats.get('example.com:7'), [[true, 0.1], [false, 0.2], [true, 0.3]]);
});

test('coalesced protocol-4 output records all validated outcomes in terminal order, never raw captures twice', async t => {
  const engine = engineFixture(t), job = engine.queue.get(bounty().txid + ':0');
  const { pool, commands, write } = persistentPoolFixture(t);
  await pool.start({ connectionsPerSecond: 256, concurrency: 256 });
  const samples = Array.from({ length: 180 }, (_, index) => [index === 0, index < 80 ? 0.2 : 0.005]);
  const pending = samples.map(() => {
    const request = { job, observed: false };
    return pool.attempt(context, { bountyId: `${bounty().txid}:0`, onCapture: value => engine.observe(request, value),
      onResult: value => engine.observeResult(request, value) });
  });
  const captures = commands.map((command, index) => ({ type: 'capture', id: command.id, context,
    started: true, captured: index < 2, seconds: samples[index][1], cancelled: false,
    successfulConnections: String(Math.min(index + 1, 2)) }));
  // Real pipe chunks may contain many complete frames. All observations arrive
  // together, followed by verification results in a different completion order.
  write(captures.flatMap(frame => [{ type: 'started', id: frame.id }, frame]));
  assert.equal(engine.domainStats.has('example.com:7'), false, 'capture alone must not improve the EMA');
  const terminals = captures.map((frame, index) => ({ ...frame, type: 'attempt', proof: null, verified: false, validationPassed: samples[index][0] }));
  write(terminals.reverse());
  await Promise.all(pending);
  const stats = engine.domainStats.get('example.com:7'), completionOrder = [...samples].reverse();
  assertRate(stats, completionOrder);
  assert.equal(stats.completed, 180);
  assert.notEqual(stats.connectionRate(), expectedRate(completionOrder.slice(-100)), 'older observations still influence the EMA');
  assert.equal(engine.domainStats.has('example.com:1'), false);
  assert.equal(engine.successCounts.get(`${bounty().txid}:0`), 2n);
  write([captures[0]]);
  assert.match(pool.failure.message, /duplicate|Unexpected/);
  assertRate(stats, completionOrder);
});

test('EMA distinguishes invalid proofs from valid target misses and excludes unfinished validation cancellation', t => {
  const engine = engineFixture(t), job = engine.queue.get(bounty().txid + ':0');
  const observe = value => {
    const request = { job, observed: false }, result = { started: true, ...value };
    engine.observe(request, result); engine.observeResult(request, result);
  };
  observe({ captured: false, seconds: 10, cancelled: true, validationPassed: null });
  observe({ captured: true, seconds: 0.1, cancelled: true, validationPassed: null });
  assert.equal(engine.domainStats.has('example.com:7'), false);
  observe({ captured: false, seconds: 10, cancelled: false, validationPassed: false });
  observe({ captured: true, seconds: 0.2, cancelled: false, proof: null, verified: false, validationPassed: false });
  observe({ captured: true, seconds: 0.05, cancelled: false, proof: null, verified: false, validationPassed: true });
  observe({ captured: true, seconds: 0.08, cancelled: true, proof: null, verified: false, validationPassed: true });
  observe({ captured: true, seconds: 0.3, cancelled: true, proof: null, verified: false, validationPassed: false });
  const stats = engine.domainStats.get('example.com:7');
  const samples = [[false, 10], [false, 0.2], [true, 0.05], [true, 0.08], [false, 0.3]];
  assertRate(stats, samples);
  const duplicate = { job, observed: true };
  assert.throws(() => engine.observe(duplicate, { captured: true, seconds: 1, cancelled: false }), /Duplicate/);
  assert.throws(() => engine.observeResult({ job, resultObserved: true }, { started: true, captured: true, seconds: 1, validationPassed: true }), /Duplicate/);
  assertRate(stats, samples);
});

test('legacy capture-only statistics cannot be imported as cryptographically valid history', () => {
  assert.throws(() => validateAttemptStats({ completed: 1, recent: [[true, 0.2]] }, 10), /statistics/);
  assert.throws(() => validateAttemptStats({ validation: 'capture-only', completed: 1, recent: [[true, 0.2]] }, 10), /statistics/);
});

test('catalog retirement bounds local factors and statistics but retains an active out-of-window attempt', t => {
  const engine = engineFixture(t), first = bounty(), second = bounty(1, { signature_algorithms_mask: 1 });
  const active = engine.queue.get(first.txid + ':0');
  engine.recordAttemptStats(active, { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 0.1]] }, 0);
  const factor = active.factor;
  engine.activeKey = first.txid + ':0';
  engine.retainCatalog([second]);
  assert.equal(engine.factors.get(first.txid + ':0'), factor);
  assert.equal(engine.domainStats.has('example.com:7'), true);
  engine.activeKey = null;
  engine.retainCatalog([second]);
  assert.equal(engine.factors.has(first.txid + ':0'), false);
  assert.equal(engine.domainStats.has('example.com:7'), false);
  assert.equal(engine.factors.has(second.txid + ':1'), true);
});

test('selection-preserving discovery reset keeps factors, stats and domain turn; normal clear erases them', t => {
  const engine = engineFixture(t), row = bounty(), id = row.txid + ':0';
  const job = engine.queue.get(id), factor = job.factor;
  engine.recordAttemptStats(job, { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 0.1]] }, 0);
  engine.markAssigned(engine.nextReady());
  assert.equal(engine.scheduler.domainAfter, 'example.com');
  assert.equal(engine.preferReward, true);
  engine.clear({ preserveSelection: true });
  assert.equal(engine.queue.size, 0);
  assert.equal(engine.factors.get(id), factor);
  assertRate(engine.domainStats.get('example.com:7'), [[true, 0.1]]);
  assert.equal(engine.scheduler.domainAfter, 'example.com');
  assert.equal(engine.preferReward, true);
  engine.enqueue([row]);
  assert.equal(engine.queue.get(id).factor, factor);
  engine.clear();
  assert.equal(engine.factors.size, 0); assert.equal(engine.domainStats.size, 0);
  assert.equal(engine.scheduler.domainAfter, null); assert.equal(engine.preferReward, false);
});

test('old helpers missing completion telemetry fail closed instead of silently keeping the rate prior', async () => {
  await assert.rejects(runner([{ type: 'progress', attempts: 1, elapsed: 0.1 }])(context), /statistics|progress|telemetry/i);
  await assert.rejects(runner([], { attempts: 1 })(context), /statistics|attempt|telemetry|result/i);
});

for (const attempts of [undefined, null, 0, 2, -1, 1.5, '1']) test(`verified helper result requires the exact positive completed count: ${String(attempts)}`, async () => {
  await assert.rejects(runner([progress(1, [[true, 0.1]])], { attempts })(context), /attempt|result|statistics/i);
});
