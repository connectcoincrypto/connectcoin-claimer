import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, basename } from 'node:path';
import { ClaimsEngine } from '../src/core/claims.mjs';
import { DiagnosticLog, diagnosticError } from '../src/core/diagnostics.mjs';
import { MAX_CONNECTION_LIMIT } from '../src/core/connection-limits.mjs';

const row = vout => ({ txid: '12'.repeat(32), vout, amount: '1000000000', domain: 'private-canary.example',
  status: 'available', connection_work_target: 'f'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7 });
const context = item => ({ domain: item.domain, txid: '34'.repeat(32), input_index: 0,
  connection_work_target: item.connection_work_target, root_certificates_version: 1,
  signature_algorithms_mask: 7, validation_time: 1800000000 });
const aborted = () => Object.assign(new Error('cancelled'), { name: 'AbortError' });
const waitForAbort = signal => new Promise((_, reject) => {
  if (signal.aborted) reject(aborted()); else signal.addEventListener('abort', () => reject(aborted()), { once: true });
});
async function until(predicate) {
  for (let i = 0; i < 2000; i++) { if (predicate()) return; await new Promise(resolve => setImmediate(resolve)); }
  throw new Error('Mock operation did not settle');
}
function fixture(t, overrides = {}) {
  const events = [], { pool: poolOverrides, ...options } = overrides;
  const pool = { pacesStarts: true, async start() {}, async close() {}, async resolve() {},
    async attempt(_context, { onStarted, onCapture }) {
      onStarted(); const result = { started: true, captured: true, validationPassed: true, cancelled: false, seconds: 0.1, proof: '020100', verified: true };
      onCapture(result); return result;
    }, ...poolOverrides };
  const engine = new ClaimsEngine({ isUnlocked: () => true, randomIndex: () => 0,
    options: { connectionsPerSecond: 256, concurrency: 1 }, poolFactory: () => pool,
    prepare: async item => ({ context: context(item) }), submit: async prepared => prepared.context.txid,
    onDiagnostic: (event, details) => events.push({ event, details }), ...options });
  t.after(() => engine.stop());
  return { engine, events, pool };
}

for (const stage of ['prepare', 'dns', 'capture', 'submit']) test(`progress exposes an in-flight ${stage} and stop balances its cancellation`, async t => {
  let now = 0; t.mock.method(performance, 'now', () => now);
  const overrides = stage === 'prepare' ? { prepare: (_item, { signal }) => waitForAbort(signal) }
    : stage === 'dns' ? { pool: { resolve: (_domain, { signal }) => waitForAbort(signal) } }
      : stage === 'capture' ? { pool: { attempt: (_ctx, { signal, onStarted }) => { onStarted(); return waitForAbort(signal); } } }
        : { submit: (_prepared, _proof, { signal }) => waitForAbort(signal) };
  const { engine, events } = fixture(t, overrides);
  engine.enqueue([row(0)]); engine.start();
  await until(() => engine.diagnosticSnapshot()[`${stage}Active`] === 1);
  now = 5001; engine.reportProgress();
  const progress = events.find(item => item.event === 'claims.progress').details;
  assert.equal(progress[`${stage}Active`], 1); assert.equal(progress.activeMaxDurationMs, 5001);
  await engine.stop();
  const terminal = events.find(item => item.event === 'claims.stopped').details;
  assert.equal(terminal.reason, 'stop'); assert.equal(terminal.operationsCancelled, 1); assert.equal(terminal.cancelledStop, 1);
  assert.equal(terminal.operationsStarted, terminal.operationsCompleted + terminal.operationsFailed + terminal.operationsCancelled);
  assert.equal(terminal.prepareActive + terminal.dnsActive + terminal.captureActive + terminal.submitActive, 0);
  assert.equal(terminal.durationMaxMs, 5001); assert.equal(engine.diagnosticOperations.size, 0);
  const before = events.length; await engine.stop(); await engine.stop(); assert.equal(events.length, before);
  for (const secret of ['private-canary', row(0).txid, '34'.repeat(32), '020100']) assert.ok(!JSON.stringify(events).includes(secret));
});

test('thousands of successful operations have bounded samples and one progress record per five seconds', async t => {
  let now = 0; t.mock.method(performance, 'now', () => now);
  t.mock.timers.enable({ apis: ['setInterval'] });
  const { engine, events } = fixture(t);
  engine.enqueue(Array.from({ length: 1000 }, (_, i) => row(i))); engine.start();
  await until(() => engine.state.completed === 1000 && !engine.running);
  assert.equal(events.filter(item => item.event === 'claim.succeeded').length, 4);
  assert.equal(events.some(item => item.event === 'claim.started'), false);
  assert.equal(engine.diagnosticOperations.size, 0);
  now = 4999; engine.reportProgress(); assert.equal(events.some(item => item.event === 'claims.progress'), false);
  now = 5000; t.mock.timers.tick(5000);
  for (let i = 0; i < 100; i++) engine.reportProgress();
  assert.equal(events.filter(item => item.event === 'claims.progress').length, 1);
  const aggregate = events.find(item => item.event === 'claims.progress').details;
  assert.equal(aggregate.completed, 1000); assert.equal(aggregate.attempts, 1000); assert.equal(aggregate.captures, 1000);
  assert.equal(aggregate.operationsStarted, 3001); assert.equal(aggregate.operationsCompleted, 3001);
  assert.equal(aggregate.suppressedEvents, 996);
  now = 10000; t.mock.timers.tick(5000);
  assert.equal(events.filter(item => item.event === 'claims.progress').length, 2);
  await engine.stop();
  const count = events.length; now = 20000; t.mock.timers.tick(10000); assert.equal(events.length, count);
});

test('catalog resync preserves both activity counters and subsequent submissions accumulate', async t => {
  const { engine } = fixture(t);
  engine.enqueue([row(0), row(1)]); engine.start();
  await until(() => engine.state.completed === 2 && !engine.running);
  const totals = () => ({ attempts: engine.snapshot().attempts, completed: engine.snapshot().completed });
  assert.deepEqual(totals(), { attempts: 2, completed: 2 });
  for (let next = 2; next < 4; next++) {
    await engine.suspend();
    engine.clear({ preserveSelection: true });
    assert.deepEqual(totals(), { attempts: next, completed: next });
    engine.enqueue([row(next)]); engine.resume();
    await until(() => engine.state.completed === next + 1 && !engine.running);
    assert.deepEqual(totals(), { attempts: next + 1, completed: next + 1 });
    assert.equal(engine.diagnosticSnapshot().completed, next + 1);
  }
});

test('stop and restart preserve both activity counters; full clear resets both together', async t => {
  const { engine } = fixture(t);
  const totals = () => ({ attempts: engine.snapshot().attempts, completed: engine.snapshot().completed });
  engine.enqueue([row(0)]); engine.start();
  await until(() => engine.state.completed === 1 && !engine.running);
  await engine.stop();
  assert.deepEqual(totals(), { attempts: 1, completed: 1 });
  engine.enqueue([row(1)]); engine.start();
  await until(() => engine.state.completed === 2 && !engine.running);
  assert.deepEqual(totals(), { attempts: 2, completed: 2 });
  await engine.stop(); engine.clear();
  assert.deepEqual(totals(), { attempts: 0, completed: 0 });
  engine.enqueue([row(2)]); engine.start();
  await until(() => engine.state.completed === 1 && !engine.running);
  assert.deepEqual(totals(), { attempts: 1, completed: 1 });
});

test('success duration measures submit only while progress aggregates completed stage work', async t => {
  let now = 0; t.mock.method(performance, 'now', () => now);
  const { engine, events } = fixture(t, {
    prepare: async item => { now += 100; return { context: context(item) }; },
    pool: { async attempt(_ctx, { onStarted, onCapture }) {
      onStarted(); now += 150;
      const result = { started: true, captured: true, validationPassed: true, cancelled: false, seconds: 0.15, proof: '020100', verified: true };
      onCapture(result); return result;
    } },
    submit: async prepared => { now += 50; return prepared.context.txid; },
  });
  engine.enqueue([row(0)]); engine.start(); await until(() => engine.state.completed === 1 && !engine.running);
  const success = events.find(item => item.event === 'claim.succeeded').details;
  assert.equal(success.stage, 'submit'); assert.equal(success.durationScope, 'stage'); assert.equal(success.durationMs, 50);
  await engine.stop();
  const terminal = events.find(item => item.event === 'claims.stopped').details;
  assert.equal(terminal.durationScope, 'run'); assert.equal(terminal.durationMs, 300);
  assert.equal(terminal.durationTotalMs, 300); assert.equal(terminal.durationMaxMs, 150);
});

test('failure bursts retain totals and never sample away fatal unknown broadcast outcomes', async t => {
  const { engine, events } = fixture(t, { prepare: async () => { throw new Error('DNS resolution failed for private-canary.example'); } });
  engine.enqueue(Array.from({ length: 30 }, (_, i) => row(i))); engine.start();
  await until(() => engine.diagnosticSnapshot().operationsFailed === 30 && !engine.running);
  assert.equal(events.filter(item => item.event === 'claim.failed').length, 4);
  assert.equal(engine.diagnosticSnapshot().suppressedEvents, 26);
  const unknown = Object.assign(new Error('Broadcast outcome is unknown.'), { unknownOutcome: true });
  engine.fatal(unknown); await engine.stopping;
  const failure = events.find(item => item.event === 'claims.failed').details;
  assert.equal(failure.error, unknown); assert.equal(failure.reason, 'fatal');
  const terminal = events.find(item => item.event === 'claims.stopped').details;
  assert.equal(terminal.reason, 'fatal'); assert.equal(terminal.operationsFailed, 30);
  assert.equal(terminal.operationsStarted, 30); assert.equal(terminal.suppressedEvents, 26);
});

test('the persistent pool DNS error retains its safe category and does not invent a TCP attempt', async t => {
  const { engine, events } = fixture(t, { pool: { async resolve() { throw new Error('Domain resolution failed'); } } });
  engine.enqueue([row(0)]); engine.start(); await until(() => engine.diagnosticSnapshot().operationsFailed === 1 && !engine.running);
  await engine.stop();
  const failure = events.find(item => item.event === 'claim.failed').details;
  assert.equal(failure.stage, 'dns'); assert.equal(diagnosticError(failure.error).category, 'dns');
  const terminal = events.find(item => item.event === 'claims.stopped').details;
  assert.equal(terminal.operationsFailed, 1); assert.equal(terminal.attempts, 0);
});

test('invalidation and suspension retain distinct safe cancellation counts and resume retains the run', async t => {
  const { engine, events } = fixture(t, { pool: { attempt: (_ctx, { signal, onStarted }) => { onStarted(); return waitForAbort(signal); } } });
  engine.enqueue([row(0)]); engine.start(); await until(() => engine.diagnosticSnapshot().captureActive === 1);
  engine.remove(row(0).txid, 0); await until(() => !engine.running);
  assert.equal(engine.diagnosticSnapshot().cancelledUnavailable, 1);
  engine.enqueue([row(1)]); await until(() => engine.diagnosticSnapshot().captureActive === 1);
  await engine.suspend();
  const suspended = events.find(item => item.event === 'claims.suspended').details;
  assert.equal(suspended.reason, 'suspend'); assert.equal(suspended.cancelledSuspend, 1); assert.equal(suspended.paused, true);
  const count = events.length; await engine.suspend(); assert.equal(events.length, count);
  engine.resume(); await until(() => engine.diagnosticSnapshot().captureActive === 1);
  assert.equal(events.find(item => item.event === 'claims.resumed').details.runId, suspended.runId);
  await engine.stop();
  const terminal = events.find(item => item.event === 'claims.stopped').details;
  assert.equal(terminal.cancelledUnavailable, 1); assert.equal(terminal.cancelledSuspend, 1); assert.equal(terminal.cancelledStop, 1);
  assert.equal(terminal.operationsCancelled, 3);
});

test('fatal closes the gate before reporting and drains outstanding work with its own cancellation reason', async t => {
  const { engine, events } = fixture(t, { pool: { attempt: (_ctx, { signal, onStarted }) => { onStarted(); return waitForAbort(signal); } } });
  engine.enqueue([row(0)]); engine.start(); await until(() => engine.diagnosticSnapshot().captureActive === 1);
  engine.fatal(Object.assign(new Error('Claims helper could not start: private-canary'), { helperFatal: true }));
  await engine.stopping;
  const failed = events.find(item => item.event === 'claims.failed').details;
  assert.equal(failed.enabled, false); assert.equal(failed.captureActive, 1); assert.equal(failed.reason, 'fatal');
  const terminal = events.find(item => item.event === 'claims.stopped').details;
  assert.equal(terminal.cancelledFatal, 1); assert.equal(terminal.operationsCancelled, 1); assert.equal(terminal.captureActive, 0);
  assert.equal(terminal.operationsStarted, terminal.operationsCompleted + terminal.operationsCancelled);
  assert.equal(terminal.reason, 'fatal'); assert.equal(engine.diagnosticOperations.size, 0);
});

test('a winning proof aggregates sibling cancellation separately from stop', async t => {
  const attempts = [];
  const { engine, events } = fixture(t, { options: { connectionsPerSecond: 256, concurrency: 3 }, pool: {
    attempt(_ctx, { signal, onStarted, onCapture }) {
      return new Promise((resolve, reject) => {
        const abort = () => reject(aborted()); signal.addEventListener('abort', abort, { once: true });
        attempts.push(() => {
          signal.removeEventListener('abort', abort);
          const result = { started: true, captured: true, validationPassed: true, cancelled: false, seconds: 0.1, proof: '020100', verified: true };
          onCapture(result); resolve(result);
        });
        onStarted();
      });
    },
  } });
  engine.enqueue([row(0)]); engine.start(); await until(() => attempts.length === 3);
  attempts[0](); await until(() => engine.state.completed === 1 && !engine.running); await engine.stop();
  const terminal = events.find(item => item.event === 'claims.stopped').details;
  assert.equal(terminal.attempts, 3); assert.equal(terminal.captures, 1); assert.equal(terminal.completed, 1);
  assert.equal(terminal.cancelledSiblingProof, 2); assert.equal(terminal.cancelledStop, 0);
  assert.equal(terminal.operationsStarted, terminal.operationsCompleted + terminal.operationsCancelled);
});

test('progress allowlists exclude arbitrary reasons, duration labels, nested data and overflowing counters', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'connectwallet-progress-'));
  t.after(async () => { const path = resolve(directory); assert.equal(dirname(path), resolve(tmpdir())); assert.ok(basename(path).startsWith('connectwallet-progress-')); await rm(path, { recursive: true, force: true }); });
  const log = new DiagnosticLog({ directory }); let invoked = 0;
  log.record('claims.progress', { stage: 'lifecycle', runId: 1, prepareActive: 4, dnsActive: 2, captureActive: 256, submitActive: 4,
    operationsStarted: 1000, operationsCompleted: 500, operationsFailed: 2, operationsCancelled: 3, cancelledStop: 3,
    durationTotalMs: 10000, durationMaxMs: 2000, activeMaxDurationMs: 3000, suppressedEvents: 496,
    paused: false, durationScope: 'run', reason: 'stop', domain: 'private-canary.example', proof: 'private-proof-canary',
    get cancelledOther() { invoked++; return 1; } });
  log.record('claims.progress', { reason: 'private-reason-canary', durationScope: 'private-scope-canary', prepareActive: 5, dnsActive: 3,
    captureActive: MAX_CONNECTION_LIMIT + 1, submitActive: 5, operationsStarted: Infinity, operationsFailed: -1, cancelledStop: 1.5,
    durationTotalMs: Number.MAX_SAFE_INTEGER + 1, raw: { private: 'canary' } });
  log.record('claims.failed', { reason: 'fatal', error: Object.assign(new Error('private-error-canary'), { unknownOutcome: true }) });
  await log.flush();
  const text = await readFile(log.snapshot().file, 'utf8'), rows = text.trim().split('\n').map(JSON.parse);
  assert.equal(invoked, 0); assert.ok(!text.includes('private-')); assert.deepEqual(rows[1].details, {});
  assert.equal(rows[0].details.captureActive, 256); assert.equal(rows[0].details.suppressedEvents, 496);
  assert.equal(rows[0].details.cancelledStop, 3); assert.equal(rows[0].details.durationScope, 'run');
  assert.equal(rows[2].details.error.category, 'broadcast-unknown'); assert.equal(log.snapshot().errors, 1);
});
