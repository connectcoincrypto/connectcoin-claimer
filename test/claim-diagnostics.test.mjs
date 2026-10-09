import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { ClaimsEngine, createProofRunner } from '../src/core/claims.mjs';

const context = { domain: 'example.com', txid: '01'.repeat(32), input_index: 0,
  connection_work_target: 'ff'.repeat(32), root_certificates_version: 1,
  signature_algorithms_mask: 7, validation_time: 1800000000 };
const bounty = vout => ({ txid: '02'.repeat(32), vout, amount: '1000000000', domain: 'example.com', status: 'available', connection_work_target: 'f'.repeat(64), signature_algorithms_mask: 7, root_certificates_version: 1 });
async function until(predicate) {
  for (let i = 0; i < 200; i++) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 5)); }
  throw new Error('Mock claims did not finish');
}

for (const stage of ['prepare', 'proof', 'submit']) test(`diagnostics retain a ${stage} failure after the next claim clears its warning`, async t => {
  const events = [];
  const failure = Object.assign(new Error('The node rejected this claim. Its bounty or proof may no longer be valid.'), { code: -32020, data: { node_code: -26 } });
  const engine = new ClaimsEngine({
    isUnlocked: () => true,
    options: { connectionsPerSecond: 256, concurrency: 1 },
    randomIndex: () => 0,
    onDiagnostic: (event, details) => {
      events.push({ event, details });
      // The rejected outpoint leaves discovery; a per-connection worker is
      // otherwise allowed to retry TCP immediately after its one-second pause.
      if (event === 'claim.failed' && details.claimId === 1) engine.remove(bounty(0).txid, 0);
    },
    prepare: async item => {
      if (item.vout === 0 && stage === 'prepare') throw failure;
      return { item, context: { ...context, txid: (item.vout === 0 ? '01' : '03').repeat(32) } };
    },
    generateProof: async publicContext => {
      if (publicContext.txid === context.txid && stage === 'proof') throw failure;
      return '020100';
    },
    submit: async prepared => { if (prepared.item.vout === 0 && stage === 'submit') throw failure; return prepared.context.txid; },
  });
  t.after(() => engine.stop());
  engine.enqueue([bounty(0), bounty(1)]); engine.start();
  await until(() => engine.snapshot().completed === 1 && !engine.running);
  assert.equal(engine.enabled, true);
  assert.equal(engine.snapshot().lastError, null);
  const recorded = events.find(row => row.event === 'claim.failed').details;
  assert.equal(recorded.stage, stage);
  assert.equal(recorded.claimId, 1);
  assert.equal(recorded.error.code, -32020);
  assert.equal(recorded.error.data.node_code, -26);
  assert.equal(recorded.failures, stage === 'proof' ? 0 : 1);
  assert.ok(recorded.retryDelayMs > (stage === 'proof' ? 900 : 29000) && recorded.retryDelayMs <= (stage === 'proof' ? 1000 : 30000));
  assert.ok(recorded.durationMs >= 0);
  assert.equal(recorded.durationScope, 'stage');
  assert.equal(recorded.attempts, stage === 'prepare' ? 0 : 1);
  assert.equal(events.find(row => row.event === 'claim.succeeded').details.claimId, 2);
  assert.equal(events.find(row => row.event === 'claim.succeeded').details.durationScope, 'stage');
  assert.ok(!JSON.stringify(events).includes(context.txid));
  assert.ok(!JSON.stringify(events).includes(bounty(0).txid));
  assert.ok(!JSON.stringify(events).includes('example.com'));
});

test('throwing and rejecting diagnostic callbacks do not stop claims', async () => {
  for (const onDiagnostic of [() => { throw new Error('disk unavailable'); }, async () => { throw new Error('disk unavailable'); }]) {
    const engine = new ClaimsEngine({ isUnlocked: () => true, onDiagnostic, options: { connectionsPerSecond: 256, concurrency: 1 },
      prepare: async () => ({ context }), generateProof: async () => '020100', submit: async () => context.txid });
    try {
      engine.enqueue([bounty(0)]); engine.start();
      await until(() => engine.snapshot().completed === 1);
      assert.equal(engine.enabled, true);
    } finally { await engine.stop(); }
  }
});

test('helper failure metadata counts but never copies stderr or partial proof output', async () => {
  const events = [];
  const spawnProcess = () => {
    const child = new EventEmitter();
    child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.stdin.on('finish', () => {
      child.stderr.write('private-helper-stderr-canary');
      child.emit('close', 7);
    });
    return child;
  };
  const runner = createProofRunner({ helper: { command: 'mock' }, spawnProcess,
    onDiagnostic: (event, details) => events.push({ event, details }) });
  await assert.rejects(runner(context), /without a verified proof/);
  assert.equal(events.length, 1);
  assert.equal(events[0].event, 'helper.failed');
  assert.equal(events[0].details.exitCode, 7);
  assert.equal(events[0].details.stderrBytes, Buffer.byteLength('private-helper-stderr-canary'));
  assert.ok(!JSON.stringify(events).includes('private-helper-stderr-canary'));
});

const connectionTimeoutWarning = 'One TCP/TLS connection attempt timed out before producing a usable TLS capture. No claim transaction was broadcast from this attempt.';
function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

for (const failureMode of ['capture-result', 'proof-error']) test(`one ${failureMode} TLS timeout never submits and later attempts can succeed`, async t => {
  const retry = deferred(), secondCapture = deferred(), states = [], events = [];
  let attempts = 0, submissions = 0;
  const pool = {
    async start() {}, async resolve() {}, async close() {},
    async attempt(publicContext, { onStarted, onCapture }) {
      onStarted(); attempts++;
      if (attempts === 1) {
        onCapture({ started: true, captured: false, cancelled: false, seconds: 10 });
        if (failureMode === 'proof-error') throw new Error('TLS connection timed out');
        return { started: true, captured: false, validationPassed: false, cancelled: false, seconds: 10, message: 'TLS connection timed out' };
      }
      await secondCapture.promise;
      const result = { started: true, captured: true, validationPassed: true, cancelled: false, seconds: 0.1, verified: true, proof: '020100' };
      onCapture(result); return result;
    },
  };
  const engine = new ClaimsEngine({
    isUnlocked: () => true, poolFactory: () => pool,
    options: { connectionsPerSecond: 256, concurrency: 1 }, randomIndex: () => 0,
    prepare: async () => ({ context }),
    submit: async () => { submissions++; return context.txid; },
    onState: state => states.push(state),
    onDiagnostic: (event, details) => events.push({ event, details }),
  });
  // Keep the first retry observable without spending a real one-second backoff.
  engine.pauseWorker = () => retry.promise;
  t.after(async () => { retry.resolve(); secondCapture.resolve(); await engine.stop(); });
  engine.enqueue([bounty(0)]); engine.start();
  await until(() => engine.snapshot().lastErrorCategory === 'tls-timeout');
  assert.equal(engine.snapshot().lastError, connectionTimeoutWarning);
  assert.equal(engine.snapshot().lastErrorTransient, true);
  assert.equal(engine.snapshot().lastErrorDiagnostic, false);
  assert.equal(engine.enabled, true);
  assert.equal(submissions, 0);
  assert.equal(engine.pendingProofs.size, 0, 'A timed-out capture must not create a claim proposal to submit');
  assert.equal(attempts, 1);
  const failure = events.find(row => row.event === 'claim.failed');
  assert.equal(failure.details.stage, 'proof');
  assert.equal(failure.details.attempts, 1);
  assert.equal(failure.details.error.message, 'TLS connection timed out');
  retry.resolve();
  await until(() => attempts === 2);
  assert.equal(engine.snapshot().lastError, null);
  assert.equal(engine.snapshot().lastErrorCategory, null, 'The next actual TCP start clears the timeout classification');
  assert.equal(engine.snapshot().lastErrorTransient, false);
  assert.equal(submissions, 0, 'Only the later verified proof may be submitted');
  secondCapture.resolve();
  await until(() => engine.snapshot().completed === 1 && !engine.running);
  assert.equal(submissions, 1);
  assert.equal(engine.enabled, true);
  assert.equal(engine.snapshot().lastErrorCategory, null);
  assert.equal(engine.snapshot().lastError, null);
  assert.ok(states.filter(state => state.lastError === null).every(state => state.lastErrorCategory === null));
});

const nonCaptureTimeouts = [
  { label: 'generic proof validation failure', stage: 'proof', message: 'TLS capture or proof validation failed' },
  { label: 'generic proof timeout', stage: 'proof', message: 'The operation exceeded its time limit.' },
  { label: 'operating-system timeout', stage: 'proof', message: 'connect ETIMEDOUT', fields: { code: 'ETIMEDOUT' } },
  { label: 'helper 45-second watchdog', stage: 'proof', message: 'Claims helper request exceeded its deadline', fields: { helperFatal: true } },
  { label: 'fatal helper with matching timeout text', stage: 'proof', message: 'TLS connection timed out', fields: { helperFatal: true } },
  { label: 'RPC submission timeout', stage: 'submit', message: 'RPC request timed out.' },
  { label: 'submission error with matching timeout text', stage: 'submit', message: 'TLS connection timed out' },
  { label: 'preparation error with matching timeout text', stage: 'prepare', message: 'TLS connection timed out' },
];
for (const { label, stage, message, fields = {} } of nonCaptureTimeouts) test(`${label} is not mislabeled as one failed TCP/TLS capture`, async t => {
  const failure = Object.assign(new Error(message), fields);
  let submissions = 0;
  const engine = new ClaimsEngine({
    isUnlocked: () => true, retryDelayMs: 300000,
    options: { connectionsPerSecond: 256, concurrency: 1 },
    prepare: async () => { if (stage === 'prepare') throw failure; return { context }; },
    generateProof: async () => { if (stage === 'proof') throw failure; return '020100'; },
    submit: async () => { submissions++; throw failure; },
  });
  t.after(() => engine.stop());
  engine.enqueue([bounty(0)]); engine.start();
  await until(() => Boolean(engine.snapshot().lastError));
  assert.equal(engine.snapshot().lastErrorCategory, null);
  assert.equal(engine.snapshot().lastError, message);
  assert.notEqual(engine.snapshot().lastError, connectionTimeoutWarning);
  assert.equal(engine.enabled, fields.helperFatal !== true);
  assert.equal(submissions, stage === 'submit' ? 1 : 0);
  if (fields.helperFatal) assert.equal(engine.snapshot().lastErrorTransient, false);
});

test('a late sibling TLS timeout cannot downgrade an unknown claim broadcast warning during shutdown', async t => {
  const siblingStarted = deferred(), lateFailure = deferred();
  const fatalMessage = 'Broadcast outcome is unknown. Check the transaction ID before retrying.';
  const states = [], events = [];
  let submissions = 0;
  const engine = new ClaimsEngine({
    isUnlocked: () => true,
    options: { connectionsPerSecond: 256, concurrency: 2 }, randomIndex: () => 0,
    prepare: async item => ({ context: { ...context, domain: item.domain,
      txid: (item.vout === 0 ? '01' : '03').repeat(32) } }),
    generateProof: async publicContext => {
      if (publicContext.txid === context.txid) return '020100';
      siblingStarted.resolve();
      // Emulate a helper error already in flight when cancellation is sent.
      await lateFailure.promise;
      throw new Error('TLS connection timed out');
    },
    submit: async () => {
      submissions++;
      await siblingStarted.promise;
      throw Object.assign(new Error(fatalMessage), { unknownOutcome: true });
    },
    onState: state => states.push(state),
    onDiagnostic: (event, details) => events.push({ event, details }),
  });
  t.after(async () => { siblingStarted.resolve(); lateFailure.resolve(); await engine.stop(); });
  engine.enqueue([bounty(0), { ...bounty(1), domain: 'example.org' }]); engine.start();
  await until(() => engine.snapshot().lastError === fatalMessage);
  assert.equal(engine.enabled, false);
  assert.equal(engine.snapshot().lastErrorCategory, null);
  assert.equal(engine.snapshot().lastErrorTransient, false);
  const fatalIndex = states.findIndex(state => state.lastError === fatalMessage);
  lateFailure.resolve();
  await until(() => !engine.running && !engine.stopping);
  assert.equal(engine.snapshot().lastError, fatalMessage);
  assert.equal(engine.snapshot().lastErrorCategory, null);
  assert.equal(engine.snapshot().lastErrorTransient, false);
  assert.equal(submissions, 1);
  assert.ok(states.slice(fatalIndex).every(state => state.lastError === fatalMessage && state.lastErrorCategory === null));
  assert.ok(events.some(row => row.event === 'claims.failed' && row.details.error.unknownOutcome === true));
  assert.ok(events.some(row => row.event === 'claim.failed' && row.details.stage === 'proof'),
    'The late capture failure remains diagnostic history without replacing the fatal warning');
});

test('TLS timeout category clears on a fresh run and any replacement or cleared warning', async t => {
  const engine = new ClaimsEngine({ isUnlocked: () => true,
    prepare: async () => ({ context }), generateProof: async () => '020100', submit: async () => context.txid });
  t.after(() => engine.stop());
  const markTimeout = () => engine.jobError({ diagnosticId: 1, failures: 0 }, new Error('TLS connection timed out'), 'proof', false);
  markTimeout();
  assert.equal(engine.snapshot().lastErrorCategory, 'tls-timeout');
  engine.start();
  assert.equal(engine.snapshot().lastError, null);
  assert.equal(engine.snapshot().lastErrorCategory, null);
  markTimeout();
  engine.notify({ lastError: 'RPC connection unavailable.' });
  assert.equal(engine.snapshot().lastErrorCategory, null);
  assert.equal(engine.snapshot().lastErrorTransient, false);
  markTimeout();
  engine.notify({ lastError: null, lastErrorCategory: 'tls-timeout', lastErrorTransient: true });
  assert.equal(engine.snapshot().lastErrorCategory, null);
  assert.equal(engine.snapshot().lastErrorTransient, false);
});
