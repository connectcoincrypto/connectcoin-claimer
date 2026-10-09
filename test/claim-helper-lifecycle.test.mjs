import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';
import { ConnectionPool } from '../src/core/claim-pool.mjs';

const tick = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate) {
  for (let i = 0; i < 100; i++) { if (predicate()) return; await tick(); }
  throw new Error('Helper lifecycle did not settle');
}

function fixture(t, { failAtStart = false } = {}) {
  const children = [], pools = [], events = [];
  const engine = new ClaimsEngine({
    isUnlocked: () => true, prepare: async () => { throw new Error('No work expected'); }, submit: async () => { throw new Error('No submission expected'); },
    onDiagnostic: (event, details) => events.push({ event, details }),
    poolFactory: ({ onFailure }) => {
      const pool = new ConnectionPool({ helper: { command: 'fake' }, onFailure,
        spawnProcess: () => {
          const child = new EventEmitter(); children.push(child);
          child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
          child.kill = () => { child.killed = true; queueMicrotask(() => child.emit('close', null, 'SIGKILL')); };
          child.stdin.on('data', frame => {
            const message = JSON.parse(frame.toString());
            if (message.type === 'start') queueMicrotask(() => failAtStart
              ? child.emit('close', 1, null)
              : child.stdout.write('{"type":"ready","protocol":4,"roots":1,"security":{"rsaPublicExponentMaxBits":64}}\n'));
            if (message.type === 'shutdown') queueMicrotask(() => child.emit('close', 0, null));
          });
          return child;
        },
      });
      pools.push(pool); return pool;
    },
  });
  t.after(() => engine.stop());
  return { engine, children, pools, events };
}

test('an idle helper crash immediately stops claims without waiting for another bounty', async t => {
  const { engine, children, events } = fixture(t);
  engine.start(); await until(() => !engine.running && children.length === 1);
  assert.equal(engine.enabled, true);
  children[0].emit('close', 3221225477, null);
  await until(() => !engine.enabled && !engine.stopping);
  assert.equal(engine.snapshot().status, 'off');
  assert.match(engine.snapshot().lastError, /closed unexpectedly/);
  assert.equal(events.filter(row => row.event === 'claims.failed').length, 1);
  assert.equal(events.find(row => row.event === 'claims.stopped').details.reason, 'fatal');
  assert.equal(engine.refreshTimer, null);
});

test('startup rejection and failure callback report one fatal event and drain', async t => {
  const { engine, events } = fixture(t, { failAtStart: true });
  engine.start(); await until(() => !engine.enabled && !engine.stopping);
  assert.equal(events.filter(row => row.event === 'claims.failed').length, 1);
  assert.equal(engine.running, null);
  assert.equal(engine.pool, null);
});

for (const transition of ['stop', 'suspend']) test(`late helper callback after ${transition} cannot stop the next generation`, async t => {
  const { engine, pools, events } = fixture(t);
  engine.start(); await until(() => !engine.running && pools.length === 1);
  await engine[transition]();
  if (transition === 'stop') engine.start(); else engine.resume();
  await until(() => !engine.running && pools.length === 2);
  pools[0].onFailure(Object.assign(new Error('late old helper failure'), { helperFatal: true }));
  await tick();
  assert.equal(engine.enabled, true);
  assert.equal(engine.pool, pools[1]);
  assert.equal(engine.snapshot().lastError, null);
  assert.equal(events.filter(row => row.event === 'claims.failed').length, 0);
});

test('helper failure cannot hide an unknown in-flight broadcast outcome discovered during cancellation', async t => {
  const context = { domain: 'example.com', txid: '01'.repeat(32), input_index: 0,
    connection_work_target: 'ff'.repeat(32), root_certificates_version: 1,
    signature_algorithms_mask: 7, validation_time: 1800000000 };
  const events = [];
  let failHelper, submitting = false;
  const unknown = Object.assign(new Error('Broadcast outcome is unknown; check transaction history before retrying.'), { unknownOutcome: true });
  const engine = new ClaimsEngine({ isUnlocked: () => true, prepare: async () => ({ context }),
    onDiagnostic: (event, details) => events.push({ event, details }),
    poolFactory: ({ onFailure }) => {
      failHelper = onFailure;
      return { async start() {}, async close() {}, async resolve() {},
        async attempt(_context, { onStarted, onCapture }) {
          onStarted(); const result = { started: true, captured: true, validationPassed: true, cancelled: false, seconds: 0.1, verified: true, proof: '020100' };
          onCapture(result); return result;
        },
      };
    },
    submit: async (_prepared, _proof, { signal }) => {
      submitting = true;
      return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(unknown), { once: true }));
    },
  });
  t.after(() => engine.stop());
  engine.enqueue([{ txid: '02'.repeat(32), vout: 0, amount: '1000000000', status: 'available', ...Object.fromEntries(
    ['domain', 'connection_work_target', 'root_certificates_version', 'signature_algorithms_mask'].map(key => [key, context[key]])) }]);
  engine.start(); await until(() => submitting);
  failHelper(Object.assign(new Error('Persistent claims helper closed unexpectedly'), { helperFatal: true }));
  await until(() => !engine.enabled && !engine.stopping);
  assert.equal(engine.snapshot().lastError, unknown.message);
  const failures = events.filter(row => row.event === 'claims.failed');
  assert.equal(failures.length, 2);
  assert.equal(failures[1].details.error, unknown);
  assert.equal(engine.running, null);
  assert.equal(engine.snapshot().completed, 0);
});

for (const lateOutcome of ['success', 'rejection']) test(`another submission's late ${lateOutcome} cannot replace an unknown broadcast warning`, async t => {
  const context = { domain: 'example.com', txid: '01'.repeat(32), input_index: 0,
    connection_work_target: 'ff'.repeat(32), root_certificates_version: 1,
    signature_algorithms_mask: 7, validation_time: 1800000000 };
  const submissions = new Map(), events = [];
  const unknown = Object.assign(new Error('Broadcast outcome is unknown; verify before retrying.'), { unknownOutcome: true });
  const engine = new ClaimsEngine({ isUnlocked: () => true,
    prepare: async bounty => ({ index: bounty.vout, context: { ...context, txid: (bounty.vout ? '03' : '01').repeat(32) } }),
    onDiagnostic: (event, details) => events.push({ event, details }),
    poolFactory: () => ({ pacesStarts: true, async start() {}, async close() {}, async resolve() {},
      async attempt(_context, { onStarted, onCapture }) {
        onStarted(); const result = { started: true, captured: true, validationPassed: true, cancelled: false, seconds: 0.1, verified: true, proof: '020100' };
        onCapture(result); return result;
      },
    }),
    submit: prepared => new Promise((resolve, reject) => submissions.set(prepared.index, { resolve, reject })),
  });
  t.after(async () => { for (const submission of submissions.values()) submission.reject(unknown); await engine.stop(); });
  engine.enqueue([0, 1].map(vout => ({ txid: '02'.repeat(32), vout, amount: '1000000000', status: 'available', domain: context.domain,
    connection_work_target: context.connection_work_target, root_certificates_version: 1, signature_algorithms_mask: 7 })));
  engine.start(); await until(() => submissions.size === 2);
  submissions.get(0).reject(unknown);
  await until(() => !engine.enabled);
  assert.equal(engine.snapshot().lastError, unknown.message);
  if (lateOutcome === 'success') submissions.get(1).resolve('03'.repeat(32));
  else submissions.get(1).reject(Object.assign(new Error('The node rejected this claim.'), { code: -32020, data: { node_code: -26 } }));
  await until(() => !engine.stopping);
  assert.equal(engine.snapshot().lastError, unknown.message);
  assert.equal(engine.snapshot().lastErrorTransient, false);
  assert.equal(engine.snapshot().lastErrorDiagnostic, false);
  assert.equal(engine.snapshot().completed, lateOutcome === 'success' ? 1 : 0);
  assert.equal(events.filter(row => row.event === 'claims.failed').length, 1);
  assert.ok(events.some(row => row.event === (lateOutcome === 'success' ? 'claim.succeeded' : 'claim.failed')));
});
