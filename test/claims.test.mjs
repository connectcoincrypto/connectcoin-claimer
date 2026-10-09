import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { ClaimsEngine, createProofRunner, validateClaimContext, validateClaimOptions } from '../src/core/claims.mjs';

const context = () => ({ domain: 'example.com', txid: '01'.repeat(32), input_index: 0, connection_work_target: 'ff'.repeat(32), root_certificates_version: 1, signature_algorithms_mask: 7, validation_time: 1800000000 });
const bounty = (vout = 0) => ({ txid: '02'.repeat(32), vout, amount: '1000000000', domain: 'example.com', status: 'available', connection_work_target: 'f'.repeat(64), signature_algorithms_mask: 7, root_certificates_version: 1 });
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function until(predicate) { for (let i = 0; i < 100; i++) { if (predicate()) return; await new Promise((resolve) => setTimeout(resolve, 2)); } throw new Error('Timed out waiting for claims state'); }

test('removing or retiring absent discovery entries does not flood state notifications', () => {
  let notifications = 0;
  const engine = new ClaimsEngine({ isUnlocked: () => true, prepare: async () => {}, submit: async () => {}, onState: () => { notifications++; } });
  for (let vout = 0; vout < 1000; vout++) {
    engine.remove(bounty().txid, vout);
    engine.retire(bounty().txid, vout);
  }
  assert.equal(notifications, 0);
  engine.enqueue([bounty()]);
  const before = notifications;
  engine.remove(bounty().txid, 0);
  assert.equal(notifications, before + 1);
  assert.equal(engine.queue.size, 0);
  engine.remove(bounty().txid, 0);
  assert.equal(notifications, before + 1);
});

test('idempotent discovery invalidation preserves active cancellation and retirement', () => {
  let notifications = 0;
  const engine = new ClaimsEngine({ isUnlocked: () => true, prepare: async () => {}, submit: async () => {}, onState: () => { notifications++; } });
  engine.enqueue([bounty()]);
  engine.activeKey = `${bounty().txid}:0`;
  engine.controller = new AbortController();
  const before = notifications;
  engine.retire(bounty().txid, 0);
  assert.equal(engine.queue.get(engine.activeKey).retired, true);
  assert.equal(engine.controller.signal.aborted, false);
  engine.retire(bounty().txid, 0);
  assert.equal(notifications, before + 1);
  engine.remove(bounty().txid, 0);
  assert.equal(engine.controller.signal.aborted, true);
  assert.equal(notifications, before + 2);
  engine.remove(bounty().txid, 0);
  assert.equal(notifications, before + 2);
  // Abort must still work if another cleanup already removed the active entry.
  engine.controller = new AbortController();
  engine.remove(bounty().txid, 0);
  assert.equal(engine.controller.signal.aborted, true);
  assert.equal(notifications, before + 3);
});

test('enqueue without new bounties still wakes the scheduler without redundant queue notifications', () => {
  let notifications = 0, kicks = 0;
  const engine = new ClaimsEngine({ isUnlocked: () => true, prepare: async () => {}, submit: async () => {}, onState: () => { notifications++; } });
  engine.kick = () => { kicks++; };
  assert.equal(engine.enqueue([bounty()]), 1);
  assert.equal(notifications, 1);
  assert.equal(engine.enqueue([bounty()]), 0);
  assert.equal(engine.enqueue([]), 0);
  assert.equal(notifications, 1);
  assert.equal(kicks, 3);
});

test('claims options are finite and public context cannot smuggle private fields', () => {
  assert.equal(validateClaimOptions().concurrency, 100);
  assert.equal(validateClaimOptions().connectionsPerSecond, 100);
  for (const options of [{ concurrency: 0 }, { concurrency: 2147483648 }, { connectionsPerSecond: -1 }, { overallTimeout: Infinity }, { maxAttempts: 0 }, { allowPrivate: true }]) assert.throws(() => validateClaimOptions(options));
  for (const name of ['connectionsPerSecond', 'concurrency']) {
    for (const value of [257, 1000, 2147483647]) assert.equal(validateClaimOptions({ [name]: value })[name], value);
    for (const value of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, 2147483648]) assert.throws(() => validateClaimOptions({ [name]: value }));
  }
  for (const delta of [{ domain: '127.0.0.1/evil' }, { domain: 'wallet.local' }, { domain: 'EXAMPLE.com' }, { domain: 'localhost' }, { root_certificates_version: 2 }, { signature_algorithms_mask: 0 }, { validation_time: 0 }, { password: 'not permitted' }]) assert.throws(() => validateClaimContext({ ...context(), ...delta }));
  assert.deepEqual(validateClaimContext(context()), context());
});

function fakeSpawn(send) {
  const capture = {};
  return { capture, spawnProcess(command, args, options) {
    Object.assign(capture, { command, args, options });
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.killed = false;
    child.kill = () => { child.killed = true; capture.killed = true; setImmediate(() => child.emit('close', null)); return true; };
    let input = '';
    child.stdin.on('data', (chunk) => { input += chunk.toString(); });
    child.stdin.on('finish', () => { capture.request = JSON.parse(input); send(child, capture.request); });
    return child;
  } };
}
const validResult = (request) => ({ type: 'result', context: request.context, proof: '020100', verified: true, attempts: 1 });
const validProgress = { type: 'progress', attempts: 1, elapsed: 0.1, attemptStats: { validation: 'certificate-proof-v1', completed: 1, recent: [[true, 0.1]] } };

test('proof runner sends only public context via stdin, no shell; requires verified matching result and clean exit', async () => {
  const fixture = fakeSpawn((child, request) => {
    child.stdout.write(`${JSON.stringify(validProgress)}\n`);
    child.stdout.write(`${JSON.stringify(validResult(request))}\n`);
    child.emit('close', 0);
  });
  const runner = createProofRunner({ ...fixture, helper: { command: '/private/helper', args: [] } });
  assert.equal(await runner(context()), '020100');
  assert.deepEqual(fixture.capture.args, ['--require-rsa-exponent-64']);
  assert.equal(fixture.capture.options.shell, false);
  assert.equal(fixture.capture.options.env.PYTHONPATH, undefined);
  assert.equal(fixture.capture.options.env.CONNECTCOIN_RPC_PASSWORD, undefined);
  assert.deepEqual(Object.keys(fixture.capture.request).sort(), ['context', 'options']);
  assert.equal(fixture.capture.request.context.txid, context().txid);
  assert.equal(fixture.capture.request.options.connectionsPerSecond, 100);
  assert.equal(fixture.capture.request.options.concurrency, 100);
});

test('proof runner appends the required RSA policy after source-helper arguments', async () => {
  const fixture = fakeSpawn((child, request) => {
    child.stdout.write(`${JSON.stringify(validProgress)}\n${JSON.stringify(validResult(request))}\n`);
    child.emit('close', 0);
  });
  const args = ['-I', 'claims_bridge.py'];
  assert.equal(await createProofRunner({ ...fixture, helper: { command: 'python', args } })(context()), '020100');
  assert.deepEqual(fixture.capture.args, ['-I', 'claims_bridge.py', '--require-rsa-exponent-64']);
  assert.deepEqual(args, ['-I', 'claims_bridge.py'], 'do not mutate shared helper arguments');
});

test('proof runner rejects legacy helper flag errors with rebuild guidance and no fallback', async () => {
  let calls = 0;
  let progress = 0;
  const fixture = fakeSpawn(child => {
    calls++;
    child.stdout.write('{"type":"error","message":"unknown helper arguments"}\n');
    child.emit('close', 1);
  });
  const runner = createProofRunner({ ...fixture, helper: { command: 'legacy-helper' } });
  await assert.rejects(runner(context(), { onProgress: () => { progress++; } }), /RSA public-exponent limit.*npm run build:claims/);
  assert.deepEqual(fixture.capture.args, ['--require-rsa-exponent-64']);
  assert.equal(calls, 1);
  assert.equal(progress, 0);
});

test('proof runner rejects tampered contexts, oversized frames, unknown messages, partial output, and nonzero exit', async () => {
  const cases = [
    (request) => `${JSON.stringify({ ...validResult(request), context: { ...request.context, txid: '03'.repeat(32) } })}\n`,
    (request) => `${JSON.stringify({ ...validResult(request), verified: false })}\n`,
    () => 'x'.repeat(170000),
    () => '{"type":"please-sign","privateKey":true}\n',
    (request) => JSON.stringify(validResult(request)),
  ];
  for (const makeResponse of cases) {
    const fixture = fakeSpawn((child, request) => { child.stdout.write(`${JSON.stringify(validProgress)}\n${makeResponse(request)}`); setImmediate(() => child.emit('close', 0)); });
    await assert.rejects(createProofRunner({ ...fixture, helper: { command: 'test' } })(context()));
  }
  const fixture = fakeSpawn((child, request) => { child.stdout.write(`${JSON.stringify(validProgress)}\n${JSON.stringify(validResult(request))}\n`); child.emit('close', 1); });
  await assert.rejects(createProofRunner({ ...fixture, helper: { command: 'test' } })(context()));
});

test('aborting a TLS search terminates its helper and rejects after exit', async () => {
  const fixture = fakeSpawn(() => {});
  const abort = new AbortController();
  const promise = createProofRunner({ ...fixture, helper: { command: 'test' } })(context(), { signal: abort.signal });
  abort.abort();
  await assert.rejects(promise, { name: 'AbortError' });
  assert.equal(fixture.capture.killed, true);
});

test('engine is opt-in, deduplicates bounties, preserves prepared txid, and submits once', async () => {
  let prepares = 0;
  let submits = 0;
  const engine = new ClaimsEngine({
    isUnlocked: () => true,
    prepare: async (item) => { prepares++; return { context: context(), item, immutableTransaction: 'fixed' }; },
    generateProof: async (ctx) => { assert.equal(ctx.txid, context().txid); assert.notEqual(ctx.txid, bounty().txid); return '020100'; },
    submit: async (prepared, proof) => { assert.equal(prepared.immutableTransaction, 'fixed'); assert.equal(proof, '020100'); submits++; return prepared.context.txid; },
  });
  assert.equal(engine.enqueue([bounty(), bounty(), { ...bounty(1), status: 'spent' }]), 1);
  await tick();
  assert.equal(prepares, 0);
  engine.start();
  await until(() => engine.snapshot().completed === 1);
  await engine.stop();
  assert.equal(submits, 1);
  assert.equal(engine.enqueue([bounty()]), 0);
});

test('wallet lock during concurrent generation never submits found proofs', async t => {
  let unlocked = true;
  const proofs = [];
  let submitted = false;
  const engine = new ClaimsEngine({ options: { concurrency: 3, connectionsPerSecond: 256 }, isUnlocked: () => unlocked,
    prepare: async () => ({ context: context() }), generateProof: () => new Promise(resolve => proofs.push(resolve)),
    submit: async () => { submitted = true; } });
  t.after(async () => { const stopped = engine.stop(); for (const resolve of proofs) resolve('020100'); await stopped; });
  engine.enqueue([bounty()]);
  engine.start();
  await until(() => proofs.length === 3);
  unlocked = false;
  for (const resolve of proofs) resolve('020100');
  await until(() => !engine.running);
  assert.equal(submitted, false);
  assert.equal(engine.enabled, false);
  await engine.stop();
});

test('stop aborts every concurrent worker and forbids restart until all cleanup finishes', async t => {
  let started = 0;
  const releases = [];
  let submitted = false;
  const engine = new ClaimsEngine({ options: { concurrency: 3, connectionsPerSecond: 256 }, isUnlocked: () => true,
    prepare: async () => ({ context: context() }), generateProof: (_, { signal }) => new Promise((resolve, reject) => {
      started++; signal.addEventListener('abort', () => releases.push(() => reject(Object.assign(new Error('cancelled'), { name: 'AbortError' }))), { once: true });
    }), submit: async () => { submitted = true; } });
  t.after(async () => { const stopped = engine.stop(); for (const release of releases) release(); await stopped; });
  engine.enqueue([bounty()]); engine.start();
  await until(() => started === 3);
  const stopped = engine.stop();
  assert.equal(releases.length, 3);
  let settled = false;
  void stopped.then(() => { settled = true; });
  // Releasing only the last mock used to leave earlier concurrent calls stuck.
  releases.at(-1)();
  await tick();
  assert.equal(settled, false);
  assert.throws(() => engine.start(), /previous claims worker/);
  for (const release of releases) release();
  await stopped;
  assert.equal(submitted, false);
  assert.equal(engine.running, null);
});

test('bounded queue, backoff and unavailable bounties avoid flooding and stale broadcasts', async () => {
  let attempts = 0;
  const engine = new ClaimsEngine({ isUnlocked: () => true, maxQueue: 2, retryDelayMs: 300000, randomIndex: () => 0, prepare: async () => { attempts++; throw new Error('bounty unavailable'); }, generateProof: async () => { throw new Error('must not generate'); }, submit: async () => { throw new Error('must not submit'); } });
  assert.equal(engine.enqueue([bounty(), bounty(1), bounty(2)]), 2);
  engine.start();
  await until(() => attempts === 2 && !engine.running);
  await tick();
  assert.equal(attempts, 2);
  engine.remove(bounty().txid, 0);
  assert.equal(engine.snapshot().queued, 1);
  await engine.stop();
  engine.setOptions({ connectionsPerSecond: 100, concurrency: 100 });
  assert.equal(engine.snapshot().options.connectionsPerSecond, 100);
});

test('locked wallet cannot start or submit queued claims', () => {
  const engine = new ClaimsEngine({ isUnlocked: () => false, prepare: async () => {}, submit: async () => {} });
  engine.enqueue([bounty()]);
  assert.throws(() => engine.start(), /Unlock/);
  assert.equal(engine.enabled, false);
});

test('discovery suspension preserves opt-in but prevents queued work until a complete snapshot', async () => {
  let prepared = 0;
  const engine = new ClaimsEngine({ isUnlocked: () => true, prepare: async () => { prepared++; return { context: context() }; }, generateProof: async () => '020100', submit: async () => context().txid });
  await engine.suspend();
  engine.enqueue([bounty()]); engine.start();
  await tick();
  assert.equal(engine.enabled, true);
  assert.equal(prepared, 0);
  engine.resume();
  await until(() => engine.snapshot().completed === 1);
  await engine.suspend(); await engine.stop(); engine.resume();
  engine.enqueue([bounty(1)]);
  await tick();
  assert.equal(prepared, 1);
  assert.equal(engine.enabled, false);
});

test('only explicit recognized submit rejections are classified as diagnostic notices', async () => {
  const cases = [
    ...[-22, -25, -26, -8].map(node_code => ({ fields: { code: -32020, data: { node_code } }, recoverable: true })),
    ...[-27, -99, 0, 999, undefined, null, '-26', NaN, Infinity].map(node_code => ({ fields: { code: -32020, data: { node_code } }, recoverable: false })),
    { fields: { code: '-32020', data: { node_code: -26 } }, recoverable: false },
    { fields: { code: -32020, data: { node_code: -26 }, unknownOutcome: true }, recoverable: false },
    { fields: { code: -32020, data: { node_code: -26 }, unknownOutcome: 'unknown' }, recoverable: false },
    { fields: { code: -32029 }, recoverable: false },
    { fields: {}, recoverable: false },
  ];
  for (const stage of ['prepare', 'proof', 'submit']) for (const { fields, recoverable } of cases) {
    const failure = Object.assign(new Error('The node rejected this claim. Its bounty or proof may no longer be valid.'), fields);
    const engine = new ClaimsEngine({
      isUnlocked: () => true, retryDelayMs: 300000,
      prepare: async () => { if (stage === 'prepare') throw failure; return { context: context() }; },
      generateProof: async () => { if (stage === 'proof') throw failure; return '020100'; },
      submit: async () => { throw failure; },
    });
    assert.equal(engine.snapshot().lastErrorDiagnostic, false);
    engine.enqueue([bounty()]); engine.start();
    try {
      await until(() => !!engine.snapshot().lastError);
      assert.equal(engine.snapshot().lastErrorDiagnostic, stage === 'submit' && recoverable,
        `${stage}, node ${String(fields.data?.node_code)}, unknown ${String(fields.unknownOutcome)}`);
      assert.equal(engine.snapshot().lastError, failure.message);
    } finally { await engine.stop(); }
  }
});

test('diagnostic classification clears with its last error when the next claim begins', async () => {
  const observed = [];
  const engine = new ClaimsEngine({
    isUnlocked: () => true, retryDelayMs: 300000,
    prepare: async item => ({ context: context(), item }), generateProof: async () => '020100',
    submit: async prepared => {
      if (prepared.item.vout === 0) throw Object.assign(new Error('Known node rejection'), { code: -32020, data: { node_code: -26 } });
      return context().txid;
    },
    onState: state => observed.push(state),
  });
  engine.enqueue([bounty()]); engine.start();
  await until(() => engine.snapshot().lastErrorDiagnostic && !engine.running);
  engine.enqueue([bounty(1)]);
  await until(() => engine.snapshot().completed === 1 && !engine.running);
  assert.equal(engine.snapshot().lastError, null);
  assert.equal(engine.snapshot().lastErrorDiagnostic, false);
  assert.ok(observed.some(state => state.lastErrorDiagnostic));
  assert.ok(observed.filter(state => state.lastError === null).every(state => state.lastErrorDiagnostic === false));
  await engine.stop();
});
