import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { ConnectionPool, validateConnectionOptions } from '../src/core/claim-pool.mjs';
import { diagnosticError } from '../src/core/diagnostics.mjs';

const context = (domain = 'example.com') => ({ domain, txid: '01'.repeat(32), input_index: 0,
  connection_work_target: 'f'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7, validation_time: 1800000000 });
const bountyId = `${'02'.repeat(32)}:0`;
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture(t, onCommand = () => {}, options = {}) {
  const commands = [], children = [], spawns = [];
  const spawnProcess = (command, args, opts) => {
    spawns.push({ command, args, options: opts });
    const child = new EventEmitter();
    child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.killed = false;
    child.kill = () => { child.killed = true; setImmediate(() => child.emit('close', null)); return true; };
    child.send = value => child.stdout.write(JSON.stringify(value) + '\n');
    let buffer = '';
    child.stdin.on('data', data => {
      buffer += data.toString(); let end;
      while ((end = buffer.indexOf('\n')) !== -1) {
        const message = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        commands.push(message);
        if (message.type === 'start') {
          if (options.autoReady !== false) queueMicrotask(() => child.send({ type: 'ready', protocol: 4, roots: 1, security: { rsaPublicExponentMaxBits: 64 } }));
        }
        else if (message.type === 'shutdown') { if (options.autoClose !== false) setImmediate(() => child.emit('close', 0)); }
        else onCommand(message, child);
      }
    });
    children.push(child); return child;
  };
  const pool = new ConnectionPool({ helper: { command: 'isolated-protocol4-helper', args: ['mock'] }, spawnProcess, ...options });
  t.after(() => pool.close());
  return { pool, commands, children, spawns };
}

function observation(command, overrides = {}) {
  const value = { id: command.id, context: command.context, started: true, captured: true, seconds: 0.1,
    cancelled: false, successfulConnections: (BigInt(command.successfulConnections) + 1n).toString(), ...overrides };
  // Test captures are valid unless explicitly overridden by a validation test.
  return { ...value, validationPassed: value.started && !value.cancelled ? value.captured : null, ...overrides };
}
function complete(command, child, overrides = {}) {
  const value = observation(command, overrides);
  child.send({ type: 'started', id: command.id });
  child.send({ type: 'capture', ...value });
  child.send({ type: 'attempt', ...value, proof: '020100', verified: true });
}

test('exhausted capture budget is a no-start result, not an attempt or failed observation', async t => {
  const { pool } = fixture(t, (command, child) => child.send({ type: 'attempt', ...observation(command, {
    started: false, captured: false, seconds: 0, successfulConnections: command.successfulConnections,
  }), proof: null, verified: false, blocked: 'budget' }));
  await pool.start({});
  let starts = 0, captures = 0;
  const result = await pool.attempt(context(), { bountyId, onStarted: () => starts++, onCapture: () => captures++ });
  assert.equal(result.blocked, 'budget'); assert.equal(result.retryAfterMs, undefined);
  assert.equal(result.validationPassed, null); assert.equal(starts, 0); assert.equal(captures, 0);
});

for (const patch of [{ retryAfterMs: 0 }, { retryAfterMs: 60001 }, { retryAfterMs: '2000' }, { retryAfterMs: 1.5 },
  { blocked: 'endpoint' }, { blocked: 'unknown' }, { blocked: 'endpoint', retryAfterMs: 2000 },
  { validationPassed: false }, { seconds: 1 }, { proof: '020100', verified: true }]) {
  test(`rejects unsupported endpoint pauses and malformed budget outcomes ${JSON.stringify(patch)}`, async t => {
    const { pool } = fixture(t, (command, child) => child.send({ type: 'attempt', ...observation(command, {
      started: false, captured: false, seconds: 0, successfulConnections: command.successfulConnections,
    }), proof: null, verified: false, blocked: 'budget', ...patch }));
    await pool.start({});
    await assert.rejects(pool.attempt(context(), { bountyId }), error => error.helperFatal === true);
  });
}

test('connection-only settings reject lifetime batch options and invalid global limits', () => {
  assert.deepEqual(validateConnectionOptions(), { connectionsPerSecond: 100, concurrency: 100 });
  for (const input of [null, [], { maxAttempts: 1 }, { overallTimeout: 1 }]) assert.throws(() => validateConnectionOptions(input));
  for (const name of ['concurrency', 'connectionsPerSecond']) {
    for (const value of [1, 257, 512, 1000, 2147483647]) assert.equal(validateConnectionOptions({ [name]: value })[name], value);
    for (const value of [0, -1, 1.5, NaN, Infinity, 2147483648, Number.MAX_SAFE_INTEGER + 1, '1000', null]) {
      assert.throws(() => validateConnectionOptions({ [name]: value }), /Connection limits/);
    }
  }
});

test('large configured limits allocate no requests until work arrives', async t => {
  const { pool, commands, spawns } = fixture(t);
  await pool.start({ connectionsPerSecond: 2147483647, concurrency: 2147483647 });
  assert.equal(spawns.length, 1);
  assert.equal(pool.requests.size, 0);
  assert.equal(pool.sequence, 0);
  assert.deepEqual(commands, [{ type: 'start', protocol: 4, options: { connectionsPerSecond: 2147483647, concurrency: 2147483647 } }]);
});

test('socket pacing before the start acknowledgement does not consume the capture deadline', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { pool, commands, children } = fixture(t);
  await pool.start({ connectionsPerSecond: 1, concurrency: 1000 });
  const pending = pool.attempt(context(), { bountyId });
  const outcome = assert.rejects(pending, /deadline/);
  t.mock.timers.tick(60000);
  assert.equal(pool.failure, undefined);
  assert.equal(pool.requests.size, 1);
  const command = commands.find(row => row.type === 'attempt');
  children[0].send({ type: 'started', id: command.id });
  t.mock.timers.tick(44999);
  assert.equal(pool.failure, undefined);
  t.mock.timers.tick(1);
  await outcome;
  assert.equal(pool.requests.size, 0);
  assert.equal(children[0].killed, true);
});

test('a helper stuck before its socket-start acknowledgement fails after pacing allowance and watchdog', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { pool, children } = fixture(t);
  await pool.start({ connectionsPerSecond: 1, concurrency: 1000 });
  const outcome = assert.rejects(pool.attempt(context(), { bountyId }), /start acknowledgement.*deadline/);
  t.mock.timers.tick(60999);
  assert.equal(pool.failure, undefined);
  t.mock.timers.tick(1);
  await outcome;
  assert.equal(pool.requests.size, 0);
  assert.equal(pool.pendingStarts, 0);
  assert.equal(children[0].killed, true);
});

test('low-rate admissions include the queued pacing delay and reset the deadline independently on start', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { pool, commands, children } = fixture(t);
  await pool.start({ connectionsPerSecond: 1, concurrency: 1000 });
  const pending = [pool.attempt(context(), { bountyId }), pool.attempt(context(), { bountyId })];
  const attempts = commands.filter(row => row.type === 'attempt');
  t.mock.timers.tick(60000);
  complete(attempts[0], children[0]);
  t.mock.timers.tick(1999);
  assert.equal(pool.failure, undefined, 'the second request receives two seconds of pacing allowance');
  children[0].send({ type: 'started', id: attempts[1].id });
  t.mock.timers.tick(44999);
  assert.equal(pool.failure, undefined, 'socket start replaces rather than inherits the admission watchdog');
  const value = observation(attempts[1]);
  children[0].send({ type: 'capture', ...value });
  children[0].send({ type: 'attempt', ...value, proof: '020100', verified: true });
  await Promise.all(pending);
  assert.equal(pool.pendingStarts, 0);
  t.mock.timers.tick(60000);
  assert.equal(pool.failure, undefined, 'completed requests leave no watchdog behind');
});

test('DNS keeps its independent deadline before any socket start', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { pool } = fixture(t);
  await pool.start({ concurrency: 1000 });
  const outcome = assert.rejects(pool.resolve('example.com'), /deadline/);
  t.mock.timers.tick(45000);
  await outcome;
  assert.equal(pool.requests.size, 0);
});

test('more than 512 live requests complete within configured capacity without stopping the helper', async t => {
  const { pool, commands, children } = fixture(t);
  await pool.start({ connectionsPerSecond: 1000, concurrency: 600 });
  const pending = Array.from({ length: 600 }, () => pool.attempt(context(), { bountyId }));
  const dns = [pool.resolve('example.com'), pool.resolve('other.example')];
  assert.equal(pool.requests.size, 602);
  await assert.rejects(pool.resolve('excess.example'), /capacity/);
  assert.equal(pool.failure, undefined, 'the request bound is not a helper crash');
  for (const command of commands.filter(row => row.type === 'attempt')) complete(command, children[0]);
  for (const command of commands.filter(row => row.type === 'resolve')) children[0].send({ type: 'resolved', id: command.id, ok: true });
  assert.equal((await Promise.all(pending)).length, 600);
  await Promise.all(dns);
  assert.equal(pool.requests.size, 0);
  assert.equal(children[0].killed, false);
});

for (const security of [undefined, null, {}, { rsaPublicExponentMaxBits: '64' }, { rsaPublicExponentMaxBits: 63 }, { rsaPublicExponentMaxBits: 65 }]) {
  test(`persistent helper rejects missing or incompatible RSA policy ${JSON.stringify(security)}`, async t => {
    const { pool, children, commands } = fixture(t, () => {}, { autoReady: false });
    const starting = assert.rejects(pool.start({}), error => error.helperFatal === true && /npm run build:claims/.test(error.message));
    children[0].send({ type: 'ready', protocol: 4, roots: 1, security });
    await starting;
    await assert.rejects(pool.resolve('example.com'), /npm run build:claims/);
    assert.equal(pool.started, undefined);
    assert.equal(children[0].killed, true);
    assert.deepEqual(commands.map(command => command.type), ['start'], 'no DNS or TLS request reaches a stale helper');
  });
}

test('one persistent helper serves several domains and proofs with monotonic request identities', async t => {
  const { pool, commands, spawns } = fixture(t, (command, child) => {
    if (command.type === 'resolve') child.send({ type: 'resolved', id: command.id, ok: true });
    if (command.type === 'attempt') complete(command, child);
  });
  await pool.start({ connectionsPerSecond: 20, concurrency: 3 });
  assert.equal(pool.pacesStarts, true, 'protocol 4 paces actual TCP starts in the persistent helper');
  await pool.start({ connectionsPerSecond: 20, concurrency: 3 });
  await Promise.all(['example.com', 'other.example'].map(domain => pool.resolve(domain)));
  const events = [];
  const values = await Promise.all(['example.com', 'other.example'].map(domain => pool.attempt(context(domain), {
    bountyId, successfulConnections: 7n, onStarted: () => events.push('start'), onCapture: row => events.push(row.captured ? 'capture' : 'failed'),
  })));
  assert.equal(spawns.length, 1); assert.deepEqual(spawns[0].args, ['mock', '--service']);
  assert.equal(spawns[0].options.shell, false); assert.equal(spawns[0].options.windowsHide, true);
  assert.equal(commands.filter(row => row.type === 'start').length, 1);
  assert.deepEqual(commands.filter(row => row.id !== undefined).map(row => row.id), [1, 2, 3, 4]);
  assert.deepEqual(events, ['start', 'capture', 'start', 'capture']);
  assert.ok(values.every(value => value.proof === '020100' && value.successfulConnections === '8'));
  for (const command of commands.filter(row => row.type === 'attempt')) {
    assert.deepEqual(Object.keys(command.context).sort(), Object.keys(context()).sort());
    assert.equal(command.successfulConnections, '7');
  }
  assert.equal(pool.requests.size, 0);
});

test('capture is delivered early but a valid hash miss is observed only after verification', async t => {
  let pending, child, captures = 0, settled = false;
  const validations = [];
  const { pool } = fixture(t, (command, current) => { pending = command; child = current; });
  await pool.start({});
  const result = pool.attempt(context(), { bountyId, onCapture: value => { assert.equal(value.captured, true); captures++; },
    onResult: value => validations.push(value.validationPassed) }).then(value => { settled = true; return value; });
  child.send({ type: 'started', id: pending.id });
  child.send({ type: 'capture', ...observation(pending) });
  await tick(); assert.equal(captures, 1); assert.equal(settled, false);
  assert.deepEqual(validations, []);
  child.send({ type: 'attempt', ...observation(pending), proof: null, verified: false });
  assert.equal((await result).captured, true); assert.equal(captures, 1);
  assert.deepEqual(validations, [true]);
});

test('protocol 3 helpers fail closed before attempting DNS or TLS', async t => {
  const { pool, children, commands } = fixture(t, () => {}, { autoReady: false });
  const rejected = assert.rejects(pool.start({}), /protocol 4/);
  children[0].send({ type: 'ready', protocol: 3, roots: 1, security: { rsaPublicExponentMaxBits: 64 } });
  await rejected;
  assert.deepEqual(commands.map(value => value.type), ['start']);
});

for (const validationPassed of [true, false, null]) test(`late cancellation preserves the conclusive validation outcome ${validationPassed}`, async t => {
  let pending, child;
  const { pool } = fixture(t, (command, current) => { if (command.type === 'attempt') { pending = command; child = current; } });
  await pool.start({});
  const abort = new AbortController(), observed = [];
  const rejected = assert.rejects(pool.attempt(context(), { bountyId, signal: abort.signal,
    onResult: value => observed.push(value.validationPassed) }), error => error.name === 'AbortError');
  child.send({ type: 'started', id: pending.id });
  child.send({ type: 'capture', ...observation(pending) });
  abort.abort();
  child.send({ type: 'attempt', ...observation(pending, { cancelled: true, validationPassed }), proof: null, verified: false });
  await rejected;
  assert.deepEqual(observed, [validationPassed]);
  assert.equal(pool.failure, undefined);
});

test('budget rejection before TCP does not invent a capture or start notification', async t => {
  const { pool } = fixture(t, (command, child) => child.send({ type: 'attempt', ...observation(command, {
    started: false, captured: false, seconds: 0, successfulConnections: command.successfulConnections,
  }), proof: null, verified: false, blocked: 'budget' }));
  await pool.start({});
  let events = 0;
  const result = await pool.attempt(context(), { bountyId, successfulConnections: 3n, onStarted: () => events++, onCapture: () => events++ });
  assert.equal(result.blocked, 'budget'); assert.equal(events, 0);
});

for (const [message, expected, category] of [
  ['TLS connection timed out', 'TLS connection timed out', 'tls-timeout'],
  ['TLS capture or proof validation failed', 'TLS capture or proof validation failed', 'proof-failed'],
  ['TLS capture cancelled', 'TLS capture cancelled', 'unknown'],
  ['Public DNS resolution is required', 'Public DNS resolution is required', 'unknown'],
  ['private-peer-details: timed out', 'TLS capture or proof validation failed', 'proof-failed'],
  [{ private: 'private-peer-details' }, 'TLS capture or proof validation failed', 'proof-failed'],
]) test(`attempt descriptions retain only allowlisted text: ${typeof message === 'string' ? message : 'non-string'}`, async t => {
  const { pool, children } = fixture(t, (command, child) => {
    const value = observation(command, { captured: false, successfulConnections: command.successfulConnections });
    child.send({ type: 'started', id: command.id });
    child.send({ type: 'capture', ...value });
    child.send({ type: 'attempt', ...value, proof: null, verified: false, message });
  });
  await pool.start({});
  const result = await pool.attempt(context(), { bountyId, successfulConnections: 2n });
  assert.equal(result.message, expected);
  assert.equal(diagnosticError(new Error(result.message)).category, category);
  assert.equal(result.successfulConnections, '2');
  assert.equal(result.cancelled, false);
  assert.ok(!JSON.stringify(result).includes('private-peer-details'));
  assert.equal(pool.failure, undefined);
  assert.equal(children[0].killed, false);
  assert.equal(pool.requests.size, 0);
});

test('fatal helper error frames never expose arbitrary message text', async t => {
  const { pool, children } = fixture(t, (_command, child) => child.send({ type: 'error', message: 'private-peer-details: timed out' }));
  await pool.start({});
  await assert.rejects(pool.attempt(context(), { bountyId }), error => {
    assert.equal(error.message, 'Claims helper failed');
    assert.equal(diagnosticError(error).category, 'helper-failed');
    return error.helperFatal === true;
  });
  assert.equal(children[0].killed, true);
});

test('cancellation sends only its request ID and waits for the terminal acknowledgement', async t => {
  const pending = new Map();
  const { pool, commands, children } = fixture(t, command => { if (command.type === 'attempt') pending.set(command.id, command); });
  await pool.start({});
  const abort = new AbortController();
  const cancelled = pool.attempt(context(), { bountyId, signal: abort.signal });
  const other = pool.attempt(context('other.example'), { bountyId: `${'03'.repeat(32)}:1` });
  const rejected = assert.rejects(cancelled, error => error.name === 'AbortError');
  abort.abort(); assert.equal(pool.requests.size, 2);
  assert.deepEqual(commands.at(-1), { type: 'cancel', id: 1 });
  children[0].send({ type: 'attempt', ...observation(pending.get(1), { started: false, captured: false, cancelled: true, seconds: 0, successfulConnections: '0' }), proof: null, verified: false });
  await rejected; assert.equal(pool.requests.size, 1); assert.equal(children[0].killed, false);
  complete(pending.get(2), children[0]); assert.equal((await other).verified, true);
});

for (const scenario of ['wrong-context', 'unknown-id', 'duplicate-start', 'missing-capture', 'false-verified', 'string-verified', 'missing-verified', 'conflicting-capture', 'missing-counter', 'regressing-counter', 'conflicting-counter', 'nonfinite-duration', 'oversized-proof', 'missing-validation', 'string-validation', 'false-validation', 'null-validation']) {
  test(`persistent helper fails closed for ${scenario}`, async t => {
    const { pool, children } = fixture(t, (command, child) => {
      const value = observation(command);
      if (scenario === 'unknown-id') { child.send({ type: 'started', id: command.id + 100 }); return; }
      child.send({ type: 'started', id: command.id });
      if (scenario === 'duplicate-start') { child.send({ type: 'started', id: command.id }); return; }
      if (scenario !== 'missing-capture') child.send({ type: 'capture', ...value });
      const result = { type: 'attempt', ...value, proof: '020100', verified: true };
      if (scenario === 'wrong-context') result.context = { ...command.context, txid: 'ff'.repeat(32) };
      if (scenario === 'false-verified') result.verified = false;
      if (scenario === 'string-verified') result.verified = 'true';
      if (scenario === 'missing-verified') delete result.verified;
      if (scenario === 'conflicting-capture') result.captured = false;
      if (scenario === 'missing-counter') delete result.successfulConnections;
      if (scenario === 'regressing-counter') result.successfulConnections = '0';
      if (scenario === 'conflicting-counter') result.successfulConnections = '2';
      if (scenario === 'nonfinite-duration') result.seconds = Infinity;
      if (scenario === 'oversized-proof') result.proof = '02' + '11'.repeat(65536);
      if (scenario === 'missing-validation') delete result.validationPassed;
      if (scenario === 'string-validation') result.validationPassed = 'true';
      if (scenario === 'false-validation') result.validationPassed = false;
      if (scenario === 'null-validation') result.validationPassed = null;
      child.send(result);
    });
    await pool.start({});
    await assert.rejects(pool.attempt(context(), { bountyId }), error => error.helperFatal === true);
    assert.equal(children[0].killed, true); assert.equal(pool.requests.size, 0);
  });
}

test('malformed framing rejects every live request and does not leave the helper running', async t => {
  const { pool, children } = fixture(t);
  await pool.start({});
  const requests = [pool.resolve('example.com'), pool.attempt(context(), { bountyId })];
  const observed = Promise.allSettled(requests);
  children[0].stdout.write('{malformed}\n');
  assert.ok((await observed).every(row => row.status === 'rejected' && row.reason.helperFatal));
  assert.equal(pool.requests.size, 0); assert.equal(children[0].killed, true);
});

test('a rejected asynchronous diagnostic callback cannot escape helper failure cleanup', async t => {
  const { pool, children } = fixture(t, () => {}, { onDiagnostic: async () => { throw new Error('mock diagnostic failure'); } });
  await pool.start({});
  const result = assert.rejects(pool.resolve('example.com'));
  children[0].stdout.write('[]\n');
  await result; await tick(); assert.equal(children[0].killed, true);
});

for (const helperReady of [false, true]) {
  for (const [exitCode, signal] of [[0, null], [1, null], [0xc0000005, null], [-1073741819, null], [null, 'SIGTERM']]) {
    test(`an idle helper closing ${helperReady ? 'after' : 'before'} ready records safe status ${exitCode ?? signal}`, async t => {
      const events = [], failures = [];
      const { pool, children, commands } = fixture(t, () => {}, {
        autoReady: helperReady, onDiagnostic: (event, details) => events.push({ event, details }), onFailure: error => failures.push(error),
      });
      const starting = pool.start({});
      const started = helperReady ? starting : assert.rejects(starting, error => error.helperFatal === true);
      if (helperReady) await started;
      children[0].stderr.write('private-helper-traceback-and-profile-path');
      children[0].emit('close', exitCode, signal);
      await started;
      assert.equal(pool.requests.size, 0);
      assert.equal(events.length, 1);
      assert.deepEqual(failures, [pool.failure]);
      assert.equal(events[0].event, 'helper.failed');
      const { details } = events[0];
      assert.equal(details.helperReady, helperReady);
      assert.ok(details.durationMs >= 0 && details.durationMs < 10000);
      assert.equal(details.stderrBytes, Buffer.byteLength('private-helper-traceback-and-profile-path'));
      assert.equal(details.exitCode, exitCode === null ? undefined : exitCode);
      assert.equal(details.signal, signal ?? undefined);
      assert.equal(diagnosticError(details.error).category, 'helper-failed');
      assert.ok(!JSON.stringify(events).includes('private-helper'));
      assert.equal(children[0].killed, false, 'a child that already closed must not be killed again');
      await pool.close();
      assert.equal(commands.some(command => command.type === 'shutdown'), false);
    });
  }
}

test('unexpected helper exit rejects all requests with the same first failure and clears pending work', async t => {
  const events = [], failures = [];
  const { pool, children } = fixture(t, () => {}, {
    onDiagnostic: (event, details) => events.push({ event, details }), onFailure: error => failures.push(error),
  });
  await pool.start({});
  const aborted = new AbortController();
  const pending = Promise.allSettled([
    pool.resolve('example.com', { signal: aborted.signal }), pool.attempt(context(), { bountyId }),
  ]);
  children[0].emit('close', 42, null);
  const results = await pending;
  assert.ok(results.every(row => row.status === 'rejected' && row.reason === pool.failure && row.reason.helperFatal));
  assert.equal(pool.requests.size, 0);
  aborted.abort(); // Its removed handler must not write cancellation to a dead helper.
  assert.equal(events.length, 1);
  assert.deepEqual(failures, [pool.failure]);
  assert.equal(events[0].details.exitCode, 42);
  await assert.rejects(pool.resolve('example.com'), error => error === pool.failure);
});

test('shutdown before ready cancels startup and terminates malformed output without reporting a crash', async t => {
  const events = [], failures = [];
  const { pool, children } = fixture(t, () => {}, {
    autoReady: false, onDiagnostic: (event, details) => events.push({ event, details }), onFailure: error => failures.push(error),
  });
  const starting = assert.rejects(pool.start({}), error => error.name === 'AbortError');
  const stopping = pool.close();
  children[0].stdout.write('{invalid-json}\n');
  children[0].stderr.write('x'.repeat(9000));
  children[0].stdin.emit('error', new Error('late EPIPE'));
  await Promise.all([starting, stopping]);
  assert.equal(pool.failure, undefined);
  assert.equal(children[0].killed, true);
  assert.deepEqual(events, []);
  assert.deepEqual(failures, []);
});

test('a valid ready response racing shutdown cannot revive startup or accept new requests', async t => {
  const { pool, children } = fixture(t, () => {}, { autoReady: false, autoClose: false });
  const starting = assert.rejects(pool.start({}), error => error.name === 'AbortError');
  const stopping = pool.close();
  children[0].send({ type: 'ready', protocol: 4, roots: 1, security: { rsaPublicExponentMaxBits: 64 } });
  await starting;
  await assert.rejects(pool.resolve('example.com'), error => error.name === 'AbortError');
  assert.equal(children[0].killed, false);
  children[0].emit('close', 0); await stopping;
  assert.equal(pool.failure, undefined);
});

test('a successful DNS response after shutdown rejects its request even without a signal', async t => {
  let command;
  const { pool, children } = fixture(t, value => { command = value; }, { autoClose: false });
  await pool.start({});
  const pending = assert.rejects(pool.resolve('example.com'), error => error.name === 'AbortError');
  const stopping = pool.close();
  children[0].send({ type: 'resolved', id: command.id, ok: true });
  await pending;
  assert.equal(pool.requests.size, 0);
  children[0].emit('close', 0); await stopping;
});

for (const validationPassed of [true, false, null]) for (const withSignal of [false, true]) {
  test(`shutdown drains validation ${validationPassed} with ${withSignal ? 'an aborted signal' : 'no signal'}`, async t => {
    let command;
    const { pool, children } = fixture(t, value => { if (value.type === 'attempt') command = value; }, { autoClose: false });
    await pool.start({});
    const abort = new AbortController(), observed = [], captures = [];
    const pending = assert.rejects(pool.attempt(context(), { bountyId,
      ...(withSignal ? { signal: abort.signal } : {}),
      onCapture: value => captures.push(value), onResult: value => observed.push(value),
    }), error => error.name === 'AbortError');
    const child = children[0];
    child.send({ type: 'started', id: command.id });
    child.send({ type: 'capture', ...observation(command) });
    if (withSignal) abort.abort();
    const stopping = pool.close();
    child.send({ type: 'attempt', ...observation(command, { cancelled: true, validationPassed }), proof: null, verified: false });
    await pending;
    assert.equal(observed.length, 1);
    assert.equal(observed[0].validationPassed, validationPassed);
    assert.equal(observed[0].seconds, captures[0].seconds);
    assert.equal(pool.requests.size, 0);
    assert.equal(child.killed, false);
    child.emit('close', 0); await stopping;
    assert.equal(pool.failure, undefined);
  });
}

test('shutdown drains late start and capture frames but never returns a winning proof without a signal', async t => {
  let command, starts = 0, captures = 0;
  const observed = [];
  const { pool, children } = fixture(t, value => { command = value; }, { autoClose: false });
  await pool.start({});
  const pending = assert.rejects(pool.attempt(context(), { bountyId, onStarted: () => starts++,
    onCapture: () => captures++, onResult: value => observed.push(value),
  }), error => error.name === 'AbortError');
  const stopping = pool.close(), child = children[0];
  complete(command, child);
  await pending;
  assert.equal(starts, 1); assert.equal(captures, 1);
  assert.equal(observed.length, 1);
  assert.equal(observed[0].validationPassed, true);
  assert.equal(observed[0].cancelled, true);
  assert.equal(observed[0].proof, null);
  assert.equal(observed[0].verified, false);
  child.emit('close', 0); await stopping;
});

for (const scenario of ['malformed', 'oversized', 'invalid-validation']) {
  test(`shutdown terminates ${scenario} output and discards later validation observations`, async t => {
    let command;
    const observed = [], events = [], failures = [];
    const { pool, children } = fixture(t, value => { command = value; }, {
      autoClose: false, onDiagnostic: (...args) => events.push(args), onFailure: error => failures.push(error),
    });
    await pool.start({});
    const pending = assert.rejects(pool.attempt(context(), { bountyId, onResult: value => observed.push(value) }),
      error => error.name === 'AbortError');
    const child = children[0];
    child.send({ type: 'started', id: command.id });
    child.send({ type: 'capture', ...observation(command) });
    const stopping = pool.close();
    if (scenario === 'malformed') child.stdout.write('{invalid-json}\n' + JSON.stringify({
      type: 'attempt', ...observation(command), proof: null, verified: false,
    }) + '\n');
    else if (scenario === 'oversized') child.stdout.write('x'.repeat(160 * 1024 + 1));
    else child.send({ type: 'attempt', ...observation(command), validationPassed: 'true', proof: null, verified: false });
    assert.equal(child.killed, true);
    child.send({ type: 'attempt', ...observation(command), proof: null, verified: false });
    await Promise.all([pending, stopping]);
    assert.equal(pool.requests.size, 0);
    assert.deepEqual(observed, []); assert.deepEqual(events, []); assert.deepEqual(failures, []);
  });
}

test('shutdown retains its two-second termination deadline while draining outstanding results', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { pool, children } = fixture(t, () => {}, { autoClose: false });
  await pool.start({});
  const pending = assert.rejects(pool.attempt(context(), { bountyId }), error => error.name === 'AbortError');
  const stopping = pool.close();
  t.mock.timers.tick(1999); assert.equal(children[0].killed, false);
  t.mock.timers.tick(1); assert.equal(children[0].killed, true);
  await Promise.all([pending, stopping]);
  assert.equal(pool.requests.size, 0);
});

test('shutdown after ready cancels pending work without reporting a crash', async t => {
  const events = [], failures = [];
  const { pool, children } = fixture(t, () => {}, {
    onDiagnostic: (event, details) => events.push({ event, details }), onFailure: error => failures.push(error),
  });
  await pool.start({});
  const pending = assert.rejects(pool.resolve('example.com'), error => error.name === 'AbortError');
  await pool.close();
  await pending;
  assert.equal(pool.requests.size, 0);
  assert.equal(children[0].killed, false);
  assert.deepEqual(events, []);
  assert.deepEqual(failures, []);
});

test('protocol failure keeps its original diagnosis when process teardown emits more errors', async t => {
  const events = [], failures = [];
  const { pool, children } = fixture(t, () => {}, {
    onDiagnostic: (event, details) => events.push({ event, details }), onFailure: error => failures.push(error),
  });
  await pool.start({});
  const pending = assert.rejects(pool.resolve('example.com'), /Malformed claims helper response/);
  children[0].stdout.write('[]\n');
  const first = pool.failure;
  children[0].stderr.write('x'.repeat(9000));
  children[0].stdin.emit('error', new Error('late EPIPE'));
  await pending;
  await tick();
  assert.equal(pool.failure, first);
  assert.equal(events.length, 1);
  assert.deepEqual(failures, [first]);
  assert.equal(events[0].details.error, first);
  assert.equal(diagnosticError(first).category, 'helper-response');
  assert.equal(children[0].killed, true);
});

test('arbitrary process status values never enter the helper diagnostic callback', async t => {
  const events = [];
  const { pool, children } = fixture(t, () => {}, { onDiagnostic: (event, details) => events.push({ event, details }) });
  await pool.start({});
  children[0].emit('close', 'private-exit-text', 'private-signal-text');
  assert.equal(events.length, 1);
  assert.equal(events[0].details.exitCode, undefined);
  assert.equal(events[0].details.signal, undefined);
  assert.ok(!JSON.stringify(events).includes('private-'));
});

test('a closed pool cannot restart a helper or leave its startup promise pending', async t => {
  const { pool, spawns } = fixture(t);
  await pool.close();
  await assert.rejects(pool.start({}), error => error.name === 'AbortError');
  assert.deepEqual(spawns, []);
});

for (const asynchronous of [false, true]) test(`a ${asynchronous ? 'rejecting' : 'throwing'} failure callback cannot escape helper cleanup`, async t => {
  const onFailure = asynchronous ? async () => { throw new Error('callback unavailable'); } : () => { throw new Error('callback unavailable'); };
  const { pool, children } = fixture(t, () => {}, { onFailure });
  await pool.start({});
  const pending = assert.rejects(pool.resolve('example.com'), error => error.helperFatal === true);
  children[0].stdout.write('[]\n');
  await pending;
  await tick();
  assert.equal(pool.requests.size, 0);
  assert.equal(children[0].killed, true);
  await pool.close();
});
