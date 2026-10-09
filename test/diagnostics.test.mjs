import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, readdir, rm, stat, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, isAbsolute, resolve, dirname, basename } from 'node:path';
import { DiagnosticLog, diagnosticError, diagnosticProcessExit } from '../src/core/diagnostics.mjs';
import { MAX_CONNECTION_LIMIT } from '../src/core/connection-limits.mjs';

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'connectwallet-diagnostics-'));
  t.after(() => {
    const absolute = resolve(directory);
    assert.equal(dirname(absolute), resolve(tmpdir()));
    assert.ok(basename(absolute).startsWith('connectwallet-diagnostics-'));
    return rm(absolute, { recursive: true, force: true });
  });
  return directory;
}
async function rows(file) { return (await readFile(file, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line)); }

test('startup timing logs retain only safe numeric timing metadata', async t => {
  const log = new DiagnosticLog({ directory: await fixture(t) });
  const events = ['wallet.unlock_started', 'wallet.unlocked', 'wallet.snapshot_ready', 'wallet.render_ready'];
  for (const event of events) log.record(event, { stage: 'lifecycle', runId: 1, durationMs: 123.5,
    password: 'PRIVATE-CANARY', address: 'PRIVATE-CANARY', balance: 'PRIVATE-CANARY', history: ['PRIVATE-CANARY'] });
  await log.flush();
  const stored = await rows(log.snapshot().file);
  assert.deepEqual(stored.map(row => row.event), events);
  for (const row of stored) assert.deepEqual(row.details, { stage: 'lifecycle', runId: 1, durationMs: 123.5 });
  assert.equal(JSON.stringify(stored).includes('PRIVATE-CANARY'), false);
});

test('claims diagnostics retain high concurrency without widening unrelated metadata bounds', async t => {
  const log = new DiagnosticLog({ directory: await fixture(t) });
  const valid = [0, 257, 400, 1000, MAX_CONNECTION_LIMIT];
  for (const captureActive of valid) log.record('claims.progress', { captureActive, prepareActive: 4, dnsActive: 2, submitActive: 4 });
  for (const captureActive of [-1, 0.5, MAX_CONNECTION_LIMIT + 1, NaN, Infinity, '1000']) {
    log.record('claims.progress', { captureActive, prepareActive: 5, dnsActive: 3, submitActive: 5 });
  }
  await log.flush();
  const stored = await rows(log.snapshot().file);
  assert.deepEqual(stored.slice(0, valid.length).map(row => row.details), valid.map(captureActive => ({
    captureActive, prepareActive: 4, dnsActive: 2, submitActive: 4,
  })));
  for (const row of stored.slice(valid.length)) assert.deepEqual(row.details, {});
});

test('helper DNS, blocked destination and target exhaustion retain safe distinct reasons', () => {
  for (const [message, category] of [
    ['DNS resolution failed for private-canary.example: system diagnostic', 'dns'],
    ['domain resolved to no permitted TCP addresses: private-canary', 'destination-blocked'],
    ['no proof met the target in 1000 attempts; last error: private-canary', 'target-not-met'],
    ['generation timed out after 1000 completed attempts', 'timeout'],
    ['TLS capture or proof validation failed', 'proof-failed'],
  ]) {
    const error = diagnosticError(new Error(message));
    assert.equal(error.category, category);
    assert.ok(!JSON.stringify(error).includes('private-canary'));
  }
});

test('only the exact allowlisted TLS attempt timeout receives its precise description', () => {
  const message = 'One TCP/TLS connection attempt timed out before producing a usable TLS capture. No claim transaction was broadcast from this attempt.';
  assert.deepEqual(diagnosticError(new Error('TLS connection timed out')), { category: 'tls-timeout', message });
  assert.deepEqual(diagnosticError(new Error('private wrapper', { cause: new Error('TLS connection timed out') })), { category: 'tls-timeout', message });
  for (const error of [
    new Error('RPC request timed out.'),
    new Error('TLS connection timed out: private endpoint'),
    new Error('tls connection timed out'),
    new Error('TLS connection timed out.'),
    new Error('TLS handshake exceeded the connection timeout'),
    { message: 'Claims helper request timed out after 45000 ms', helperFatal: true },
    { message: 'Claims helper startup timed out; update or rebuild the helper', helperFatal: true },
    { message: 'TLS connection timed out', helperFatal: true },
    { code: 'ETIMEDOUT' },
  ]) {
    assert.equal(diagnosticError(error).category, 'timeout');
  }
  assert.equal(diagnosticError({ message: 'helper private text', helperFatal: true }).category, 'helper-failed');
  assert.equal(diagnosticError({ message: 'wrapper', helperFatal: true, cause: new Error('TLS connection timed out') }).category, 'helper-failed');
});

test('broadcast uncertainty and cancellation retain precedence over the TLS timeout message', () => {
  for (const metadata of [{ name: 'AbortError' }, { code: 'ABORT_ERR' }]) {
    assert.equal(diagnosticError({ message: 'TLS connection timed out', ...metadata }).category, 'cancelled');
    assert.equal(diagnosticError({ message: 'TLS connection timed out', ...metadata, unknownOutcome: true }).category, 'broadcast-unknown');
  }
  assert.equal(diagnosticError({ message: 'TLS connection timed out', unknownOutcome: true }).category, 'broadcast-unknown');
  assert.equal(diagnosticError(new Error('Broadcast outcome is unknown.', { cause: new Error('TLS connection timed out') })).category, 'broadcast-unknown');
  assert.equal(diagnosticError({ message: 'wrapper', name: 'AbortError', cause: new Error('TLS connection timed out') }).category, 'cancelled');
});

test('TLS timeout logs preserve classification while redacting domains, proofs and private fields', async t => {
  const directory = await fixture(t), log = new DiagnosticLog({ directory });
  const secret = 'PRIVATE-TLS-domain-address-transaction-proof-password';
  const cause = Object.assign(new Error('TLS connection timed out'), { domain: secret, address: secret, proof: secret, stack: secret });
  log.record('claim.failed', { stage: 'proof', durationMs: 10012, domain: secret, endpoint: secret, transaction: secret,
    error: Object.assign(new Error(secret, { cause }), { password: secret, stack: secret }) });
  log.record('claim.failed', { stage: 'proof', error: new Error('RPC request timed out.') });
  log.record('helper.failed', { stage: 'proof', error: { message: 'Claims helper request timed out after 45000 ms', helperFatal: true } });
  await log.flush();
  const stored = await rows(log.snapshot().file);
  assert.equal(stored[0].details.error.category, 'tls-timeout');
  assert.equal(stored[0].details.durationMs, 10012);
  assert.equal(stored[1].details.error.category, 'timeout');
  assert.equal(stored[2].details.error.category, 'timeout');
  assert.equal((await readFile(log.snapshot().file, 'utf8')).includes(secret), false);
  assert.equal(JSON.stringify(log.snapshot()).includes(secret), false);
});

test('diagnostics persist UTC, session and sequence metadata across launches', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory });
  assert.equal(log.record('wallet.started', { stage: 'lifecycle' }), undefined);
  log.record('claim.failed', { stage: 'proof', claimId: 3, attempts: 12, error: new Error('TLS proof generation failed') });
  await log.flush();
  const snapshot = log.snapshot();
  assert.equal(snapshot.status, 'ready');
  assert.equal(snapshot.dropped, 0);
  assert.ok(isAbsolute(snapshot.file));
  const stored = await rows(snapshot.file);
  assert.deepEqual(stored.slice(1), snapshot.recent);
  assert.equal(snapshot.errors, 1);
  assert.match(stored[0].session, /^[0-9a-f-]{36}$/);
  assert.match(stored[0].timestamp, /^\d{4}-\d\d-\d\dT.*Z$/);
  assert.deepEqual(stored.map(row => row.sequence), [1, 2]);
  assert.equal(stored[1].details.error.category, 'proof-failed');
  const next = new DiagnosticLog({ directory });
  next.record('wallet.started');
  await next.flush();
  const reopened = await rows(snapshot.file);
  assert.equal(reopened.length, 3);
  assert.notEqual(reopened[0].session, reopened[2].session);
  assert.equal(reopened[2].sequence, 1);
});

test('rotation retains only bounded active and backup files in chronological order', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory, maxBytes: 512, backups: 2 });
  for (let claimId = 0; claimId < 16; claimId++) log.record('claim.started', { stage: 'prepare', claimId });
  await log.flush();
  const files = await readdir(join(directory, 'logs'));
  assert.deepEqual(files.sort(), ['diagnostics.1.jsonl', 'diagnostics.2.jsonl', 'diagnostics.jsonl']);
  for (const file of files) assert.ok((await stat(join(directory, 'logs', file))).size <= 512);
  const retained = (await Promise.all(['diagnostics.2.jsonl', 'diagnostics.1.jsonl', 'diagnostics.jsonl'].map(file => rows(join(directory, 'logs', file))))).flat();
  assert.equal(retained.at(-1).details.claimId, 15);
  assert.deepEqual(retained.map(row => row.sequence), retained.map(row => row.sequence).sort((a, b) => a - b));
  assert.equal(new Set(retained.map(row => row.sequence)).size, retained.length);
  assert.equal(log.snapshot().dropped, 0);
});

test('queue and history stay bounded and snapshots cannot mutate retained records', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory, maxPending: 3, historyLimit: 2 });
  for (let claimId = 0; claimId < 50; claimId++) log.record('claim.failed', { claimId, error: { code: 'ETIMEDOUT' } });
  await log.flush();
  const snapshot = log.snapshot();
  assert.equal(snapshot.dropped, 47);
  assert.equal(snapshot.recent.length, 2);
  assert.deepEqual(snapshot.recent.map(row => row.details.claimId), [48, 49]);
  assert.equal((await rows(snapshot.file)).length, 3);
  snapshot.recent[0].details.error.message = 'untrusted mutation';
  snapshot.recent[0].details.claimId = 100;
  assert.equal(log.snapshot().recent[0].details.claimId, 48);
  assert.notEqual(log.snapshot().recent[0].details.error.message, 'untrusted mutation');
});

test('successful claims do not evict recent current-session failures', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory, historyLimit: 2 });
  log.record('claim.failed', { stage: 'proof', claimId: 3, error: { code: 'ETIMEDOUT' } });
  for (let claimId = 4; claimId < 1004; claimId++) log.record('claim.succeeded', { claimId });
  await log.flush();
  assert.equal(log.snapshot().errors, 1);
  assert.deepEqual(log.snapshot().recent.map(row => row.details.claimId), [3]);
  const next = new DiagnosticLog({ directory });
  await next.flush();
  assert.deepEqual(next.snapshot().recent, []);
  assert.equal(next.snapshot().errors, 0);
  assert.equal((await rows(next.snapshot().file))[0].event, 'claim.failed');
});

test('intentional RPC and refresh cancellations remain on disk without increasing errors', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory });
  log.record('rpc.cancelled', { stage: 'request', method: 'getaddresshistory', durationMs: 3, unknownOutcome: false });
  log.record('wallet.refresh_cancelled', { stage: 'refresh', durationMs: 5 });
  log.record('rpc.failed', { stage: 'request', method: 'sendrawtransaction', unknownOutcome: true,
    error: Object.assign(new Error('Broadcast outcome is unknown.'), { unknownOutcome: true }) });
  await log.flush();
  const stored = await rows(log.snapshot().file);
  assert.deepEqual(stored.map(row => row.event), ['rpc.cancelled', 'wallet.refresh_cancelled', 'rpc.failed']);
  assert.equal(stored[0].details.error, undefined);
  assert.equal(stored[1].details.error, undefined);
  assert.equal(log.snapshot().errors, 1);
  assert.equal(log.snapshot().dropped, 0);
  assert.deepEqual(log.snapshot().recent.map(row => row.event), ['rpc.failed']);
  assert.equal(stored[2].details.error.category, 'broadcast-unknown');
});

test('strict detail allowlists exclude secrets, payloads, arbitrary strings and numeric overflow', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory });
  const secret = 'NEVER-RECORD-this-mnemonic-password-private-key-address-proof-transaction';
  log.record('claim.failed', {
    stage: secret, method: secret, claimId: secret, attempts: Infinity, queued: -1,
    completed: 1000000001, failures: NaN, retryDelayMs: 86400001, durationMs: 1.25,
    height: 0xffffffff + 1, bytes: 1073741825, stderrBytes: 8193, exitCode: -1,
    enabled: true, unknownOutcome: false, password: secret, mnemonic: secret,
    address: secret, proof: secret, txhex: secret, params: { secret }, response: secret,
    config: secret, env: secret, stack: secret,
    error: { message: secret, stack: secret, code: secret, data: { node_code: secret, secret } },
  });
  log.record(secret, { stage: 'proof' });
  await log.flush();
  const serialized = await readFile(log.snapshot().file, 'utf8');
  assert.equal(serialized.includes(secret), false);
  const [row] = await rows(log.snapshot().file);
  assert.deepEqual(row.details, { durationMs: 1.25, stderrBytes: 8193, exitCode: -1, enabled: true, unknownOutcome: false, error: diagnosticError({}) });
  assert.equal(log.snapshot().dropped, 1);
});

test('known errors retain safe categories and codes without echoing messages', () => {
  const cases = [
    [{ code: 'ENOTFOUND' }, 'dns'], [{ code: 'EAI_AGAIN' }, 'dns'],
    [{ message: 'Cannot connect to RPC (ECONNREFUSED).' }, 'network'],
    [{ code: 'ECONNRESET' }, 'network'], [{ message: 'RPC request timed out.' }, 'timeout'],
    [{ code: -32029 }, 'quota'], [{ code: -32001 }, 'index-not-ready'],
    [{ code: -32004 }, 'data-unavailable'], [{ code: -32020, data: { node_code: -27 } }, 'node-rejected'],
    [{ message: 'This bounty is no longer eligible for claiming.' }, 'bounty-unavailable'],
    [{ message: 'Bounty availability changed while preparing its claim.' }, 'bounty-unavailable'],
    [{ message: 'Automatic Claims helper is not installed. Run npm run setup:claims or use a packaged desktop release.' }, 'helper-missing'],
    [{ message: 'Claims helper could not start: arbitrary secret' }, 'helper-failed'],
    [{ message: 'Persistent claims helper closed unexpectedly' }, 'helper-failed'],
    [{ message: 'Incompatible claims helper; update or rebuild it' }, 'helper-failed'],
    [{ message: 'arbitrary secret from helper', helperFatal: true }, 'helper-failed'],
    [{ message: 'Malformed claims helper response' }, 'helper-response'],
    [{ message: 'Claims helper ended without a verified proof' }, 'proof-failed'],
    [{ message: 'RPC server returned an invalid or oversized response.' }, 'invalid-response'],
    [{ message: 'Claims helper diagnostic limit exceeded' }, 'resource-limit'],
    [{ unknownOutcome: true, message: 'private txid' }, 'broadcast-unknown'],
    [{ name: 'AbortError' }, 'cancelled'], [{ code: 'ENOSPC' }, 'storage'],
    [{ message: 'Wallet locked or changed; please try again after unlocking.' }, 'wallet-locked'],
  ];
  for (const [input, category] of cases) {
    const result = diagnosticError(input);
    assert.equal(result.category, category, input.message || String(input.code));
    assert.equal(result.message.includes('arbitrary secret'), false);
    assert.equal(result.message.includes('private txid'), false);
  }
  assert.equal(diagnosticError({ code: -32020, data: { node_code: -27 } }).nodeCode, -27);
  assert.equal(diagnosticError({ message: 'Cannot connect to RPC (ENOTFOUND).' }).code, 'ENOTFOUND');
  assert.equal(diagnosticError({ code: -2147483649, data: { node_code: 1.5 } }).code, undefined);
});

test('wrapped errors use safe codes and at most one cause without retaining exception text', () => {
  const cause = { message: 'sensitive server text', code: -32020, data: { node_code: -27 } };
  assert.deepEqual(diagnosticError(new Error('wrapper private payload', { cause })), {
    category: 'node-rejected', message: 'The node rejected the transaction or claim.', code: -32020, nodeCode: -27,
  });
  assert.equal(diagnosticError(new Error('wrapper', { cause: new Error('RPC request timed out.') })).category, 'timeout');
  assert.equal(diagnosticError({ cause: { cause: { code: -32020 } } }).category, 'unknown');
  const cycle = {}; cycle.cause = cycle;
  assert.equal(diagnosticError(cycle).category, 'unknown');
});

test('helper exit metadata supports unsigned Windows status and only fixed signal names', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory });
  for (const exitCode of [0, 1, -1073741819, 0xc0000005, 0xffffffff]) {
    log.record('helper.failed', { ...diagnosticProcessExit(exitCode, null), helperReady: false, stderrBytes: 27,
      error: new Error('Persistent claims helper closed unexpectedly') });
  }
  log.record('helper.failed', { ...diagnosticProcessExit(null, 'SIGTERM'), helperReady: true });
  await log.flush();
  const stored = await rows(log.snapshot().file);
  assert.deepEqual(stored.slice(0, 5).map(row => row.details.exitCode), [0, 1, -1073741819, 0xc0000005, 0xffffffff]);
  assert.ok(stored.slice(0, 5).every(row => row.details.helperReady === false && row.details.error.category === 'helper-failed'));
  assert.deepEqual(stored[5].details, { signal: 'SIGTERM', helperReady: true });
  assert.deepEqual(diagnosticProcessExit(0xffffffff + 1, 'private-signal'), {});
  assert.deepEqual(diagnosticProcessExit(-2147483649, 'sigterm'), {});
  assert.deepEqual(diagnosticProcessExit(1.5, null), {});
});

test('forged helper status fields cannot escape strict diagnostic metadata allowlists', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory });
  const privateText = 'private-profile-path-and-stderr';
  log.record('helper.failed', { exitCode: 0xffffffff + 1, helperReady: privateText, signal: privateText,
    stderrBytes: 1073741825, stderr: privateText, argv: [privateText], profile: privateText,
    error: { message: privateText, signal: privateText, exitCode: privateText, helperReady: privateText } });
  let getters = 0;
  log.record('helper.failed', Object.defineProperties({}, Object.fromEntries(['exitCode', 'signal', 'helperReady', 'stderrBytes'].map(key => [key, {
    get() { getters++; return privateText; },
  }]))));
  await log.flush();
  assert.equal(getters, 0);
  const stored = await rows(log.snapshot().file);
  assert.deepEqual(stored[0].details, { error: diagnosticError({}) });
  assert.deepEqual(stored[1].details, {});
  assert.equal((await readFile(log.snapshot().file, 'utf8')).includes(privateText), false);
});

test('prototype data, getters, coercion hooks and throwing proxies cannot enter logs', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory });
  let invoked = 0;
  const getter = () => { invoked++; throw new Error('getter secret'); };
  const error = Object.create({ code: -32020, message: 'inherited secret', data: { node_code: -1 } });
  for (const key of ['message', 'code', 'data', 'name', 'unknownOutcome']) Object.defineProperty(error, key, { get: getter });
  const details = Object.create({ method: 'getchaintip', password: 'inherited secret' });
  for (const key of ['stage', 'claimId', 'enabled']) Object.defineProperty(details, key, { get: getter });
  details.error = error;
  details.toJSON = getter;
  log.record('claim.failed', details);
  const proxy = new Proxy({}, { getOwnPropertyDescriptor: getter, get: getter });
  assert.doesNotThrow(() => log.record('claim.failed', proxy));
  assert.doesNotThrow(() => diagnosticError(proxy));
  // A revoked proxy is also harmless; none of its metadata can be inspected.
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  assert.doesNotThrow(() => log.record('claim.failed', revoked.proxy));
  await log.flush();
  const stored = await rows(log.snapshot().file);
  assert.deepEqual(stored[0].details, { error: diagnosticError({}) });
  assert.deepEqual(stored[1].details, {});
  assert.deepEqual(stored[2].details, {});
  assert.ok(invoked > 0); // Only proxy descriptor traps run; property getters never do.
  assert.equal((await readFile(log.snapshot().file, 'utf8')).includes('secret'), false);
});

test('own property getters are never invoked', async t => {
  const directory = await fixture(t);
  let invoked = 0;
  const error = Object.defineProperties({}, Object.fromEntries(['message', 'code', 'name', 'data'].map(key => [key, { get() { invoked++; return 'secret'; } }])));
  const log = new DiagnosticLog({ directory });
  log.record('rpc.failed', { get method() { invoked++; return 'getchaintip'; }, error });
  await log.flush();
  assert.equal(invoked, 0);
});

test('disk initialization failure is nonthrowing and keeps bounded local history', async t => {
  const directory = await fixture(t);
  await writeFile(join(directory, 'logs'), 'blocking ordinary file');
  const log = new DiagnosticLog({ directory, historyLimit: 2 });
  assert.doesNotThrow(() => log.record('wallet.started'));
  await assert.doesNotReject(log.flush());
  assert.equal(log.snapshot().status, 'unavailable');
  for (let attempts = 0; attempts < 6; attempts++) assert.doesNotThrow(() => log.record('claim.failed', { attempts }));
  await assert.doesNotReject(log.flush());
  assert.equal(log.snapshot().recent.length, 2);
  assert.equal(log.snapshot().dropped, 7);
  assert.equal(await readFile(join(directory, 'logs'), 'utf8'), 'blocking ordinary file');
});

test('write failure after successful initialization does not reject wallet work', async t => {
  const directory = await fixture(t);
  const log = new DiagnosticLog({ directory });
  await log.flush();
  await rm(log.snapshot().file);
  await mkdir(log.snapshot().file);
  log.record('claim.failed', { stage: 'submit', error: { unknownOutcome: true } });
  await assert.doesNotReject(log.flush());
  assert.equal(log.snapshot().status, 'unavailable');
  assert.equal(log.snapshot().dropped, 1);
  assert.equal(log.snapshot().recent[0].details.error.category, 'broadcast-unknown');
});

test('invalid directory is unavailable without affecting callers', async () => {
  for (const directory of [undefined, null, {}, '', 'invalid\0path']) {
    const log = new DiagnosticLog({ directory });
    assert.doesNotThrow(() => log.record('wallet.started'));
    await assert.doesNotReject(log.flush());
    assert.equal(log.snapshot().status, 'unavailable');
    assert.equal(log.snapshot().dropped, 1);
  }
});

test('limits remain bounded after a previous launch used larger files or more backups', async t => {
  const directory = await fixture(t);
  const logs = join(directory, 'logs');
  await mkdir(logs);
  for (const name of ['diagnostics.jsonl', 'diagnostics.1.jsonl', 'diagnostics.2.jsonl', 'diagnostics.5.jsonl']) await writeFile(join(logs, name), 'x'.repeat(2048));
  await writeFile(join(logs, 'unrelated.txt'), 'preserved');
  const log = new DiagnosticLog({ directory, maxBytes: 512, backups: 1, historyLimit: 0 });
  log.record('wallet.started');
  await log.flush();
  assert.deepEqual((await readdir(logs)).sort(), ['diagnostics.jsonl', 'unrelated.txt']);
  assert.deepEqual(log.snapshot().recent, []);
  assert.ok((await stat(log.snapshot().file)).size <= 512);
  assert.equal(await readFile(join(logs, 'unrelated.txt'), 'utf8'), 'preserved');
});
