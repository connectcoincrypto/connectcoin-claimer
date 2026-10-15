import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { RpcClient, RpcError, validateRpcParams } from '../src/core/rpc.mjs';

const hash = 'a'.repeat(64);
const IO_GUARD_MS = 5000;
const FIXTURE_TIMEOUT_MS = 10000;
const line = message => `${JSON.stringify(message)}\n`;
const response = (request, result) => ({ jsonrpc: '2.0', id: request.id, result });
const note = (method, params) => ({ jsonrpc: '2.0', method, params });
async function mock(handler, options = {}) {
  const sockets = new Set(), requests = [];
  let connections = 0;
  const server = net.createServer(socket => {
    connections++; sockets.add(socket);
    socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const request = JSON.parse(buffer.slice(0, newline)); buffer = buffer.slice(newline + 1);
        requests.push(request); handler(request, socket, requests);
      }
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const client = new RpcClient({ host: '127.0.0.1', port: server.address().port, timeoutMs: FIXTURE_TIMEOUT_MS, ...options });
  return { client, requests, get connections() { return connections; }, async close() {
    client.close(); for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  } };
}
async function bounded(promise, timeoutMs = IO_GUARD_MS) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('TEST: stranded RPC promise')), timeoutMs); })]); }
  finally { clearTimeout(timer); }
}

// Set up real TCP first. Intentional expiry/pacing tests then control both the
// request timer and its monotonic admission clock; CPU steal is not elapsed
// protocol time in these fixtures. Each test also has a real runner deadline.
function controlledClock(t) {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  return { tick(ms) { now += ms; t.mock.timers.tick(ms); },
    reset() { t.mock.timers.reset(); t.mock.restoreAll(); } };
}
const settle = () => new Promise(resolve => setImmediate(resolve));
function pacingWait(t, client) {
  const waiting = Promise.withResolvers(), original = client.quotaWait;
  t.mock.method(client, 'quotaWait', function (...args) {
    const wait = original.apply(this, args);
    if (wait > 0) waiting.resolve(wait);
    return wait;
  });
  return waiting.promise;
}

test('only well-framed explicit stream invalidations preserve recoverable server codes', async () => {
  for (const [ending, expectedCode] of [
    [{ complete: false, chunks: 0, error: { code: -32011, message: 'Block aged out' } }, -32011],
    [{ complete: false, chunks: 0, error: { code: -32001, message: 'Index not ready' } }, -32001],
    [{ complete: false, chunks: 0, error: { code: -32002, message: 'Backend failed' } }, undefined],
    [{ complete: false, chunks: 1, error: { code: -32011, message: 'Wrong chunk count' } }, undefined],
    [{ complete: true, chunks: 0, error: { code: -32011, message: 'Missing stream state' } }, undefined],
    [{ complete: false, chunks: 0, error: { code: -32011, message: {} } }, undefined],
  ]) {
    const server = await mock((request, socket) => {
      socket.write(line(response(request, { stream_id: 'recoverability-test' })) +
        line(note('stream.end', { stream_id: 'recoverability-test', ...ending })));
    });
    try {
      await assert.rejects(bounded(server.client.request('getblockbounties', { block_hash: hash }, { onChunk() {} })), error => {
        assert.match(error.message, /Bounty stream was incomplete/);
        assert.equal(error.code, expectedCode);
        return true;
      });
    } finally { await server.close(); }
  }
});

test('method/parameter allowlist cannot leak secrets or invoke getters', () => {
  for (const method of ['getblocktemplate', 'stop', '__proto__', 'constructor']) assert.throws(() => validateRpcParams(method, {}), /not allowed/);
  assert.throws(() => validateRpcParams('getchaintip', { mnemonic: 'secret' }), /Unexpected/);
  assert.throws(() => validateRpcParams('gettransaction', { txid: hash, password: 'secret' }), /Unexpected/);
  assert.throws(() => validateRpcParams('gettransaction', { get txid() { throw new Error('getter executed'); } }), /plain data/);
  assert.throws(() => validateRpcParams('gettransaction', Object.create({ txid: hash })), /Unexpected/);
  assert.throws(() => validateRpcParams('gettransaction', { txid: { toJSON: () => hash } }), /Invalid/);
  assert.throws(() => validateRpcParams('getchaintip', []), /Unexpected/);
  assert.throws(() => validateRpcParams('getchaintip', JSON.parse('{"__proto__":{"mnemonic":"secret"}}')), /Unexpected/);
  assert.deepEqual(validateRpcParams('gettransaction', { txid: hash.toUpperCase() }), { txid: hash });
  assert.throws(() => validateRpcParams('getaddressbalance', { address: 'tcc1p\u202eaddress' }));
  assert.throws(() => validateRpcParams('getbountychanges', { cursor: 'x'.repeat(1025) }));
  assert.throws(() => validateRpcParams('sendrawtransaction', { transaction_hex: '00'.repeat(400001) }));
  assert.deepEqual(validateRpcParams('getbountychanges', { cursor: null }), { cursor: null });
});

test('unsubscribe accepts opaque bounded IDs and rejects overlong or control-character IDs', () => {
  for (const subscription_id of ['subscribetip:', 'subscribeaddress:abcdefgh1', 'x'.repeat(100)]) {
    assert.deepEqual(validateRpcParams('unsubscribe', { subscription_id }), { subscription_id });
  }
  for (const subscription_id of ['', 'x'.repeat(101), 'bad\u0000id', 'bad\nID', 'bad\u007fID']) {
    assert.throws(() => validateRpcParams('unsubscribe', { subscription_id }), /Invalid RPC subscription ID/);
  }
});

test('bounty delta opt-in and compact transaction status keep strict parameter validation', () => {
  assert.deepEqual(validateRpcParams('getbountychanges', { include_bounties: true, cursor: null }), { cursor: null, include_bounties: true });
  assert.deepEqual(validateRpcParams('getbountychanges', { include_bounties: false }), { include_bounties: false });
  for (const value of [null, undefined, 0, 1, 'true', [], {}]) {
    assert.throws(() => validateRpcParams('getbountychanges', { include_bounties: value }), /Invalid RPC bounty delta option/);
  }
  assert.throws(() => validateRpcParams('getbountychanges', { get include_bounties() { throw new Error('Getter executed'); } }), /plain data/);
  assert.deepEqual(validateRpcParams('gettransactionstatus', { txid: hash.toUpperCase() }), { txid: hash });
  assert.throws(() => validateRpcParams('gettransactionstatus', {}), /Missing/);
  assert.throws(() => validateRpcParams('gettransactionstatus', { txid: hash, password: 'secret' }), /Unexpected/);
  assert.throws(() => validateRpcParams('gettransactionstatus', { txid: ['a'.repeat(64)] }), /Invalid/);
});

test('recent block count is an optional strict bounded integer without getters or coercion', () => {
  assert.deepEqual(validateRpcParams('getrecentblockhashes', {}), {});
  for (const count of [1, 5, 100, 600]) {
    assert.deepEqual(validateRpcParams('getrecentblockhashes', { count }), { count });
  }
  for (const count of [null, undefined, false, true, '5', 0, -1, 601, 5.5, NaN, Infinity, [], { valueOf: () => 5 }]) {
    assert.throws(() => validateRpcParams('getrecentblockhashes', { count }), /Invalid RPC recent-block count/);
  }
  assert.throws(() => validateRpcParams('getrecentblockhashes', { get count() { throw new Error('getter executed'); } }), /plain data/);
  assert.throws(() => validateRpcParams('getrecentblockhashes', { count: 5, limit: 5 }), /Unexpected/);
});

test('known tip requires bounty opt-in and an exact plain nested height/hash pair', () => {
  for (const height of [0, 700, Number.MAX_SAFE_INTEGER]) {
    const known_tip = { height, hash };
    assert.deepEqual(validateRpcParams('getbountychanges', { include_bounties: true, known_tip }), { include_bounties: true, known_tip });
  }
  for (const known_tip of [null, [], {}, { height: 1 }, { hash }, { height: -1, hash },
    { height: 1.5, hash }, { height: '1', hash }, { height: Infinity, hash },
    { height: Number.MAX_SAFE_INTEGER + 1, hash }, { height: 1, hash: hash.toUpperCase() },
    { height: 1, hash: [hash] }, { height: 1, hash, password: 'secret' },
    Object.create({ height: 1, hash }), { height: 1, hash, [Symbol('secret')]: 'secret' },
    { get height() { assert.fail('Nested height getter ran'); }, hash },
    { height: 1, get hash() { assert.fail('Nested hash getter ran'); } }]) {
    assert.throws(() => validateRpcParams('getbountychanges', { include_bounties: true, known_tip }), /Invalid RPC known tip/);
  }
  for (const include_bounties of [false, undefined]) {
    const params = { known_tip: { height: 1, hash }, ...(include_bounties === undefined ? {} : { include_bounties }) };
    assert.throws(() => validateRpcParams('getbountychanges', params), /Invalid RPC known tip/);
  }
  assert.throws(() => validateRpcParams('getbountychanges', { include_bounties: true,
    get known_tip() { assert.fail('Outer getter ran'); } }), /plain data/);
});

test('known tip is copied deeply before the real RPC client queues transmission', async () => {
  const server = await mock((request, socket) => socket.write(line(response(request, request.params))));
  try {
    const params = { include_bounties: true, known_tip: { height: 700, hash } };
    const pending = server.client.request('getbountychanges', params);
    params.known_tip.height = 701; params.known_tip.hash = 'b'.repeat(64); params.known_tip.password = 'secret';
    assert.deepEqual(await pending, { include_bounties: true, known_tip: { height: 700, hash } });
    assert.deepEqual(server.requests[0].params, { include_bounties: true, known_tip: { height: 700, hash } });
  } finally { await server.close(); }
});

test('recent block count is transmitted by the real RPC client and copied before queueing', async () => {
  const server = await mock((request, socket) => socket.write(line(response(request, { count: request.params.count }))));
  try {
    const params = { count: 5 };
    const pending = server.client.request('getrecentblockhashes', params);
    params.count = 600;
    assert.deepEqual(await pending, { count: 5 });
    assert.deepEqual(server.requests[0].params, { count: 5 });
  } finally { await server.close(); }
});

test('concurrent requests share one connection; chunk fragmentation is reassembled', async () => {
  const received = Promise.withResolvers();
  const server = await mock((_request, socket, requests) => { if (requests.length === 2) received.resolve(socket); });
  try {
    const pending = Promise.all([server.client.request('getchaintip'), server.client.request('getrecentblockhashes')]);
    const socket = await bounded(received.promise);
    const first = line(response(server.requests[0], { method: server.requests[0].method }));
    const fragmentRead = once(server.client.socket, 'data');
    socket.write(first.slice(0, 8)); await bounded(fragmentRead);
    assert.equal(server.client.pending.size, 2, 'A partial frame cannot settle either request');
    socket.write(first.slice(8) + line(response(server.requests[1], { method: server.requests[1].method })));
    const results = await pending;
    assert.deepEqual(results.map(result => result.method), ['getchaintip', 'getrecentblockhashes']);
    assert.equal(server.connections, 1); assert.equal(server.client.pending.size, 0);
  } finally { await server.close(); }
});

test('bounty stream initial reply and all notifications may arrive in the same chunk', async () => {
  const server = await mock((request, socket) => socket.write([
    response(request, { stream_id: 's1' }),
    note('stream.chunk', { stream_id: 's1', sequence: 0, items: { type: 'snapshot', block_hash: hash } }),
    note('stream.chunk', { stream_id: 's1', sequence: 1, items: { type: 'bounties', items: [{ txid: hash }] } }),
    note('stream.chunk', { stream_id: 's1', sequence: 2, items: { type: 'state' } }),
    note('stream.end', { stream_id: 's1', chunks: 3, complete: true }),
  ].map(line).join('')));
  const chunks = [];
  try {
    const result = await server.client.request('getblockbounties', { block_hash: hash }, { onChunk: item => chunks.push(item) });
    assert.deepEqual(result, { chunks: 3, records: 1 });
    assert.deepEqual(chunks.map(chunk => chunk.type), ['snapshot', 'bounties', 'state']);
    assert.equal(server.client.pending.size, 0); assert.equal(server.client.streams.size, 0);
  } finally { await server.close(); }
});

test('malformed stream IDs reject promptly rather than leaving an untracked promise', async () => {
  for (const result of [{}, { stream_id: '' }, { stream_id: 1 }, { stream_id: 'x'.repeat(129) }]) {
    const server = await mock((request, socket) => socket.write(line(response(request, result))));
    try {
      await assert.rejects(bounded(server.client.request('getblockbounties', { block_hash: hash }, { onChunk() {} })), /invalid or oversized/);
      assert.equal(server.client.pending.size, 0); assert.equal(server.client.streams.size, 0);
    } finally { await server.close(); }
  }
});

test('stream sequence errors, missing snapshot, and callback failures tear down affected requests', async () => {
  for (const mode of ['sequence', 'snapshot', 'callback']) {
    const server = await mock((request, socket) => socket.write([
      response(request, { stream_id: 'stream' }), note('stream.chunk', { stream_id: 'stream', sequence: mode === 'sequence' ? 1 : 0, items: { type: mode === 'snapshot' ? 'state' : 'snapshot' } }),
    ].map(line).join('')));
    try {
      await assert.rejects(bounded(server.client.request('getblockbounties', { block_hash: hash }, { onChunk() { if (mode === 'callback') throw new Error('Bad bounty'); } })), /invalid or oversized/);
      assert.equal(server.client.pending.size, 0); assert.equal(server.client.streams.size, 0);
    } finally { await server.close(); }
  }
});

test('incomplete stream reports failure and does not claim a complete block', async () => {
  const server = await mock((request, socket) => socket.write([
    response(request, { stream_id: 's' }), note('stream.chunk', { stream_id: 's', sequence: 0, items: { type: 'snapshot' } }),
    note('stream.end', { stream_id: 's', chunks: 1, complete: false, error: { code: -32001 } }),
  ].map(line).join('')));
  try { await assert.rejects(server.client.request('getblockbounties', { block_hash: hash }, { onChunk() {} }), /incomplete/); }
  finally { await server.close(); }
});

test('incomplete stream diagnostics preserve numeric server classifications without untrusted text or data', async () => {
  const events = [];
  const server = await mock((request, socket) => socket.write([
    response(request, { stream_id: 'failed-stream' }),
    note('stream.chunk', { stream_id: 'failed-stream', sequence: 0, items: { type: 'snapshot' } }),
    note('stream.end', { stream_id: 'failed-stream', chunks: 1, complete: false,
      error: { code: -32001, message: 'untrusted-private-message',
        data: { node_code: -26, address: 'untrusted-private-address', transaction_hex: 'untrusted-private-transaction' } } }),
  ].map(line).join('')), { onDiagnostic: (event, details) => events.push({ event, details }) });
  try {
    await assert.rejects(server.client.request('getblockbounties', { block_hash: hash }, { onChunk() {} }), error => {
      assert.equal(error.message, 'Bounty stream was incomplete; nothing from this block was applied.');
      assert.equal(error.code, -32001);
      assert.equal(error.data, undefined);
      return true;
    });
    const failures = events.filter(item => item.event === 'rpc.failed');
    assert.equal(failures.length, 1);
    const { details } = failures[0];
    assert.equal(details.method, 'getblockbounties');
    assert.equal(details.stage, 'stream');
    assert.equal(details.unknownOutcome, false);
    assert.equal(details.error.code, -32001);
    assert.deepEqual(details.error.data, { node_code: -26 });
    assert.equal(details.error.message, 'Bounty stream was incomplete; nothing from this block was applied.');
    assert.equal(JSON.stringify(events).includes('untrusted-private-'), false);
    assert.equal(server.client.pending.size, 0);
    assert.equal(server.client.streams.size, 0);
    assert.equal(server.client.socket?.destroyed ?? true, true);
  } finally { await server.close(); }
});

test('incomplete stream diagnostics ignore nonnumeric or unsafe server classifications', async () => {
  for (const error of [
    { code: '-32001', data: { node_code: -26 } },
    { code: Number.MAX_SAFE_INTEGER + 1, data: { node_code: -26 } },
    { code: -32001, data: { node_code: '-26' } },
  ]) {
    const events = [];
    const server = await mock((request, socket) => socket.write([
      response(request, { stream_id: 'invalid-code' }),
      note('stream.end', { stream_id: 'invalid-code', chunks: 0, complete: false, error }),
    ].map(line).join('')), { onDiagnostic: (event, details) => events.push({ event, details }) });
    try {
      await assert.rejects(server.client.request('getblockbounties', { block_hash: hash }, { onChunk() {} }), /incomplete/);
      const failure = events.find(item => item.event === 'rpc.failed').details.error;
      assert.equal(failure.code, Number.isSafeInteger(error.code) ? error.code : undefined);
      assert.equal(failure.data, undefined);
    } finally { await server.close(); }
  }
});

test('invalid envelopes, UTF8, and oversized unframed messages fail closed', async () => {
  for (const malformed of [
    request => line({ jsonrpc: '2.0', id: request.id, result: 1, error: { code: -1, message: 'bad' } }),
    request => line({ jsonrpc: '2.0', id: request.id, error: {} }),
    request => line({ jsonrpc: '2.0', id: request.id + 1, result: null }),
    () => Buffer.from([0xff, 10]),
    () => Buffer.alloc(2 * 1024 * 1024 + 1, 65),
  ]) {
    const server = await mock((request, socket) => socket.write(malformed(request)));
    try {
      // A complete 2 MiB transfer may take more than 400 ms on a contended runner.
      // This is only a liveness guard: protocol rejection is still mandatory,
      // and the longer RPC timeout cannot accidentally satisfy this assertion.
      await assert.rejects(bounded(server.client.request('getchaintip')), /invalid or oversized/);
      assert.equal(server.requests.length, 1);
      assert.equal(server.client.pending.size, 0); assert.equal(server.client.streams.size, 0);
      assert.equal(server.client.socket?.destroyed ?? true, true);
    }
    finally { await server.close(); }
  }
});

test('timeout and transport loss make broadcast outcome explicitly unknown, with no retry', { timeout: FIXTURE_TIMEOUT_MS }, async t => {
  for (const close of [true, false]) {
    const received = Promise.withResolvers();
    const server = await mock((_request, socket) => received.resolve(socket));
    let clock;
    try {
      await server.client.connect();
      clock = controlledClock(t); server.client.timeoutMs = 50;
      const result = assert.rejects(server.client.request('sendrawtransaction', { transaction_hex: '00'.repeat(20) }), error => error.unknownOutcome && /unknown/.test(error.message));
      const socket = await received.promise;
      assert.equal(server.client.pending.size, 1);
      if (close) socket.destroy();
      else {
        clock.tick(49); await settle();
        assert.equal(server.client.pending.size, 1, 'The written broadcast must not expire early');
        clock.tick(1);
      }
      await result; clock.tick(1000); await settle();
      assert.equal(server.requests.length, 1); assert.equal(server.connections, 1);
      assert.equal(server.client.pending.size, 0);
    } finally { await server.close(); clock?.reset(); }
  }
});

for (const failure of ['timeout', 'malformed reply']) test(`immediate retry after ${failure} publishes disconnection before replacing the socket`, { timeout: FIXTURE_TIMEOUT_MS }, async t => {
  const received = Promise.withResolvers();
  const server = await mock((request, socket, requests) => {
    if (requests.length > 1) socket.write(line(response(request, true)));
    else received.resolve(socket);
  });
  const events = [];
  server.client.on('connected', () => events.push('connected'));
  server.client.on('disconnected', () => events.push('disconnected'));
  try {
    await server.client.connect();
    const clock = controlledClock(t); server.client.timeoutMs = 50;
    const rejected = assert.rejects(server.client.request('getchaintip'), failure === 'timeout' ? /request timed out/ : /invalid or oversized/);
    const socket = await received.promise;
    if (failure === 'timeout') {
      clock.tick(49); await settle(); assert.equal(server.client.pending.size, 1);
      clock.tick(1);
    } else socket.write('invalid-json\n');
    await rejected;
    // Retry in the rejected request's continuation, before the old socket's
    // close event. Subscription and wallet invalidations must not disappear.
    assert.equal(await server.client.request('getchaintip'), true);
    await settle();
    assert.deepEqual(events, ['connected', 'disconnected', 'connected']);
    assert.equal(server.connections, 2);
    assert.equal(server.client.pending.size, 0);
  } finally { await server.close(); }
});

test('a disconnection listener can close the client before an immediate reconnect', { timeout: FIXTURE_TIMEOUT_MS }, async t => {
  const received = Promise.withResolvers();
  const server = await mock(() => received.resolve());
  try {
    await server.client.connect();
    const clock = controlledClock(t); server.client.timeoutMs = 50;
    const rejected = assert.rejects(server.client.request('getchaintip'), /request timed out/);
    await received.promise;
    clock.tick(49); await settle(); assert.equal(server.client.pending.size, 1);
    clock.tick(1); await rejected;
    server.client.once('disconnected', () => server.client.close());
    await assert.rejects(server.client.request('getchaintip'), { name: 'AbortError' });
    assert.equal(server.connections, 1);
    assert.equal(server.client.socket, null);
    assert.equal(server.client.pending.size, 0);
  } finally { await server.close(); }
});

test('RPC not-ready and rate limit errors retain structured codes; future request obeys cooldown', { timeout: FIXTURE_TIMEOUT_MS }, async t => {
  const times = [];
  const server = await mock((request, socket, requests) => {
    times.push(performance.now());
    socket.write(line(requests.length === 1 ? { jsonrpc: '2.0', id: request.id, error: { code: -32029, message: 'Rate limited', data: { retry_after_ms: 80 } } } : response(request, true)));
  });
  try {
    await server.client.connect(); const clock = controlledClock(t);
    await assert.rejects(server.client.request('getchaintip'), error => error instanceof RpcError && error.code === -32029);
    const waiting = pacingWait(t, server.client);
    const pending = server.client.request('getchaintip');
    assert.equal(await waiting, 80, 'The real cooldown must suspend admission');
    clock.tick(79); await settle(); assert.equal(server.requests.length, 1, 'Cooldown forbids early transmission');
    clock.tick(1); assert.equal(await pending, true);
    assert.equal(times[1] - times[0], 80);
  } finally { await server.close(); }
  const notReady = await mock((request, socket) => socket.write(line({ jsonrpc: '2.0', id: request.id, error: { code: -32001, message: 'Not ready' } })));
  try { await assert.rejects(notReady.client.request('getchaintip'), error => error.code === -32001); }
  finally { await notReady.close(); }
});

test('quota survives reconnection and block quotas are canonical per block', { timeout: FIXTURE_TIMEOUT_MS }, async t => {
  const times = [];
  const server = await mock((request, socket) => { times.push(performance.now()); socket.write(line(response(request, true))); }, { quota: 1, windowMs: 100 });
  try {
    await server.client.connect(); const clock = controlledClock(t);
    await server.client.request('getchaintip');
    const oldClosed = once(server.client, 'disconnected'); server.client.socket.destroy(); await oldClosed;
    assert.deepEqual(server.client.history.get('getchaintip'), [0], 'Closing the socket cannot clear quota history');
    const waiting = pacingWait(t, server.client);
    const pending = server.client.request('getchaintip');
    assert.equal(await waiting, 110, 'The retained quota must suspend admission');
    clock.tick(99); await settle(); assert.equal(server.requests.length, 1, 'Quota survives socket replacement');
    assert.ok(server.client.quotaWait('getchaintip', {}) > 0, 'Admission remains blocked before the quota window');
    clock.tick(11); await pending;
    assert.equal(times[1] - times[0], 110); assert.equal(server.connections, 2);
    assert.equal(server.client.history.get('getchaintip').length, 1);
    assert.equal(server.client.history.get('getchaintip')[0], 110, 'Admission uses the controlled write clock');
    await server.client.pace('getblockbounties', { block_hash: hash });
    await server.client.pace('getblockbounties', { block_hash: 'b'.repeat(64) });
    assert.equal(server.client.history.get(`getblockbounties:${hash}`).length, 1);
  } finally { await server.close(); }
});

test('queued parameters are snapshotted, close aborts pace waiters, connection-close race settles', async t => {
  t.mock.method(performance, 'now', () => 0);
  const events = [];
  const server = await mock((request, socket) => socket.write(line(response(request, request.params))), {
    quota: 1, windowMs: 1000, onDiagnostic: (event, details) => events.push({ event, details }),
  });
  try {
    const params = { txid: hash };
    const first = server.client.request('gettransaction', params); params.txid = 'b'.repeat(64);
    assert.deepEqual(await first, { txid: hash });
    const waiting = server.client.request('gettransaction', { txid: hash });
    const assertion = assert.rejects(bounded(waiting), error => error.name === 'AbortError' && error.code === 'ABORT_ERR');
    server.client.close(); await assertion; assert.equal(server.client.queuedRequests, 0);
    assert.equal(server.requests.length, 1);
    assert.equal(events.filter(item => item.event === 'rpc.cancelled').length, 1);
    assert.equal(events.some(item => item.event === 'rpc.failed'), false);
  } finally { await server.close(); }
  const raceEvents = [];
  const race = await mock((request, socket) => socket.write(line(response(request, true))), {
    onDiagnostic: (event, details) => raceEvents.push({ event, details }),
  });
  try {
    race.client.once('connected', () => race.client.close());
    await assert.rejects(bounded(race.client.request('getchaintip')), error => error.name === 'AbortError');
    assert.equal(raceEvents.filter(item => item.event === 'rpc.cancelled').length, 1);
    assert.equal(raceEvents.some(item => item.event === 'rpc.failed'), false);
  } finally { await race.close(); }
});

test('local close cancels reads but preserves an already-sent broadcast as an unknown failure', async () => {
  const events = [];
  let received;
  const ready = new Promise(resolve => { received = resolve; });
  const server = await mock((_request, _socket, requests) => { if (requests.length === 2) received(); }, {
    onDiagnostic: (event, details) => events.push({ event, details }),
  });
  try {
    const read = assert.rejects(server.client.request('getchaintip'), error => error.name === 'AbortError' && error.code === 'ABORT_ERR');
    const broadcast = assert.rejects(server.client.request('sendrawtransaction', { transaction_hex: 'ab'.repeat(40) }), error => error.unknownOutcome === true && error.name !== 'AbortError');
    await bounded(ready);
    server.client.close();
    await Promise.all([read, broadcast]);
    const cancelled = events.filter(item => item.event === 'rpc.cancelled');
    assert.equal(cancelled.length, 1);
    assert.equal(cancelled[0].details.method, 'getchaintip');
    assert.equal(cancelled[0].details.error, undefined);
    assert.equal(cancelled[0].details.unknownOutcome, false);
    const failures = events.filter(item => item.event === 'rpc.failed');
    assert.equal(failures.length, 1);
    assert.equal(failures[0].details.method, 'sendrawtransaction');
    assert.equal(failures[0].details.unknownOutcome, true);
    assert.equal(failures[0].details.error.unknownOutcome, true);
    assert.equal(server.requests.length, 2);
    assert.equal(server.client.pending.size, 0);
  } finally { await server.close(); }
});

test('local close settles an active stream and an unfinished connection as cancellation', async () => {
  const events = [];
  let received;
  const ready = new Promise(resolve => { received = resolve; });
  const server = await mock((request, socket) => socket.write([
    response(request, { stream_id: 'cancel-stream' }),
    note('stream.chunk', { stream_id: 'cancel-stream', sequence: 0, items: { type: 'snapshot' } }),
  ].map(line).join('')), { onDiagnostic: (event, details) => events.push({ event, details }) });
  try {
    const streamed = assert.rejects(server.client.request('getblockbounties', { block_hash: hash }, { onChunk: received }), error => error.name === 'AbortError');
    await bounded(ready);
    server.client.close(); await streamed;
    assert.equal(server.client.streams.size, 0);
    assert.equal(events.filter(item => item.event === 'rpc.cancelled').length, 1);
    assert.equal(events.find(item => item.event === 'rpc.cancelled').details.stage, 'stream');
    assert.equal(events.some(item => item.event === 'rpc.failed'), false);
  } finally { await server.close(); }
  const connecting = await mock(() => {});
  try {
    const pending = assert.rejects(bounded(connecting.client.connect()), error => error.name === 'AbortError');
    connecting.client.close(); await pending;
  } finally { await connecting.close(); }
});

test('local close cannot reclassify a transport failure that already rejected a request', async () => {
  const events = [];
  let received;
  const ready = new Promise(resolve => { received = resolve; });
  const server = await mock(() => received(), { onDiagnostic: (event, details) => events.push({ event, details }) });
  try {
    const failure = new Error('RPC request timed out.');
    const pending = assert.rejects(server.client.request('getchaintip'), error => error === failure);
    await bounded(ready);
    server.client.failAll(failure); server.client.close(); await pending;
    assert.equal(events.filter(item => item.event === 'rpc.failed').length, 1);
    assert.equal(events.find(item => item.event === 'rpc.failed').details.error, failure);
    assert.equal(events.some(item => item.event === 'rpc.cancelled'), false);
  } finally { await server.close(); }
});

test('diagnostic callbacks cannot fail requests or replace RPC errors', async () => {
  for (const onDiagnostic of [() => { throw new Error('sink failed'); }, async () => { throw new Error('async sink failed'); }]) {
    const server = await mock((request, socket, requests) => socket.write(line(requests.length === 1
      ? response(request, true)
      : { jsonrpc: '2.0', id: request.id, error: { code: -32020, message: 'Rejected', data: { node_code: -26 } } })), { onDiagnostic });
    try {
      assert.equal(await server.client.request('getchaintip'), true);
      await assert.rejects(server.client.request('getchaintip'), error => error instanceof RpcError && error.code === -32020 && error.data.node_code === -26);
      await delay(0);
      assert.equal(server.client.pending.size, 0);
    } finally { await server.close(); }
  }
});

test('diagnostics record RPC error metadata without request params or endpoint details', async t => {
  t.mock.method(performance, 'now', () => 0);
  const events = [];
  const server = await mock((request, socket) => socket.write(line({ jsonrpc: '2.0', id: request.id,
    error: { code: -32020, message: 'Rejected', data: { node_code: -26 } } })), { onDiagnostic: (event, details) => events.push({ event, details }) });
  const params = [
    ['getaddressbalance', { address: 'tcc1pPrivateAddressNeverLog12345' }],
    ['gettransaction', { txid: hash }],
    ['sendrawtransaction', { transaction_hex: 'cafe'.repeat(50) }],
  ];
  try {
    for (const [method, value] of params) await assert.rejects(server.client.request(method, value), error => error.code === -32020);
    const failures = events.filter(item => item.event === 'rpc.failed');
    assert.deepEqual(failures.map(item => item.details.method), params.map(([method]) => method));
    for (const { details } of failures) {
      assert.deepEqual(Object.keys(details).sort(), ['durationMs', 'error', 'failureSource', 'method', 'notSent', 'sent', 'stage', 'unknownOutcome']);
      assert.equal(details.stage, 'request');
      assert.equal(details.unknownOutcome, false);
      assert.ok(details.durationMs >= 0);
      assert.ok(details.error instanceof RpcError);
      assert.equal(details.error.code, -32020);
      assert.equal(details.error.data.node_code, -26);
    }
    const serialized = JSON.stringify(events);
    for (const [, value] of params) for (const secret of Object.values(value)) assert.equal(serialized.includes(secret), false);
    assert.equal(serialized.includes('127.0.0.1'), false);
    assert.equal(events.filter(item => item.event === 'rpc.connected').length, 1);
    assert.equal(events.some(item => item.event === 'rpc.slow'), false);
  } finally {
    // Intentional client.close clears its socket reference, so its public
    // disconnected event is not promised; diagnostics run on socket.close.
    const disconnected = server.client.socket ? once(server.client.socket, 'close') : Promise.resolve();
    await server.close(); await bounded(disconnected);
  }
  assert.equal(events.filter(item => item.event === 'rpc.disconnected').length, 1);
});

test('transport diagnostics retain the timeout cause and unknown broadcast outcome without retrying', { timeout: FIXTURE_TIMEOUT_MS }, async t => {
  const events = [];
  const received = Promise.withResolvers();
  const server = await mock(() => received.resolve(), { onDiagnostic: (event, details) => events.push({ event, details }) });
  try {
    await server.client.connect();
    const clock = controlledClock(t); server.client.timeoutMs = 30;
    const result = assert.rejects(server.client.request('sendrawtransaction', { transaction_hex: 'ab'.repeat(40) }), error => error.unknownOutcome === true);
    // A local socket.write does not mean the peer's data callback has run.
    // Exercise the actual timeout only after the mock has received the bytes.
    await received.promise;
    assert.equal(server.requests.length, 1); assert.equal(server.client.pending.size, 1);
    clock.tick(29); await settle();
    assert.equal(events.filter(item => item.event === 'rpc.failed').length, 0);
    assert.equal(server.client.pending.size, 1, 'The request must not expire before 30 ms');
    clock.tick(1); await result;
    const failures = events.filter(item => item.event === 'rpc.failed');
    assert.equal(failures.length, 1);
    assert.equal(failures[0].details.method, 'sendrawtransaction');
    assert.equal(failures[0].details.stage, 'request');
    assert.equal(failures[0].details.unknownOutcome, true);
    assert.match(failures[0].details.error.message, /request timed out/);
    assert.equal(failures[0].details.durationMs, 30);
    assert.equal(server.requests.length, 1);
    assert.equal(server.client.pending.size, 0); assert.equal(server.connections, 1);
  } finally { await server.close(); }
});

test('stream protocol failures are diagnosed at the stream stage', async () => {
  const events = [];
  const server = await mock((request, socket) => socket.write([
    response(request, { stream_id: 'diagnostic-stream' }),
    note('stream.chunk', { stream_id: 'diagnostic-stream', sequence: 2, items: { type: 'snapshot' } }),
  ].map(line).join('')), { onDiagnostic: (event, details) => events.push({ event, details }) });
  try {
    await assert.rejects(server.client.request('getblockbounties', { block_hash: hash }, { onChunk() {} }), /invalid or oversized/);
    const failures = events.filter(item => item.event === 'rpc.failed');
    assert.equal(failures.length, 1);
    assert.equal(failures[0].details.method, 'getblockbounties');
    assert.equal(failures[0].details.stage, 'stream');
    assert.equal(failures[0].details.unknownOutcome, false);
    assert.match(failures[0].details.error.message, /invalid or oversized/);
  } finally { await server.close(); }
});

test('connection failures retain their socket code and request context', async () => {
  const events = [];
  const server = await mock(() => {}, { onDiagnostic: (event, details) => events.push({ event, details }) });
  const port = server.client.port;
  await server.close();
  const client = new RpcClient({ host: '127.0.0.1', port, timeoutMs: FIXTURE_TIMEOUT_MS, onDiagnostic: (event, details) => events.push({ event, details }) });
  try {
    await assert.rejects(client.request('getchaintip'), /Cannot connect/);
    const failures = events.filter(item => item.event === 'rpc.failed');
    assert.equal(failures.length, 1);
    assert.equal(failures[0].details.stage, 'connect');
    assert.equal(failures[0].details.method, 'getchaintip');
    assert.equal(failures[0].details.unknownOutcome, false);
    assert.equal(failures[0].details.error.code, 'ECONNREFUSED');
  } finally { client.close(); }
});

test('invalid method names and rejected params are never copied into diagnostics', async () => {
  const events = [];
  const client = new RpcClient({ host: '127.0.0.1', port: 48190, onDiagnostic: (event, details) => events.push({ event, details }) });
  try {
    await assert.rejects(client.request('secret-caller-input', { password: 'secret-password' }), /not allowed/);
    await assert.rejects(client.request('getchaintip', { mnemonic: 'secret-phrase' }), /Unexpected/);
    assert.equal(events.length, 2);
    assert.equal(events[0].details.method, undefined);
    assert.equal(events[1].details.method, 'getchaintip');
    assert.equal(JSON.stringify(events).includes('secret-'), false);
    assert.equal(client.queuedRequests, 0);
    assert.equal(client.socket, null);
  } finally { client.close(); }
});

test('slow diagnostics include pacing time and omit fast successful requests', { timeout: FIXTURE_TIMEOUT_MS }, async t => {
  const events = [];
  const server = await mock((request, socket) => socket.write(line(response(request, true))), {
    quota: 1, windowMs: 1100, onDiagnostic: (event, details) => events.push({ event, details }),
  });
  try {
    await server.client.connect(); const clock = controlledClock(t);
    assert.equal(await server.client.request('getchaintip'), true);
    assert.equal(events.some(item => item.event === 'rpc.slow'), false);
    const waiting = pacingWait(t, server.client);
    const pending = server.client.request('getchaintip');
    assert.equal(await waiting, 1110, 'Real quota pacing contributes to request duration');
    clock.tick(1099); await settle(); assert.equal(server.requests.length, 1);
    clock.tick(11); assert.equal(await pending, true);
    const slow = events.filter(item => item.event === 'rpc.slow');
    assert.equal(slow.length, 1);
    assert.equal(slow[0].details.method, 'getchaintip');
    assert.equal(slow[0].details.stage, 'request');
    assert.equal(slow[0].details.durationMs, 1110);
    assert.equal(events.some(item => item.event === 'rpc.failed'), false);
    assert.equal(server.requests.length, 2);
  } finally { await server.close(); }
});
