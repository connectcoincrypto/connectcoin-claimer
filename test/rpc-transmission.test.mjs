import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { RpcClient } from '../src/core/rpc.mjs';
import { diagnosticError } from '../src/core/diagnostics.mjs';

const hash = 'a'.repeat(64), transaction = '1234'.repeat(20);
const frame = message => JSON.stringify(message) + '\n';
const observed = promise => promise.then(value => ({ value }), error => ({ error }));
const unsent = error => {
  assert.equal(error.notSent, true);
  assert.notEqual(error.unknownOutcome, true);
  return true;
};
const uncertain = error => {
  assert.equal(error.unknownOutcome, true);
  assert.notEqual(error.notSent, true);
  return true;
};
async function until(predicate) {
  const deadline = performance.now() + 2000;
  while (!predicate()) {
    if (performance.now() >= deadline) assert.fail('Transmission fixture timed out');
    await delay(2);
  }
}
async function fixture(t, handler = () => {}, options = {}) {
  const requests = [], sockets = new Set(), events = [];
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', data => {
      buffer += data.toString('utf8');
      let end;
      while ((end = buffer.indexOf('\n')) !== -1) {
        const request = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        requests.push({ request, socket }); handler(request, socket);
      }
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const client = new RpcClient({ host: '127.0.0.1', port: server.address().port, timeoutMs: 1000,
    onDiagnostic: (event, details) => events.push({ event, details }), ...options });
  t.after(async () => {
    client.close(); for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  const answer = (index, result = true) => {
    const { request, socket } = requests[index];
    socket.write(frame({ jsonrpc: '2.0', id: request.id, result }));
  };
  return { client, requests, events, answer };
}

test('every locally proven pre-write failure marks a broadcast notSent, not unknown', async t => {
  for (const mode of ['queue-limit', 'closed-client', 'preconnect', 'connection-refused', 'id-exhausted', 'output-buffer', 'bad-params']) {
    await t.test(mode, async t => {
      const f = await fixture(t);
      if (mode === 'queue-limit') f.client.queuedRequests = 32;
      if (mode === 'closed-client') f.client.close();
      if (mode === 'preconnect' || mode === 'connection-refused') f.client.connect = async () => {
        throw mode === 'preconnect' ? new Error('RPC connection is closed.') : Object.assign(new Error('Refused'), { code: 'ECONNREFUSED' });
      };
      if (mode === 'id-exhausted') f.client.nextId = Number.MAX_SAFE_INTEGER;
      if (mode === 'output-buffer') {
        await f.client.connect();
        Object.defineProperty(f.client.socket, 'writableLength', { value: 2 * 1024 * 1024, configurable: true });
      }
      await assert.rejects(f.client.request('sendrawtransaction', { transaction_hex: mode === 'bad-params' ? 'bad' : transaction }), error => {
        unsent(error);
        if (mode === 'queue-limit') assert.equal(error.code, 'RPC_QUEUE_FULL');
        return true;
      });
      assert.equal(f.requests.length, 0);
      assert.equal(f.client.pending.size, 0);
      assert.equal(f.client.capacityReservations, 0);
      assert.equal(f.client.history.has('sendrawtransaction'), false);
      const diagnostic = f.events.find(row => ['rpc.failed', 'rpc.cancelled'].includes(row.event));
      assert.equal(diagnostic.details.sent, false);
      assert.equal(diagnostic.details.notSent, true);
      assert.equal(diagnostic.details.failureSource, 'pre-write');
    });
  }
});

test('a server cannot forge local queue exhaustion after a broadcast write', async t => {
  const f = await fixture(t, (request, socket) => socket.write(frame({ jsonrpc: '2.0', id: request.id,
    error: { code: 'RPC_QUEUE_FULL', message: 'Too many queued RPC requests; retry shortly.', data: { notSent: true } } })));
  await assert.rejects(f.client.request('sendrawtransaction', { transaction_hex: transaction }), error => {
    uncertain(error); assert.notEqual(error.code, 'RPC_QUEUE_FULL'); return true;
  });
  assert.equal(f.requests.length, 1); assert.equal(f.client.pending.size, 0);
});

test('real loopback connection refusal is proven unsent', async () => {
  const server = net.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  const client = new RpcClient({ host: '127.0.0.1', port, timeoutMs: 1000 });
  try {
    await assert.rejects(client.request('sendrawtransaction', { transaction_hex: transaction }), error => {
      assert.match(error.message, /Cannot connect to RPC/); return unsent(error);
    });
    assert.equal(client.pending.size, 0);
  } finally { client.close(); }
});

test('quota cancellation is unsent and never invokes the final transmission fence', async t => {
  const f = await fixture(t, (request, socket) => socket.write(frame({ jsonrpc: '2.0', id: request.id, result: { txid: hash } })),
    { quota: 1, windowMs: 60000 });
  await f.client.request('sendrawtransaction', { transaction_hex: transaction });
  const controller = new AbortController(); let fenced = false;
  const next = observed(f.client.request('sendrawtransaction', { transaction_hex: transaction },
    { signal: controller.signal, beforeSend() { fenced = true; } }));
  await until(() => f.client.queuedRequests === 1);
  controller.abort(); unsent((await next).error);
  assert.equal(f.requests.length, 1); assert.equal(fenced, false);
  assert.equal(f.client.capacityReservations, 0);
  assert.equal(f.client.history.get('sendrawtransaction').length, 1);
});

test('48 revoked final fences consume no quota and the next legitimate broadcast is sent immediately', async t => {
  const f = await fixture(t, (request, socket) => socket.write(frame({ jsonrpc: '2.0', id: request.id, result: { txid: hash } })),
    { quota: 48, windowMs: 60000 });
  for (let index = 0; index < 48; index++) {
    await assert.rejects(f.client.request('sendrawtransaction', { transaction_hex: transaction }, { beforeSend() {
      throw Object.assign(new Error('Catalog changed before transmission.'), { name: 'AbortError', code: 'ABORT_ERR' });
    } }), unsent);
    assert.equal(f.client.history.has('sendrawtransaction'), false);
  }
  assert.equal(f.requests.length, 0);
  assert.equal(f.client.quotaWait('sendrawtransaction', {}), 0);
  const result = await f.client.request('sendrawtransaction', { transaction_hex: transaction }, { signal: AbortSignal.timeout(2000) });
  assert.equal(result.txid, hash);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].request.params.transaction_hex, transaction);
  assert.equal(f.client.history.get('sendrawtransaction').length, 1);
  assert.equal(f.client.pending.size, 0); assert.equal(f.client.capacityReservations, 0);
});

test('capacity-delayed catalog reset rejects at beforeSend without disturbing written siblings', async t => {
  const f = await fixture(t);
  const holding = Array.from({ length: 12 }, () => observed(f.client.request('gettransaction', { txid: hash })));
  await until(() => f.requests.length === 12);
  let gateOpen = true, calls = 0;
  const broadcast = observed(f.client.request('sendrawtransaction', { transaction_hex: transaction }, { beforeSend() {
    calls++;
    if (!gateOpen) throw Object.assign(new Error('Catalog changed before transmission.'), { name: 'AbortError', code: 'ABORT_ERR' });
  } }));
  await until(() => f.client.capacityWaiters.length === 1);
  gateOpen = false; f.answer(0);
  unsent((await broadcast).error);
  assert.equal(calls, 1); assert.equal(f.requests.length, 12);
  assert.equal(f.client.history.has('sendrawtransaction'), false);
  assert.equal(f.client.pending.size, 11); assert.equal(f.client.capacityReservations, 0);
  assert.equal(f.client.socket.destroyed, false);
  for (let index = 1; index < 12; index++) f.answer(index);
  assert.ok((await Promise.all(holding)).every(result => result.value === true));
});

test('beforeSend forbids asynchronous fences and checks a fence-triggered abort before write', async t => {
  for (const mode of ['resolved-promise', 'rejected-promise', 'throws', 'abort', 'client-close', 'socket-close', 'not-function']) {
    await t.test(mode, async t => {
      const f = await fixture(t), controller = new AbortController();
      const beforeSend = mode === 'not-function' ? true : () => {
        if (mode === 'resolved-promise') return Promise.resolve();
        if (mode === 'rejected-promise') return Promise.reject(new Error('Fence failed asynchronously.'));
        if (mode === 'throws') throw new Error('Fence denied.');
        if (mode === 'client-close') { f.client.close(); return; }
        if (mode === 'socket-close') { f.client.socket.destroy(); return; }
        controller.abort();
      };
      await assert.rejects(f.client.request('sendrawtransaction', { transaction_hex: transaction },
        { beforeSend, signal: controller.signal }), unsent);
      assert.equal(f.requests.length, 0); assert.equal(f.client.pending.size, 0);
      assert.equal(f.client.capacityReservations, 0); assert.equal(f.client.queuedRequests, 0);
      assert.equal(f.client.history.has('sendrawtransaction'), false);
    });
  }
});

test('a cooldown changed by a final fence spends no quota and requires a new fence after waiting', async t => {
  const f = await fixture(t, (request, socket) => socket.write(frame({ jsonrpc: '2.0', id: request.id, result: { txid: hash } })));
  let fences = 0;
  const pending = f.client.request('sendrawtransaction', { transaction_hex: transaction }, { beforeSend() {
    if (++fences === 1) f.client.cooldowns.set('sendrawtransaction', performance.now() + 200);
  } });
  await until(() => fences === 1);
  assert.equal(f.client.history.has('sendrawtransaction'), false);
  assert.equal(f.client.capacityReservations, 0);
  assert.equal(f.requests.length, 0);
  assert.equal((await pending).txid, hash);
  assert.equal(fences, 2);
  assert.equal(f.requests.length, 1);
  assert.equal(f.client.history.get('sendrawtransaction').length, 1);
});

test('after-write loss and timeout stay unknown and diagnostics distinguish their origin', async t => {
  for (const mode of ['socket-close', 'request-timeout', 'socket-write', 'client-close']) {
    await t.test(mode, async t => {
      const f = await fixture(t, (_request, socket) => { if (mode === 'socket-close') socket.destroy(); }, { timeoutMs: 5000 });
      // Establish the fixture before testing an after-write failure. A short
      // connection deadline can legitimately fail before transmission under
      // CPU contention, which is a different (notSent) case covered above.
      await f.client.connect();
      if (mode === 'request-timeout') f.client.timeoutMs = 100;
      if (mode === 'socket-write') {
        t.mock.method(f.client.socket, 'write', () => { throw new Error('Synchronous write failure'); });
      }
      const pending = observed(f.client.request('sendrawtransaction', { transaction_hex: transaction }));
      if (mode === 'client-close') { await until(() => f.requests.length === 1); f.client.close(); }
      uncertain((await pending).error);
      const failure = f.events.find(row => row.event === 'rpc.failed' && row.details.method === 'sendrawtransaction').details;
      assert.equal(failure.sent, true); assert.equal(failure.notSent, false);
      assert.equal(failure.unknownOutcome, true); assert.equal(failure.failureSource, mode);
      assert.ok(f.requests.length <= 1);
      assert.equal(f.client.history.get('sendrawtransaction').length, 1);
    });
  }
});

test('stream timeout records its source on a concurrent unknown broadcast without leaking transaction bytes', async t => {
  const f = await fixture(t, (request, socket) => {
    if (request.method === 'getblockbounties') socket.write(frame({ jsonrpc: '2.0', id: request.id, result: { stream_id: 'slow' } }));
  }, { timeoutMs: 160 });
  const stream = observed(f.client.request('getblockbounties', { block_hash: hash }, { onChunk() {} }));
  await until(() => f.client.streams.size === 1);
  await delay(25);
  const broadcast = observed(f.client.request('sendrawtransaction', { transaction_hex: transaction }));
  await until(() => f.requests.length === 2);
  const [streamResult, broadcastResult] = await Promise.all([stream, broadcast]);
  assert.match(streamResult.error.message, /Bounty transfer timed out/);
  uncertain(broadcastResult.error);
  const failures = f.events.filter(row => row.event === 'rpc.failed');
  assert.equal(failures.length, 2);
  for (const { details } of failures) {
    assert.equal(details.failureSource, 'stream-timeout');
    assert.equal(details.sent, true); assert.equal(details.notSent, false);
    assert.equal(diagnosticError(details.error).category, 'timeout');
  }
  assert.equal(JSON.stringify(f.events).includes(transaction), false);
});

test('well-framed node replies including -27 are not reclassified as unsent or transport-unknown', async t => {
  for (const node_code of [-27, -26, -25, -22, -8]) {
    await t.test(String(node_code), async t => {
      const f = await fixture(t, (request, socket) => socket.write(frame({ jsonrpc: '2.0', id: request.id,
        error: { code: -32020, message: 'Node rejected', data: { node_code } } })));
      await assert.rejects(f.client.request('sendrawtransaction', { transaction_hex: transaction }), error => {
        assert.equal(error.code, -32020); assert.equal(error.data.node_code, node_code);
        assert.notEqual(error.notSent, true); assert.notEqual(error.unknownOutcome, true); return true;
      });
      const failure = f.events.find(row => row.event === 'rpc.failed').details;
      assert.equal(failure.failureSource, 'rpc-reply');
      assert.equal(failure.sent, true); assert.equal(failure.notSent, false);
      assert.equal(f.requests.length, 1);
      assert.equal(f.client.history.get('sendrawtransaction').length, 1);
    });
  }
});
