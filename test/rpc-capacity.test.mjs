import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { setTimeout as sleep } from 'node:timers/promises';
import { RpcClient } from '../src/core/rpc.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const frame = value => `${JSON.stringify(value)}\n`;
const observed = promise => promise.then(value => ({ value }), error => ({ error }));
async function until(predicate) {
  const deadline = performance.now() + 2000;
  while (!predicate()) { if (performance.now() > deadline) assert.fail('RPC capacity fixture timed out'); await sleep(2); }
}
async function fixture(t, options = {}) {
  const requests = [], sockets = new Set(); let connections = 0;
  const server = net.createServer(socket => {
    connections++; sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8'); let end;
      while ((end = buffer.indexOf('\n')) !== -1) {
        const request = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        requests.push({ request, socket, at: performance.now(), answered: false, connection: connections });
      }
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const client = new RpcClient({ host: '127.0.0.1', port: server.address().port, timeoutMs: 1500, ...options });
  t.after(async () => { client.close(); for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const answer = (index, result = true, error) => {
    const row = requests[index]; assert.ok(row && !row.answered); row.answered = true;
    row.socket.write(frame({ jsonrpc: '2.0', id: row.request.id, ...(error ? { error } : { result }) }));
  };
  return { client, requests, answer, get connections() { return connections; } };
}
const regular = (client, n, signal) => observed(client.request('gettransaction', { txid: hash(n) }, { signal }));

test('FIFO capacity gate holds at 12 on one socket, retains 32-request bound, and drains mixed claims/read work', async t => {
  const f = await fixture(t), jobs = [];
  const specification = Array.from({ length: 32 }, (_, n) => {
    switch (n % 4) {
      case 0: return ['gettransaction', { txid: hash(n) }];
      case 1: return ['sendrawtransaction', { transaction_hex: hash(n) }];
      case 2: return ['subscribeaddress', { address: `fixtureaddress${n}` }];
      default: return ['getaddresshistory', { address: `fixtureaddress${n}` }];
    }
  });
  for (const args of specification) jobs.push(observed(f.client.request(...args)));
  await until(() => f.requests.length === 12);
  assert.equal(f.client.pending.size, 12); assert.equal(f.client.capacityWaiters.length, 20);
  await assert.rejects(f.client.request('getchaintip'), /Too many queued/);
  await sleep(15); assert.equal(f.requests.length, 12);
  let replies = 0;
  while (replies < 32) {
    await until(() => f.requests.length > replies);
    assert.ok(f.client.pending.size + f.client.streams.size + f.client.capacityReservations <= 12);
    f.answer(replies++, true);
  }
  assert.ok((await Promise.all(jobs)).every(result => result.value === true));
  assert.deepEqual(f.requests.map(({ request }) => [request.method, request.params]), specification);
  assert.equal(f.client.capacityReservations, 0); assert.equal(f.client.capacityWaiters.length, 0);
  assert.equal(f.client.pending.size, 0); assert.equal(f.client.queuedRequests, 0); assert.equal(f.connections, 1);
});

test('capacity cancellation removes waiting reads and an unsent broadcast without touching active requests', async t => {
  const f = await fixture(t), holding = Array.from({ length: 12 }, (_, n) => regular(f.client, n));
  await until(() => f.requests.length === 12);
  const readController = new AbortController(), broadcastController = new AbortController();
  const read = regular(f.client, 100, readController.signal);
  const broadcast = observed(f.client.request('sendrawtransaction', { transaction_hex: hash(101) }, { signal: broadcastController.signal }));
  await until(() => f.client.capacityWaiters.length === 2);
  readController.abort(); broadcastController.abort();
  for (const { error } of await Promise.all([read, broadcast])) {
    assert.equal(error.name, 'AbortError'); assert.equal(error.notSent, true); assert.notEqual(error.unknownOutcome, true);
  }
  assert.equal(f.client.capacityWaiters.length, 0); assert.equal(f.requests.length, 12); assert.equal(f.client.pending.size, 12);
  for (let n = 0; n < 12; n++) f.answer(n);
  assert.ok((await Promise.all(holding)).every(result => result.value === true));
});

test('closing a saturated client settles capacity waiters and never transmits a queued broadcast', async t => {
  const f = await fixture(t), holding = Array.from({ length: 12 }, (_, n) => regular(f.client, n));
  await until(() => f.requests.length === 12);
  const waiting = [regular(f.client, 100), observed(f.client.request('sendrawtransaction', { transaction_hex: hash(101) }))];
  await until(() => f.client.capacityWaiters.length === 2);
  f.client.close();
  assert.ok((await Promise.all(holding)).every(result => result.error.name === 'AbortError'));
  assert.ok((await Promise.all(waiting)).every(result => result.error.name === 'AbortError' && result.error.notSent && !result.error.unknownOutcome));
  assert.equal(f.client.capacityWaiters.length, 0); assert.equal(f.client.capacityReservations, 0);
  assert.equal(f.client.queuedRequests, 0); assert.equal(f.requests.length, 12);
});

test('socket loss rejects old capacity waiters; explicit subsequent request alone opens a new socket', async t => {
  const f = await fixture(t), holding = Array.from({ length: 12 }, (_, n) => regular(f.client, n));
  await until(() => f.requests.length === 12);
  const waiting = [regular(f.client, 100), observed(f.client.request('sendrawtransaction', { transaction_hex: hash(101) }))];
  await until(() => f.client.capacityWaiters.length === 2);
  f.requests[0].socket.destroy();
  assert.ok((await Promise.all([...holding, ...waiting])).every(result => result.error && !result.error.unknownOutcome));
  assert.equal(f.client.capacityWaiters.length, 0); assert.equal(f.requests.length, 12); assert.equal(f.connections, 1);
  const next = regular(f.client, 102); await until(() => f.requests.length === 13); f.answer(12);
  assert.equal((await next).value, true); assert.equal(f.connections, 2);
  assert.equal(f.requests[12].request.params.txid, hash(102));
});

test('structured RPC rejection frees exactly one capacity slot', async t => {
  const f = await fixture(t), holding = Array.from({ length: 12 }, (_, n) => regular(f.client, n));
  await until(() => f.requests.length === 12);
  const waiting = [regular(f.client, 100), regular(f.client, 101)];
  await until(() => f.client.capacityWaiters.length === 2);
  f.answer(0, undefined, { code: -32020, message: 'Rejected' });
  await until(() => f.requests.length === 13); await sleep(15);
  assert.equal(f.requests.length, 13); assert.equal(f.client.pending.size, 12); assert.equal(f.client.capacityWaiters.length, 1);
  for (let n = 1; n < 13; n++) f.answer(n);
  await until(() => f.requests.length === 14); f.answer(13);
  assert.equal((await holding[0]).error.code, -32020);
  assert.ok((await Promise.all([...holding.slice(1), ...waiting])).every(result => result.value === true));
});

test('stream transition and abandoned drain retain a capacity slot until validated stream.end', async t => {
  const f = await fixture(t), holding = Array.from({ length: 11 }, (_, n) => regular(f.client, n));
  const streaming = observed(f.client.request('getblockbounties', { block_hash: hash(999) }, { onChunk() {
    throw Object.assign(new Error('Consumer stopped'), { name: 'AbortError', code: 'ABORT_ERR' });
  } }));
  await until(() => f.requests.length === 12);
  const index = f.requests.findIndex(row => row.request.method === 'getblockbounties');
  const waiting = regular(f.client, 100); await until(() => f.client.capacityWaiters.length === 1);
  f.answer(index, { stream_id: 'held-stream' });
  await until(() => f.client.streams.size === 1);
  assert.equal(f.client.pending.size, 11); assert.equal(f.requests.length, 12);
  const note = (method, params) => frame({ jsonrpc: '2.0', method, params: { stream_id: 'held-stream', ...params } });
  f.requests[index].socket.write(note('stream.chunk', { sequence: 0, items: { type: 'snapshot' } }));
  assert.equal((await streaming).error.name, 'AbortError');
  await sleep(15); assert.equal(f.requests.length, 12); assert.equal(f.client.streams.size, 1);
  assert.equal(f.client.streams.get('held-stream').abandoned, true);
  f.requests[index].socket.write(note('stream.chunk', { sequence: 1, items: { type: 'state' } }) + note('stream.end', { chunks: 2, complete: true }));
  await until(() => f.requests.length === 13); assert.equal(f.client.streams.size, 0);
  for (let n = 0; n < 13; n++) if (!f.requests[n].answered) f.answer(n);
  assert.ok((await Promise.all([...holding, waiting])).every(result => result.value === true));
  assert.equal(f.connections, 1); assert.equal(f.client.capacityReservations, 0);
});

test('long capacity waits debit quota at transmission, not at the expired original admission', async t => {
  const f = await fixture(t, { quota: 2, windowMs: 100 });
  const kinds = [['getchaintip', {}], ['getrecentblockhashes', {}], ['gettransaction', { txid: hash(1) }],
    ['getaddressbalance', { address: 'fixtureaddress' }], ['getaddressutxos', { address: 'fixtureaddress' }], ['subscribetip', {}]];
  const holding = kinds.flatMap(args => [observed(f.client.request(...args)), observed(f.client.request(...args))]);
  await until(() => f.requests.length === 12);
  const transmitted = [], write = f.client.socket.write;
  t.mock.method(f.client.socket, 'write', function (encoded, ...args) {
    const request = JSON.parse(encoded);
    if (request.method === 'getaddresshistory') {
      // Capture the quota debit at the real client write boundary. Server
      // data callbacks can be delayed/coalesced on a busy runner, making
      // correctly spaced transmissions appear to arrive too close together.
      const debitedAt = f.client.history.get(request.method)?.at(-1);
      assert.ok(Number.isFinite(debitedAt), 'each transmission must have a quota debit');
      transmitted.push({ id: request.id, debitedAt });
    }
    return write.call(this, encoded, ...args);
  });
  const queued = Array.from({ length: 3 }, () => observed(f.client.request('getaddresshistory', { address: 'fixtureaddress' })));
  await until(() => f.client.capacityWaiters.length === 3);
  await sleep(140); // Greater than the full quota window while all slots are busy.
  assert.equal(f.client.history.has('getaddresshistory'), false);
  for (let n = 0; n < 12; n++) f.answer(n);
  await until(() => f.requests.length >= 14);
  assert.equal(f.client.capacityReservations, 0); // The rate-limited third read holds no slot.
  f.answer(12); f.answer(13);
  await until(() => f.requests.length === 15);
  assert.deepEqual(transmitted.map(row => row.id), f.requests.slice(12).map(row => row.request.id));
  assert.equal(transmitted.length, 3);
  assert.ok(transmitted[2].debitedAt - transmitted[0].debitedAt >= f.client.windowMs,
    'the third transmitted request must consume quota in a new window');
  f.answer(14);
  assert.ok((await Promise.all([...holding, ...queued])).every(result => result.value === true));
});

test('a new server cooldown is rechecked after a capacity wait without blocking unrelated methods', async t => {
  const f = await fixture(t), holding = Array.from({ length: 12 }, (_, n) => regular(f.client, n));
  await until(() => f.requests.length === 12);
  const cooling = regular(f.client, 100), unrelated = observed(f.client.request('getchaintip'));
  await until(() => f.client.capacityWaiters.length === 2);
  const rejectedAt = performance.now();
  f.answer(0, undefined, { code: -32029, message: 'Rate limited', data: { retry_after_ms: 120 } });
  await until(() => f.requests.length === 13);
  assert.equal(f.requests[12].request.method, 'getchaintip');
  assert.equal(f.client.capacityReservations, 0);
  for (let n = 1; n < 13; n++) f.answer(n);
  await until(() => f.requests.length === 14);
  assert.equal(f.requests[13].request.method, 'gettransaction');
  assert.ok(f.requests[13].at - rejectedAt >= 110); f.answer(13);
  assert.equal((await holding[0]).error.code, -32029);
  assert.ok((await Promise.all([...holding.slice(1), cooling, unrelated])).every(result => result.value === true));
});

test('cancellation between slot grant and continuation releases its reservation before any write', async t => {
  const f = await fixture(t), holding = Array.from({ length: 12 }, (_, n) => regular(f.client, n));
  await until(() => f.requests.length === 12);
  const controller = new AbortController(), original = f.client.waitForCapacity.bind(f.client);
  let intercept = true;
  f.client.waitForCapacity = async (...args) => {
    const release = await original(...args);
    if (intercept) { intercept = false; controller.abort(); }
    return release;
  };
  const broadcast = observed(f.client.request('sendrawtransaction', { transaction_hex: hash(123) }, { signal: controller.signal }));
  await until(() => f.client.capacityWaiters.length === 1);
  f.answer(0);
  const result = await broadcast;
  assert.equal(result.error.name, 'AbortError'); assert.equal(result.error.notSent, true); assert.notEqual(result.error.unknownOutcome, true);
  assert.equal(f.client.capacityReservations, 0); assert.equal(f.requests.length, 12);
  assert.equal(f.client.history.has('sendrawtransaction'), false);
  const next = regular(f.client, 124); await until(() => f.requests.length === 13); f.answer(12);
  for (let n = 1; n < 12; n++) f.answer(n);
  assert.ok((await Promise.all([...holding, next])).every(row => row.value === true));
});

test('global not-ready cooldown received while saturated also holds queued unrelated methods', async t => {
  const f = await fixture(t), holding = Array.from({ length: 12 }, (_, n) => regular(f.client, n));
  await until(() => f.requests.length === 12);
  const waiting = [regular(f.client, 100), observed(f.client.request('getchaintip'))];
  await until(() => f.client.capacityWaiters.length === 2);
  const rejectedAt = performance.now();
  f.answer(0, undefined, { code: -32001, message: 'Not ready' });
  for (let n = 1; n < 12; n++) f.answer(n);
  await sleep(30);
  assert.equal(f.requests.length, 12); assert.equal(f.client.capacityReservations, 0);
  await until(() => f.requests.length === 14);
  assert.ok(f.requests[12].at - rejectedAt >= 980); f.answer(12); f.answer(13);
  assert.equal((await holding[0]).error.code, -32001);
  assert.ok((await Promise.all([...holding.slice(1), ...waiting])).every(row => row.value === true));
});
