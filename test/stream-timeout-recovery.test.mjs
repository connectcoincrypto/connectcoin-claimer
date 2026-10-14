import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { ClaimerService } from '../src/service.mjs';
import { RpcClient } from '../src/core/rpc.mjs';
import { GENESIS } from '../src/core/config.mjs';

const tip = { height: 0, hash: GENESIS.main, mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };

async function fixture(t, timeoutMs = 501) {
  let mode = 'complete', sequence = 0;
  const sockets = new Set(), calls = [], timers = [];
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', data => {
      buffer += data;
      for (let end; (end = buffer.indexOf('\n')) >= 0;) {
        const request = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        calls.push(request);
        const send = message => socket.write(JSON.stringify(message) + '\n');
        const reply = result => send({ jsonrpc: '2.0', id: request.id, result });
        if (request.method === 'getbountychanges') {
          if (mode !== 'complete' && sequence === 0) sequence++;
          // The incomplete cycle must request the same journal interval again.
          reply({ tip, changes: sequence > 0 && request.params.cursor !== `watermark-${sequence}` ? [{ type: 'added', sequence,
            txid: 'a'.repeat(64), vout: 0, block_hash: tip.hash }] : [], has_more: false, next_cursor: `watermark-${sequence}` });
        } else if (request.method === 'getrecentblockhashes') {
          reply({ tip, window: 600, blocks: [{ height: 0, hash: tip.hash }] });
        } else if (request.method === 'getchaintip') reply(tip);
        else if (request.method === 'getblockbounties') {
          const stream_id = `stream-${calls.length}`;
          reply({ stream_id });
          send({ jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id, sequence: 0,
            items: { type: 'snapshot', block_hash: tip.hash, tip, cursor: `watermark-${sequence}`, unit: 'connects' } } });
          if (mode === 'timeout') continue;
          send({ jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id, sequence: mode === 'bad-sequence' ? 7 : 1,
            items: { type: 'state', tip, cursor: `watermark-${sequence}` } } });
          send({ jsonrpc: '2.0', method: 'stream.end', params: { stream_id, complete: mode !== 'incomplete', chunks: 2 } });
        // A submitted broadcast with a lost reply must remain unknown when a
        // sibling read fails. No real transaction or outside endpoint is used.
        } else if (request.method !== 'sendrawtransaction') assert.fail(`Unexpected method: ${request.method}`);
      }
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const journal = { async load() { return []; }, unresolved() { return []; }, async flush() {} };
  const service = new ClaimerService({ config: { receivingAddress: 'ccpublicreceivingaddress', connectionsPerSecond: 100,
    concurrency: 100, minExpectedReturn: 1000, rpc: { host: '127.0.0.1', port: server.address().port }, network: 'main', lookbackBlocks: 600, feeRate: 1500 },
    journal, rpcFactory: options => new RpcClient({ ...options, timeoutMs }),
    poolFactory: () => ({ pacesStarts: true, async start() {}, async close() {},
      async resolve() { assert.fail('Offline test must never resolve a bounty domain.'); },
      async attempt() { assert.fail('Offline test must never perform a TLS capture.'); } }),
    setTimer: (callback, delay) => { const timer = { callback, delay, unref() {} }; timers.push(timer); return timer; },
    clearTimer: timer => { timer.cleared = true; },
  });
  t.after(async () => {
    await service.stop();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  await service.start(); await service.engine.poolReady;
  assert.equal(service.ready, true);
  return { service, calls, timers, setMode(value) { mode = value; } };
}

for (const kind of ['idle', 'total-deadline']) {
test(`real bounty stream timeout (${kind}) reconnects automatically without publishing its partial cursor`, async t => {
  if (kind === 'total-deadline') {
    const realTimeout = globalThis.setTimeout;
    // Exercise the real 180s deadline callback without waiting three minutes;
    // normal request/idle timers remain real and longer than this deadline.
    t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => realTimeout(callback, delay === 180000 ? 501 : delay, ...args));
  }
  const { service, calls, timers, setMode } = await fixture(t, kind === 'total-deadline' ? 5000 : 501);
  const oldBlocks = service.blocks, oldCursor = service.cursor;
  const oldCounters = { ...service.engine.state };
  const disconnected = once(service.rpc, 'disconnected');
  setMode('timeout');
  await service.cycle(); await disconnected; await service.suspending;
  assert.equal(service.status, 'reconnecting');
  assert.equal(service.running, true); assert.equal(service.ready, false); assert.equal(service.fatalError, null);
  assert.equal(service.lastError, kind === 'idle' ? 'Bounty transfer timed out.' : 'Bounty transfer exceeded its total time limit.');
  assert.strictEqual(service.blocks, oldBlocks); assert.equal(service.cursor, oldCursor);
  for (const field of ['attempts', 'completed']) assert.equal(service.engine.state[field], oldCounters[field]);
  assert.equal(timers.at(-1).delay, service.retryMinMs);
  setMode('complete');
  const streamsBefore = calls.filter(call => call.method === 'getblockbounties').length;
  timers.at(-1).callback();
  assert.ok(service.cycling, 'The scheduled retry must start without a manual Stop/Start.');
  await service.cycling;
  assert.equal(service.running, true); assert.equal(service.ready, true); assert.equal(service.status, 'running');
  assert.equal(service.fatalError, null); assert.equal(service.lastError, null);
  assert.ok(calls.filter(call => call.method === 'getblockbounties').length > streamsBefore);
  assert.notEqual(service.cursor, oldCursor);
});
}

test('a written broadcast stays unknown when a sibling bounty stream times out', async t => {
  const { service, calls, setMode } = await fixture(t);
  const disconnected = once(service.rpc, 'disconnected');
  const snapshotProcessed = Promise.withResolvers();
  const receive = service.rpc.receive;
  t.mock.method(service.rpc, 'receive', function (message, ...args) {
    const result = receive.call(this, message, ...args);
    // Observe the real parser/callback after it accepted the first chunk. A
    // fixed number of event-loop turns can finish before TCP delivers it (for
    // example with delayed ACK/Nagle), even though no RPC timeout has elapsed.
    if (message.method === 'stream.chunk' && message.params.sequence === 0 &&
        this.streams.get(message.params.stream_id)?.next === 1) snapshotProcessed.resolve();
    return result;
  });
  setMode('timeout');
  const cycle = service.cycle();
  await snapshotProcessed.promise;
  assert.ok([...service.rpc.streams.values()].some(stream => stream.next === 1));
  const broadcast = service.rpc.request('sendrawtransaction', { transaction_hex: 'ab'.repeat(50) }).then(
    () => assert.fail('The test server never acknowledged this broadcast.'), error => error);
  const failure = await broadcast;
  await cycle; await disconnected; await service.suspending;
  assert.equal(failure.unknownOutcome, true); assert.notEqual(failure.notSent, true);
  assert.equal(calls.filter(call => call.method === 'sendrawtransaction').length, 1);
  assert.equal(service.running, true); assert.equal(service.fatalError, null);
});

for (const mode of ['bad-sequence', 'incomplete']) {
  test(`malformed bounty stream remains fatal (${mode}), not a recoverable timeout`, async t => {
    const { service, setMode } = await fixture(t);
    const oldBlocks = service.blocks, oldCursor = service.cursor;
    setMode(mode); await service.cycle(); await service.suspending;
    assert.equal(service.running, false); assert.equal(service.status, 'failed');
    assert.match(service.fatalError.message, mode === 'bad-sequence' ? /invalid or oversized response/ : /stream was incomplete/);
    assert.strictEqual(service.blocks, oldBlocks); assert.equal(service.cursor, oldCursor);
  });
}
