import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ClaimerService } from '../src/service.mjs';
import { GENESIS } from '../src/core/config.mjs';

const line = value => JSON.stringify(value) + '\n';
const waitUntil = async predicate => {
  for (let pass = 0; pass < 100; pass++) {
    if (predicate()) return;
    await new Promise(accept => setImmediate(accept));
  }
  assert.fail('Loopback integration did not reach the expected state.');
};

test('real TCP discovery caches empty blocks, follows tips/reorgs, reconnects, and drains on shutdown without TLS attempts', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'connectcoin-claimer-loopback-test-'));
  const statePath = join(directory, 'claimer.conf.state.json');
  const genesis = GENESIS.main, firstTip = '4'.repeat(64), reorgTip = '5'.repeat(64);
  const network = { tip: { height: 0, hash: genesis, mediantime: 1700000000, chain: 'main', genesis_hash: genesis },
    blocks: [{ height: 0, hash: genesis }], cursor: 'first-epoch' };
  const sockets = new Set(), requests = [], streams = [];
  let connections = 0, streamSequence = 0, poolStarts = 0, poolCloses = 0, tlsAttempts = 0, service;
  const server = net.createServer(socket => {
    connections++; sockets.add(socket);
    socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      for (let end; (end = buffer.indexOf('\n')) !== -1;) {
        const request = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        requests.push(request);
        const reply = result => socket.write(line({ jsonrpc: '2.0', id: request.id, result }));
        if (request.method === 'getbountychanges') {
          if (request.params.cursor && request.params.cursor !== network.cursor) {
            socket.write(line({ jsonrpc: '2.0', id: request.id, error: { code: -32011, message: 'Cursor invalidated by test reorganization.' } }));
          } else reply({ tip: network.tip, changes: [], next_cursor: network.cursor, has_more: false });
        } else if (request.method === 'getrecentblockhashes') {
          reply({ tip: network.tip, blocks: network.blocks, window: 600 });
        } else if (request.method === 'getblockbounties') {
          const block = network.blocks.find(item => item.hash === request.params.block_hash);
          assert.ok(block, 'The client requested a block outside the active test window.');
          streams.push(block.hash);
          const id = `loopback-stream-${++streamSequence}`;
          socket.write([
            { jsonrpc: '2.0', id: request.id, result: { stream_id: id } },
            { jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id: id, sequence: 0,
              items: { type: 'snapshot', block_hash: block.hash, tip: network.tip, cursor: network.cursor, unit: 'connects', live: true } } },
            { jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id: id, sequence: 1,
              items: { type: 'state', tip: network.tip, cursor: network.cursor } } },
            { jsonrpc: '2.0', method: 'stream.end', params: { stream_id: id, complete: true, chunks: 2 } },
          ].map(line).join(''));
        } else {
          assert.fail(`Unexpected method in an empty-bounty integration: ${request.method}`);
        }
      }
    });
  });
  t.after(async () => {
    await service?.stop();
    for (const socket of sockets) socket.destroy();
    await new Promise(accept => server.close(accept));
    await rm(directory, { recursive: true, force: true });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  service = new ClaimerService({
    config: { receivingAddress: 'ccpublicreceivingaddress', connectionsPerSecond: 100, concurrency: 100,
      minExpectedReturn: 1000, rpc: { host: '127.0.0.1', port: server.address().port }, network: 'main', lookbackBlocks: 600, feeRate: 1500 },
    statePath,
    // All production components except the external TLS worker are exercised.
    poolFactory: () => ({ pacesStarts: true, async start() { poolStarts++; }, async close() { poolCloses++; },
      async resolve() { assert.fail('An empty bounty list must not resolve claim domains.'); },
      async attempt() { tlsAttempts++; assert.fail('This test must not make TLS attempts.'); },
    }),
    setTimer: (callback, delay) => ({ callback, delay, unref() {} }), clearTimer() {},
  });

  await service.start();
  await waitUntil(() => poolStarts === 1);
  assert.equal(service.snapshot().ready, true);
  assert.equal(service.snapshot().height, 0);
  assert.deepEqual(streams, [genesis]);
  assert.equal(connections, 1);
  assert.equal(requests[0].method, 'getbountychanges');
  assert.equal(requests[0].params.cursor, undefined);

  await service.cycle();
  assert.deepEqual(streams, [genesis], 'An unchanged poll must reuse the complete block snapshot.');
  assert.equal(connections, 1, 'RPC methods share one persistent socket.');

  network.tip = { ...network.tip, height: 1, hash: firstTip, mediantime: 1700000001 };
  network.blocks = [{ height: 1, hash: firstTip }, { height: 0, hash: genesis }];
  await service.cycle();
  assert.deepEqual(streams, [genesis, firstTip], 'Tip growth fetches only the new block.');
  assert.equal(service.snapshot().height, 1);

  const disconnected = once(service.rpc, 'disconnected');
  for (const socket of sockets) socket.destroy();
  await disconnected;
  assert.equal(service.ready, false);
  await service.cycle();
  assert.equal(connections, 2);
  assert.equal(service.ready, true);
  assert.deepEqual(streams, [genesis, firstTip], 'Reconnect catches up from the saved cursor without a redundant full scan.');

  network.tip = { ...network.tip, hash: reorgTip, mediantime: 1700000002 };
  network.blocks = [{ height: 1, hash: reorgTip }, { height: 0, hash: genesis }];
  network.cursor = 'reorg-epoch';
  await service.cycle();
  assert.equal(service.tip.hash, reorgTip);
  assert.equal(service.blocks.has(firstTip), false);
  assert.deepEqual(streams, [genesis, firstTip, genesis, reorgTip], 'Expired cursors discard the old snapshot and reload the active window oldest first.');
  assert.equal(tlsAttempts, 0);
  assert.equal(requests.some(request => request.method === 'sendrawtransaction'), false);

  await service.stop();
  await waitUntil(() => sockets.size === 0);
  assert.equal(service.snapshot().status, 'stopped');
  assert.equal(service.rpc.closed, true);
  assert.equal(poolCloses, poolStarts);
  assert.equal(service.engine.running, null);
  await assert.rejects(stat(statePath), { code: 'ENOENT' });
});
