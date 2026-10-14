import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { ClaimerService } from '../src/service.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { transactionIdFromRaw } from '../src/core/transaction.mjs';

const tip = { height: 0, hash: GENESIS.main, genesis_hash: GENESIS.main, chain: 'main', mediantime: 1700000000 };
const parent = '0200000001548c9fc15a3c2bc70e81307961d1350359b8d080130859f526cc1c794bd54eb30000000000ffffffff0138bd9252020000000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000';
async function until(predicate) {
  const deadline = performance.now() + 4000;
  while (!predicate()) { assert.ok(performance.now() < deadline, 'Loopback backlog did not drain'); await delay(2); }
}

for (const resetting of [false, true]) test(`temporary RPC queue exhaustion recovers without stopping claims (catalog reset: ${resetting})`, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-backpressure-'));
  const sockets = new Set(), waiting = [], parents = new Map(), requests = [];
  let hold = true, service;
  const answer = (socket, request, result) => socket.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\n');
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8');
      for (let end; (end = buffer.indexOf('\n')) !== -1;) {
        const request = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1); requests.push(request);
        if (request.method === 'getchaintip') answer(socket, request, tip);
        else {
          assert.equal(request.method, 'gettransaction'); assert.ok(parents.has(request.params.txid));
          const reply = () => answer(socket, request, { tip, transaction: { hex: parents.get(request.params.txid) } });
          if (hold) waiting.push(reply); else reply();
        }
      }
    });
  });
  t.after(async () => {
    await service?.stop(); for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  service = new ClaimerService({ statePath: join(directory, 'state.json'),
    config: { receivingAddress: 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya',
      network: 'main', rpc: { host: '127.0.0.1', port: server.address().port }, connectionsPerSecond: 100,
      concurrency: 100, minExpectedReturn: 1000, lookbackBlocks: 600, feeRate: 1500 },
    discover: async ({ rpc }) => ({ tip: await rpc.request('getchaintip', {}), blocks: new Map(), cursor: 'coherent' }),
    poolFactory: () => ({ async start() {}, async close() {}, async attempt() { assert.fail('No TLS capture is expected'); } }),
    setTimer: () => ({ unref() {} }), clearTimer() {},
  });
  await service.start();
  service.engine.notify({ attempts: 7, completed: 2 });
  for (let index = 0; index < 32; index++) {
    const locktime = Buffer.alloc(4); locktime.writeUInt32LE(index);
    const raw = parent.slice(0, -8) + locktime.toString('hex'), txid = transactionIdFromRaw(raw);
    parents.set(txid, raw);
    const controller = new AbortController();
    const pending = service.funding(txid, { signal: controller.signal });
    controller.abort(); await assert.rejects(pending, { name: 'AbortError' });
  }
  await until(() => service.rpc.queuedRequests === 32 && waiting.length === 12);
  const connection = service.rpc.socket, engine = service.engine;
  if (resetting) service.resetCatalog({ reason: 'journal-reset' });
  await service.cycle();
  assert.equal(service.running, true, 'Local backlog must not permanently stop the service');
  assert.equal(service.fatalError, null); assert.strictEqual(service.engine, engine);
  assert.strictEqual(service.rpc.socket, connection); assert.equal(connection.destroyed, false);
  assert.equal(service.ready, false); assert.equal(service.engine.state.attempts, 7); assert.equal(service.engine.state.completed, 2);
  hold = false; for (const reply of waiting.splice(0)) reply();
  await until(() => service.fundingPending.size === 0 && service.rpc.queuedRequests === 0);
  await service.cycle();
  assert.equal(service.ready, true); assert.equal(service.status, 'running');
  assert.equal(service.engine.state.attempts, 7); assert.equal(service.engine.state.completed, 2);
  assert.equal(service.rpc.capacityReservations, 0); assert.equal(service.rpc.capacityWaiters.length, 0);
  assert.equal(service.rpc.pending.size, 0); assert.equal(requests.some(row => row.method === 'sendrawtransaction'), false);
  assert.equal(service.metrics.snapshot().connectionsStarted, 0);
});
