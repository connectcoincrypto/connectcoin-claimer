import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { ClaimerService } from '../src/service.mjs';
import { BroadcastJournal, transactionDigest } from '../src/broadcast-journal.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { attachClaimProof, transactionIdFromRaw } from '../src/core/transaction.mjs';

const receivingAddress = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
const tip = { height: 0, hash: GENESIS.main, genesis_hash: GENESIS.main, chain: 'main', mediantime: 1700000000 };
const fundingHex = '02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff0100e40b5402000000020b6578616d706c652e636f6dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000700000000';
const bounty = { txid: transactionIdFromRaw(fundingHex), vout: 0, amount: '10000000000', domain: 'example.com',
  connection_work_target: 'ff'.repeat(32), root_certificates_version: 1, signature_algorithms_mask: 7,
  status: 'available', block_height: 0, block_hash: tip.hash };
const key = `${bounty.txid}:0`;
async function until(predicate) {
  const deadline = performance.now() + 4000;
  while (!predicate()) { assert.ok(performance.now() < deadline, 'Loopback operation did not finish'); await delay(2); }
}

for (const recovery of ['drain', 'disconnect', 'restart']) {
  test(`a verified winner survives local RPC saturation and ${recovery} with exact replay and one completion`, async t => {
    const directory = await mkdtemp(join(tmpdir(), 'claimer-broadcast-backpressure-'));
    const path = join(directory, 'state.json'), sockets = new Set(), services = [], requests = [], waiting = [];
    const parents = new Map([[bounty.txid, fundingHex]]);
    let hold = true, signed, accepted = false;
    const server = net.createServer(socket => {
      sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
      let buffer = '';
      socket.on('data', chunk => {
        buffer += chunk.toString('utf8');
        for (let end; (end = buffer.indexOf('\n')) !== -1;) {
          const request = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1); requests.push(request);
          const send = body => socket.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, ...body }) + '\n');
          if (request.method === 'getchaintip') send({ result: tip });
          else if (request.method === 'gettransactionstatus') {
            assert.equal(request.params.txid, signed?.txid);
            send(accepted ? { result: { tip, txid: signed.txid, status: 'pending', confirmations: 0 } }
              : { error: { code: -32004, message: 'Not indexed' } });
          }
          else if (request.method === 'gettransaction') {
            assert.notEqual(request.params.txid, signed?.txid, 'Confirmation polling must never fetch the claim witness.');
            assert.ok(parents.has(request.params.txid));
            const reply = () => send({ result: { tip, transaction: { hex: parents.get(request.params.txid) } } });
            if (hold && request.params.txid !== bounty.txid) waiting.push(reply); else reply();
          } else {
            assert.equal(request.method, 'sendrawtransaction'); assert.equal(request.params.transaction_hex, signed.hex);
            accepted = true; send({ result: { txid: signed.txid } });
          }
        }
      });
    });
    t.after(async () => {
      for (const service of services) await service.stop();
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true });
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const makeService = () => {
      const service = new ClaimerService({ statePath: path,
        config: { receivingAddress, network: 'main', rpc: { host: '127.0.0.1', port: server.address().port },
          connectionsPerSecond: 100, concurrency: 100, minExpectedReturn: 1000, lookbackBlocks: 600, feeRate: 1500 },
        discover: async ({ rpc }) => ({ tip: await rpc.request('getchaintip', {}), blocks: new Map(), cursor: 'coherent' }),
        poolFactory: () => ({ async start() {}, async close() {}, async attempt() { assert.fail('No new TLS capture is expected'); } }),
        setTimer: () => ({ unref() {} }), clearTimer() {},
      });
      services.push(service); return service;
    };
    let service = makeService(); await service.start();
    service.engine.setCatalogBlocked(true); service.outpoints.set(key, bounty); service.engine.enqueue([bounty]);
    const prepared = await service.prepare(bounty), job = service.engine.queue.get(key);
    // Public synthetic framing models an already-verified helper result, as in
    // the recovery fixtures. Native certificate/signature validation is tested
    // separately; this test uses real preparation, transport and durable replay.
    const proof = '02010000220303' + prepared.challenge + '02000000080000000b0000000f000000';
    signed = attachClaimProof(prepared, proof);
    job.prepared = prepared; job.winner = true;
    service.engine.pendingProofs.set(key, { proof, context: prepared.context, due: 0, failures: 0 });
    service.engine.notify({ attempts: 7, completed: 2 });
    for (let index = 1; index <= 32; index++) {
      const locktime = Buffer.alloc(4); locktime.writeUInt32LE(index);
      const raw = fundingHex.slice(0, -8) + locktime.toString('hex'), txid = transactionIdFromRaw(raw);
      parents.set(txid, raw);
      const controller = new AbortController(), pending = service.funding(txid, { signal: controller.signal });
      controller.abort(); await assert.rejects(pending, { name: 'AbortError' });
    }
    await until(() => service.rpc.queuedRequests === 32 && waiting.length === 12);
    const connection = service.rpc.socket;
    await service.engine.submitVerified(job, new AbortController(), service.engine.generation);
    const assertSaved = async status => {
      const disk = new BroadcastJournal(path); await disk.load(); const record = disk.entries()[0];
      assert.equal(record.status, status); assert.equal(record.outpoint, key); assert.equal(record.txid, signed.txid);
      assert.equal(record.transactionHex, signed.hex); assert.equal(record.transactionHash, transactionDigest(signed.hex));
      assert.equal(service.reserved.has(key), true); assert.equal(service.running, true); assert.equal(service.fatalError, null);
    };
    await assertSaved('pending');
    assert.equal(service.engine.deferredBroadcasts.get(key), signed.txid);
    assert.equal(service.engine.pendingProofs.size, 0, 'Durable journal now owns the only replay');
    assert.equal(service.engine.state.attempts, 7); assert.equal(service.engine.state.completed, 2);
    assert.equal(requests.some(row => row.method === 'sendrawtransaction'), false);
    await service.reconcileBroadcasts(); // The receipt read is also locally full.
    await assertSaved('pending');
    assert.equal(service.engine.state.completed, 2);
    hold = false;
    if (recovery === 'drain') {
      for (const reply of waiting.splice(0)) reply();
      await until(() => service.fundingPending.size === 0 && service.rpc.queuedRequests === 0);
      assert.strictEqual(service.rpc.socket, connection);
    } else if (recovery === 'disconnect') {
      const disconnected = once(service.rpc, 'disconnected');
      for (const socket of sockets) socket.destroy();
      await disconnected; await service.suspending; await service.cycle();
      assert.notStrictEqual(service.rpc.socket, connection);
    } else {
      await service.stop(); service = makeService(); await service.start();
    }
    service.recoveryDue.clear(); await service.reconcileBroadcasts(); await assertSaved('accepted');
    const completed = recovery === 'restart' ? 1 : 3, attempts = recovery === 'restart' ? 0 : 7;
    assert.equal(service.engine.state.completed, completed); assert.equal(service.engine.state.attempts, attempts);
    assert.equal(requests.filter(row => row.method === 'sendrawtransaction').length, 1);
    service.recoveryDue.clear(); await service.reconcileBroadcasts();
    assert.equal(service.engine.state.completed, completed); assert.equal(service.engine.state.attempts, attempts);
    assert.equal(requests.filter(row => row.method === 'sendrawtransaction').length, 1);
    assert.equal(service.metrics.snapshot().connectionsStarted, 0);
  });
}
