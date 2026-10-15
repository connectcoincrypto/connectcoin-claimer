import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { RpcClient } from '../src/core/rpc.mjs';
import { GENESIS } from '../src/core/config.mjs';
import { discoverBounties, readBountyBlock } from '../src/core/bounty-discovery.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const tip = { chain: 'main', genesis_hash: GENESIS.main, height: 4, hash: hash(4), mediantime: 1700000000 };
const blocks = [4, 3, 2, 1, 0].map(height => ({ height, hash: height ? hash(height) : GENESIS.main }));
const row = block => ({ txid: hash(100 + block.height), vout: 0, block_hash: block.hash, block_height: block.height,
  amount: '100000000', domain: 'example.com', connection_work_target: 'f'.repeat(64),
  root_certificates_version: 1, signature_algorithms_mask: 7, coinbase: false,
  confirmations: tip.height - block.height + 1, status: 'available', spending_txid: null });

async function fixture(t, { code = -32030, delayedFirst = true, malformed = null, timeoutMs = 1000 } = {}) {
  const sockets = new Set(), calls = [], diagnostics = [], invalidated = [];
  let fail = true, sequence = 0;
  const failed = new Set((delayedFirst ? [1, 2] : [0, 1]).map(height => blocks.find(block => block.height === height).hash));
  const malformedHash = blocks.find(block => block.height === (delayedFirst ? 3 : 2)).hash;
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    let buffer = '', queued = Promise.resolve();
    const write = message => { if (!socket.destroyed) socket.write(JSON.stringify(message) + '\n'); };
    async function handle(request) {
      calls.push(request);
      if (request.method === 'getbountychanges') return write({ jsonrpc: '2.0', id: request.id,
        result: { tip, changes: [], next_cursor: 'checkpoint', has_more: false, bounty_deltas: 1 } });
      if (request.method === 'getrecentblockhashes') return write({ jsonrpc: '2.0', id: request.id,
        result: { tip, window: 600, bounty_counts: 1, blocks: blocks.map(block => ({ ...block, bounty_count: 1 })) } });
      assert.equal(request.method, 'getblockbounties');
      const block = blocks.find(candidate => candidate.hash === request.params.block_hash);
      assert.ok(block);
      if (fail && failed.has(block.hash)) return write({ jsonrpc: '2.0', id: request.id,
        error: { code, message: 'Busy or invalidated snapshot', data: { retry_after_ms: 1000 } } });
      const stream_id = `sibling-${++sequence}`;
      write({ jsonrpc: '2.0', id: request.id, result: { stream_id } });
      if (fail && block.hash === malformedHash) await delay(100);
      const damaged = fail && block.hash === malformedHash ? malformed : null;
      write({ jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id, sequence: 0,
        items: { type: 'snapshot', block_hash: block.hash, tip, cursor: 'checkpoint', unit: 'connects', live: true } } });
      write({ jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id, sequence: damaged === 'sequence' ? 9 : 1,
        items: { type: 'bounties', tip, items: damaged === 'count' ? [] : [{ ...row(block), ...(damaged === 'row' ? { amount: '-1' } : {}) }] } } });
      write({ jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id, sequence: 2,
        items: { type: 'state', tip, cursor: 'checkpoint' } } });
      write({ jsonrpc: '2.0', method: 'stream.end', params: { stream_id, complete: true, chunks: 3 } });
    }
    socket.on('data', chunk => {
      buffer += chunk;
      let end;
      while ((end = buffer.indexOf('\n')) >= 0) {
        const request = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
        queued = queued.then(() => handle(request)).catch(error => socket.destroy(error));
      }
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const rpc = new RpcClient({ host: '127.0.0.1', port: server.address().port, timeoutMs, windowMs: 30,
    onDiagnostic: (event, detail) => { if (event === 'rpc.failed') diagnostics.push(detail); } });
  if (delayedFirst) rpc.history.set(`getblockbounties:${GENESIS.main}`, Array(8).fill(performance.now()));
  t.after(async () => { rpc.close(); for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const run = (options = {}) => discoverBounties({ rpc, network: 'main', onInvalidate: item => invalidated.push(item),
    ...options, readBlock: (block, readOptions) => readBountyBlock({ rpc, network: 'main', hash: block, ...readOptions }) });
  return { rpc, calls, diagnostics, invalidated, run, recover() { fail = false; } };
}

for (const code of [-32030, -32029, -32001, -32002]) {
  test(`a sibling ${code} stays retryable while valid in-flight streams retain all checks`, async t => {
    const f = await fixture(t, { code });
    const previous = new Map(), before = structuredClone(previous);
    await assert.rejects(f.run({ previous }), error => error.code === code && error.data.retry_after_ms === 1000);
    assert.deepEqual(previous, before); assert.deepEqual(f.invalidated, []);
    assert.equal(f.diagnostics.some(event => event.failureSource === 'protocol'), false);
    assert.ok(f.calls.filter(call => call.method === 'getblockbounties').length <= 4, 'No fifth block starts after failure');
    f.recover();
    const result = await f.run();
    assert.equal(result.blocks.size, 5); assert.equal(result.cursor, 'checkpoint');
    for (const block of blocks) assert.deepEqual(result.blocks.get(block.hash), [row(block)]);
  });
}

for (const delayedFirst of [false, true]) for (const malformed of ['sequence', 'row', 'count']) {
  test(`real malformed ${malformed} wins over busy regardless of worker order (${delayedFirst})`, async t => {
    const f = await fixture(t, { delayedFirst, malformed });
    const previous = new Map();
    await assert.rejects(f.run({ previous }), error => error.code !== -32030 &&
      /invalid or oversized|immutable block count/.test(error.message));
    assert.equal(previous.size, 0); assert.deepEqual(f.invalidated, []);
    if (malformed !== 'count') assert.ok(f.diagnostics.some(event => event.failureSource === 'protocol'));
  });
}

for (const code of [-32004, -32011]) {
  test(`a sibling reset ${code} cannot hide malformed stream data behind a rescan`, async t => {
    const f = await fixture(t, { code, delayedFirst: false, malformed: 'row' });
    let resets = 0;
    await assert.rejects(f.run({ onReset: () => { resets++; } }), /invalid or oversized/);
    assert.equal(resets, 1, 'Only initial admission reset, no retry of malformed data');
  });
}

test('normal stream deadlines still apply while draining a busy sibling batch', async t => {
  const f = await fixture(t, { timeoutMs: 50 });
  await assert.rejects(f.run(), /Bounty transfer timed out|RPC request timed out/);
  assert.equal(f.diagnostics.some(event => event.failureSource === 'protocol'), false);
  assert.ok(f.diagnostics.some(event => ['stream-timeout', 'request-timeout'].includes(event.failureSource)));
});

test('an epoch cancellation during sibling draining remains cancellation, never malformed data', async t => {
  const f = await fixture(t); let cancelled = false;
  const timer = setTimeout(() => { cancelled = true; }, 60);
  t.after(() => clearTimeout(timer));
  await assert.rejects(f.run({ check: () => {
    if (cancelled) throw Object.assign(new Error('Epoch changed'), { name: 'AbortError', code: 'ABORT_ERR' });
  } }), error => error.name === 'AbortError' || error.code === -32030);
  assert.equal(f.diagnostics.some(event => event.failureSource === 'protocol'), false);
  assert.deepEqual(f.invalidated, []);
});
