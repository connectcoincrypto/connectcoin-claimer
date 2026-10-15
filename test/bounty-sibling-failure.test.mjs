import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
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

async function fixture(t, { code = -32030, delayedFirst = true, malformed = null,
  holdStream = false, stallEnd = false, earlySuccess = false } = {}) {
  const sockets = new Set(), calls = [], diagnostics = [], invalidated = [], readStarts = [];
  const failureObserved = Promise.withResolvers(), snapshotValidated = Promise.withResolvers();
  const releaseStream = Promise.withResolvers(), releaseEnd = Promise.withResolvers(), fifthStarted = Promise.withResolvers();
  let fail = true, sequence = 0, sawFailure = false;
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
      if (fail && failed.has(block.hash)) {
        if (earlySuccess) await fifthStarted.promise;
        return write({ jsonrpc: '2.0', id: request.id,
          error: { code, message: 'Busy or invalidated snapshot', data: { retry_after_ms: 1000 } } });
      }
      const stream_id = `sibling-${++sequence}`;
      write({ jsonrpc: '2.0', id: request.id, result: { stream_id } });
      // Do not confuse "server wrote busy" with "the discovery worker received
      // busy". The latch is released by the real readBlock rejection below.
      // Only the explicit early-success case may finish before that rejection.
      if (fail && !(earlySuccess && block.height === 0)) await failureObserved.promise;
      const damaged = fail && block.hash === malformedHash ? malformed : null;
      write({ jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id, sequence: 0,
        items: { type: 'snapshot', block_hash: block.hash, tip, cursor: 'checkpoint', unit: 'connects', live: true } } });
      if (fail && holdStream && block.hash === malformedHash) await releaseStream.promise;
      write({ jsonrpc: '2.0', method: 'stream.chunk', params: { stream_id, sequence: damaged === 'sequence' ? 9 : 1,
        items: { type: 'bounties', tip, items: damaged === 'count' ? [] : [{ ...row(block), ...(damaged === 'row' ? { amount: '-1' } : {}) }] } } });
      if (fail && stallEnd && block.hash === malformedHash) await releaseEnd.promise;
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
  const rpc = new RpcClient({ host: '127.0.0.1', port: server.address().port, timeoutMs: 10000, windowMs: 30,
    onDiagnostic: (event, detail) => { if (event === 'rpc.failed') diagnostics.push(detail); } });
  t.after(async () => {
    rpc.close(); for (const socket of sockets) socket.destroy();
    for (const gate of [failureObserved, snapshotValidated, releaseStream, releaseEnd, fifthStarted]) gate.resolve();
    await new Promise(resolve => server.close(resolve));
  });
  const run = (options = {}) => discoverBounties({ rpc, network: 'main', onInvalidate: item => invalidated.push(item),
    ...options, readBlock: async (block, readOptions) => {
      readStarts.push({ hash: block, afterFailure: sawFailure });
      if (readStarts.length === 5) fifthStarted.resolve();
      // This models an already-started read waiting for its dispatch slot, but
      // unlike the old 30ms quota seed it cannot expire under CPU contention.
      if (fail && delayedFirst && !earlySuccess && block === GENESIS.main) await failureObserved.promise;
      try {
        let checkCalls = 0;
        return await readBountyBlock({ rpc, network: 'main', hash: block, ...readOptions, check: () => {
          checkCalls++; readOptions.check();
          // The real synchronous snapshot callback has run, not just the ACK
          // write. Tests resume only after this callback returns successfully.
          if (checkCalls > 1 && block === malformedHash && rpc.streams.size && sawFailure) snapshotValidated.resolve();
        } });
      } catch (error) {
        if (fail && error.code === code) { sawFailure = true; failureObserved.resolve(); }
        throw error;
      }
    } });
  return { rpc, calls, diagnostics, invalidated, readStarts, run, draining: snapshotValidated.promise,
    release: () => releaseStream.resolve(), recover() { fail = false; } };
}

for (const code of [-32030, -32029, -32001, -32002]) {
  test(`a sibling ${code} stays retryable while valid in-flight streams retain all checks`, async t => {
    const f = await fixture(t, { code });
    const previous = new Map(), before = structuredClone(previous);
    await assert.rejects(f.run({ previous }), error => error.code === code && error.data.retry_after_ms === 1000);
    assert.deepEqual(previous, before); assert.deepEqual(f.invalidated, []);
    assert.equal(f.diagnostics.some(event => event.failureSource === 'protocol'), false);
    assert.equal(f.readStarts.length, 4, 'Only the four admitted workers run');
    assert.equal(f.calls.filter(call => call.method === 'getblockbounties').length, 4, 'Every admitted sibling drains');
    assert.ok(f.readStarts.every(read => !read.afterFailure), 'No new block starts after an observed failure');
    f.recover();
    const result = await f.run();
    assert.equal(result.blocks.size, 5); assert.equal(result.cursor, 'checkpoint');
    for (const block of blocks) assert.deepEqual(result.blocks.get(block.hash), [row(block)]);
  });
}

test('a sibling may finish and admit a fifth block before another worker receives busy', async t => {
  const f = await fixture(t, { earlySuccess: true });
  await assert.rejects(f.run(), error => error.code === -32030);
  assert.equal(f.readStarts.length, 5, 'A completed worker may start work before any failure');
  assert.ok(f.readStarts.every(read => !read.afterFailure), 'No new block starts after an observed failure');
  assert.equal(f.diagnostics.some(event => event.failureSource === 'protocol'), false);
  assert.deepEqual(f.invalidated, []);
});

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
  const f = await fixture(t, { holdStream: true, stallEnd: true });
  const result = assert.rejects(f.run(), /Bounty transfer timed out/);
  await f.draining;
  // Shorten only the next idle timer of an already-established stream. The
  // intentionally missing end, not a race with initial RPC setup, must expire.
  f.rpc.timeoutMs = 50; f.release();
  await result;
  assert.equal(f.diagnostics.some(event => event.failureSource === 'protocol'), false);
  assert.ok(f.diagnostics.some(event => event.failureSource === 'stream-timeout'));
  assert.ok(f.diagnostics.some(event => event.error?.code === -32030));
});

test('an epoch cancellation during sibling draining remains cancellation, never malformed data', async t => {
  const f = await fixture(t, { holdStream: true }); let cancelled = false, checkedCancellation = false;
  const result = assert.rejects(f.run({ check: () => {
    if (cancelled) {
      checkedCancellation = true;
      throw Object.assign(new Error('Epoch changed'), { name: 'AbortError', code: 'ABORT_ERR' });
    }
  } }), error => error.name === 'AbortError' || error.code === -32030);
  await f.draining; cancelled = true; f.release();
  await result;
  assert.equal(checkedCancellation, true, 'Cancellation was checked while the admitted stream drained');
  assert.equal(f.diagnostics.some(event => event.failureSource === 'protocol'), false);
  assert.deepEqual(f.invalidated, []);
});
