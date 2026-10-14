import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
function fixture() {
  const blocks = Array.from({ length: 600 }, (_, index) => ({ height: 700 - index, hash: hash(1700 - index) }));
  const tip = { height: 700, hash: blocks[0].hash, mediantime: 1700000700, chain: 'main', genesis_hash: GENESIS.main };
  const previous = new Map(blocks.map(block => [block.hash, []]));
  const rows = new Map(), reads = [], invalidations = [];
  let pages = 0, hook;
  const options = {
    network: 'main', previous, previousWindow: { window: 600, blocks, tip }, cursor: 'previous',
    rpc: { async request(method) {
      if (method === 'getchaintip') return tip;
      assert.equal(method, 'getbountychanges');
      const number = ++pages;
      return { tip, next_cursor: `page-${number}`, has_more: false, changes: [], ...hook?.(number) };
    } },
    onInvalidate: (row, reason) => invalidations.push({ row, reason }),
    readBlock: async (block, { budget }) => {
      reads.push(block);
      const result = structuredClone(rows.get(block) ?? []);
      budget.count += result.length;
      return result;
    },
  };
  function row(id = 1, block = blocks[0]) {
    return { txid: hash(9000000 + id), vout: 0, block_hash: block.hash, block_height: block.height,
      amount: '100000000', domain: 'example.com', connection_work_target: 'f'.repeat(64),
      root_certificates_version: 1, signature_algorithms_mask: 7, status: 'available' };
  }
  function track(value) {
    const txid = value.txid;
    let count = 0;
    Object.defineProperty(value, 'txid', { enumerable: true, get() { count++; return txid; } });
    previous.get(value.block_hash).push(value);
    return () => count;
  }
  return { options, blocks, row, track, previous, rows, reads, invalidations, tip,
    set hook(value) { hook = value; } };
}

test('empty journal pages do not scan outpoint keys; final duplicate validation still runs', async () => {
  const f = fixture(), count = f.track(f.row());
  await discoverBounties(f.options);
  assert.equal(count(), 1, 'Only the final duplicate check needs this outpoint.');
  assert.deepEqual(f.reads, []);
});

test('events carrying block hashes do not build an unused fallback index', async () => {
  const f = fixture(), value = f.row(), txid = value.txid, count = f.track(value);
  f.hook = page => page === 1 ? { changes: [{ type: 'window_exit', sequence: 1, txid, vout: 0, block_hash: value.block_hash }] } : {};
  await discoverBounties(f.options);
  assert.equal(count(), 1);
  assert.equal(f.invalidations[0].reason, 'window_exit');
});

test('missing block hashes build one index per page and still reload affected blocks', async () => {
  const f = fixture(), value = f.row(), txid = value.txid, count = f.track(value);
  f.rows.set(value.block_hash, [{ ...value, status: 'spent' }]);
  const before = count();
  f.hook = page => page === 1 ? { changes: [
    { type: 'pending_spend', sequence: 1, txid, vout: 0 },
    { type: 'spent', sequence: 2, txid, vout: 0 },
  ] } : {};
  const result = await discoverBounties(f.options);
  assert.equal(count() - before, 1, 'The two events share a single fallback scan.');
  assert.deepEqual(f.reads, [value.block_hash]);
  assert.equal(result.blocks.get(value.block_hash)[0].status, 'spent');
  assert.ok(f.invalidations.some(item => item.reason === 'pending_spend'));
  assert.ok(f.invalidations.some(item => item.reason === 'spent'));
});

test('fallback lookup sees newly loaded rows on a later journal page', async () => {
  const f = fixture(), a = f.row(1), b = f.row(2, f.blocks[1]);
  f.previous.get(a.block_hash).push(a);
  f.rows.set(a.block_hash, [a]);
  f.rows.set(b.block_hash, [b]);
  f.hook = page => {
    if (page === 1) return { changes: [
      { type: 'available_again', sequence: 1, txid: a.txid, vout: 0 },
      { type: 'added', sequence: 2, txid: b.txid, vout: 0, block_hash: b.block_hash },
    ] };
    if (page === 2) {
      f.rows.set(b.block_hash, [{ ...b, status: 'spent' }]);
      return { changes: [{ type: 'spent', sequence: 3, txid: b.txid, vout: 0 }] };
    }
    return {};
  };
  const result = await discoverBounties(f.options);
  assert.equal(f.reads.filter(block => block === b.block_hash).length, 2);
  assert.equal(result.blocks.get(b.block_hash)[0].status, 'spent');
});

for (const type of ['added', 'matured', 'available_again', 'spent', 'pending_spend', 'window_exit']) {
  test(`a ${type} event cannot coerce an array block hash and advance past an unapplied update`, async () => {
    const f = fixture(), current = f.row(), cached = { ...current, status: 'pending_spend' };
    f.previous.get(current.block_hash).push(cached);
    f.rows.set(current.block_hash, [current]);
    // This is a JSON-representable response. RegExp.test used to accept this
    // array, while Set.has treated it as a different key and skipped reload.
    f.hook = page => page === 1 ? { changes: [{ type, sequence: 1,
      txid: current.txid, vout: 0, block_hash: [current.block_hash] }] } : {};
    await assert.rejects(discoverBounties(f.options), /Invalid bounty change event/);
    assert.deepEqual(f.reads, [], 'Malformed identity must be rejected before block work.');
    assert.deepEqual(f.invalidations, [], 'Malformed identity must not cancel a retained winner.');
    assert.strictEqual(f.previous.get(current.block_hash)[0], cached);
    assert.equal(cached.status, 'pending_spend');
    assert.equal(f.options.cursor, 'previous');
  });
}

for (const includeHash of [true, false]) {
  test(`available_again still refreshes a cached bounty with ${includeHash ? 'a string' : 'no optional'} block hash`, async () => {
    const f = fixture(), current = f.row();
    f.previous.get(current.block_hash).push({ ...current, status: 'pending_spend' });
    f.rows.set(current.block_hash, [current]);
    f.hook = page => page === 1 ? { changes: [{ type: 'available_again', sequence: 1,
      txid: current.txid, vout: 0, ...(includeHash ? { block_hash: current.block_hash } : {}) }] } : {};
    const result = await discoverBounties(f.options);
    assert.deepEqual(f.reads, [current.block_hash]);
    assert.equal(result.blocks.get(current.block_hash)[0].status, 'available');
    assert.equal(result.cursor, 'page-2');
    assert.equal(f.previous.get(current.block_hash)[0].status, 'pending_spend');
  });
}

for (const changes of [
  [{ type: 'spent', sequence: -1, txid: hash(1), vout: 0 }],
  [{ type: 'spent', sequence: 1, txid: hash(1), vout: 0, block_hash: null }],
  [{ type: 'spent', sequence: 1, txid: hash(1), vout: 0, block_hash: 'invalid' }],
  [{ type: 'unexpected', sequence: 1, txid: hash(1), vout: 0 }],
]) test(`lazy lookup retains validation before fallback scans: ${JSON.stringify(changes)}`, async () => {
  const f = fixture(), count = f.track(f.row());
  f.hook = () => ({ changes });
  await assert.rejects(discoverBounties(f.options), /Invalid bounty change event/);
  assert.equal(count(), 0);
});

test('an empty journal never bypasses duplicate outpoint rejection in cached blocks', async () => {
  const f = fixture(), first = f.row();
  f.previous.get(f.blocks[0].hash).push(first);
  f.previous.get(f.blocks[1].hash).push({ ...first, block_hash: f.blocks[1].hash, block_height: f.blocks[1].height });
  await assert.rejects(discoverBounties(f.options), /Duplicate bounty across/);
});
