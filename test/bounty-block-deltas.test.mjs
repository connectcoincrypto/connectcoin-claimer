import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
function windowAt(height = 700, replaced = new Map()) {
  const blocks = Array.from({ length: Math.min(height + 1, 600) }, (_, i) => ({ height: height - i,
    hash: replaced.get(height - i) ?? (height === i ? GENESIS.main : hash(1000 + height - i)) }));
  return { window: 600, blocks, tip: { height, hash: blocks[0].hash, mediantime: 1700000000 + height,
    chain: 'main', genesis_hash: GENESIS.main } };
}
const bounty = (block, id = 1, tipHeight = block.height) => ({ txid: hash(100000 + id), vout: 0,
  block_hash: block.hash, block_height: block.height, amount: '100000000', domain: 'example.com',
  connection_work_target: 'f'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7,
  coinbase: false, confirmations: tipHeight - block.height + 1, status: 'available', spending_txid: null });
const change = (row, sequence, tip) => ({ type: 'added', sequence, txid: row.txid, vout: row.vout,
  block_hash: row.block_hash, bounty: structuredClone(row), tip: structuredClone(tip) });
const nextOptions = result => ({ previous: result.blocks, previousWindow: result.window, cursor: result.cursor });

function fixture() {
  let current = windowAt(), sequence = 0, hook, afterRead, bytes = 0;
  const rows = new Map(), pages = [], calls = [], reads = [], resets = [], invalidations = [];
  const rpc = { async request(method, params = {}) {
    calls.push({ method, params: structuredClone(params) });
    let response;
    if (method === 'getrecentblockhashes') response = { ...current, blocks: current.blocks.slice(0, params.count ?? 600) };
    else {
      assert.equal(method, 'getbountychanges', 'No redundant tip requests are permitted.');
      const changes = pages.shift() ?? [];
      if (changes.length) sequence = changes.at(-1).sequence;
      response = { tip: current.tip, next_cursor: String(sequence), has_more: pages.length > 0, changes, bounty_deltas: 1 };
      if (params.known_tip) {
        const base = params.known_tip, distance = current.tip.height - base.height;
        const canonical = current.blocks.some(block => block.height === base.height && block.hash === base.hash);
        response.block_deltas = 1;
        response.block_delta = canonical && distance >= 0 && distance <= 5 ? {
          base_height: base.height, base_hash: base.hash,
          blocks: current.blocks.slice(0, distance).reverse().map(block => ({ ...block, bounty_count: (rows.get(block.hash) ?? []).length })),
        } : null;
      }
    }
    response = await hook?.(method, params, structuredClone(response), calls.filter(call => call.method === method).length) ?? response;
    bytes += Buffer.byteLength(JSON.stringify(response));
    return structuredClone(response);
  } };
  return { rows, pages, calls, reads, resets, invalidations,
    get bytes() { return bytes; }, get current() { return current; }, set current(value) { current = value; },
    set hook(value) { hook = value; }, set afterRead(value) { afterRead = value; },
    warm() { return { cursor: String(sequence), previousWindow: structuredClone(current),
      previous: new Map(current.blocks.map(block => [block.hash, structuredClone(rows.get(block.hash) ?? [])])) }; },
    options: { rpc, network: 'main', onReset: value => resets.push(value), onInvalidate: (row, reason) => invalidations.push({ row, reason }),
      readBlock: async (hash, { budget }) => {
        reads.push(hash);
        const result = structuredClone(rows.get(hash) ?? []).map(row => ({ ...row, confirmations: current.tip.height - row.block_height + 1 }));
        budget.count += result.length;
        await afterRead?.(hash);
        return result;
      } },
  };
}

test('unchanged warm snapshots use exactly one coherent journal request', async t => {
  const f = fixture(); let previous = f.warm();
  for (let i = 0; i < 100; i++) previous = nextOptions(await discoverBounties({ ...f.options, ...previous }));
  assert.equal(f.calls.length, 100); assert.deepEqual(f.reads, []);
  assert.ok(f.calls.every(call => call.method === 'getbountychanges' && call.params.include_bounties && call.params.known_tip.height === 700));
  t.diagnostic(`100 unchanged polls: ${f.calls.length} RPC calls, ${f.bytes} response bytes, zero block/hash reads.`);
});

for (const distance of [1, 5]) test(`${distance} new authoritative empty blocks need one poll and no hash or block reads`, async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(700 + distance);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.calls.length, 1); assert.deepEqual(f.reads, []);
  assert.equal(result.blocks.size, 600); assert.deepEqual(result.tip, f.current.tip);
  for (const block of f.current.blocks.slice(0, distance)) {
    assert.deepEqual(result.blocks.get(block.hash), []); assert.equal(result.window.blockCounts[block.hash], 0);
  }
  assert.ok(Object.isFrozen(result.window.blockCounts));
  assert.equal(previous.previousWindow.blockCounts, undefined);
});

test('positive counts load every bounty including unannounced spent rows and replay afterward', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = bounty(f.current.blocks[0]), b = { ...bounty(f.current.blocks[0], 2), status: 'spent', spending_txid: hash(999) };
  f.rows.set(a.block_hash, [a, b]); f.pages.push([change(a, 1, f.current.tip)]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.calls.length, 2); assert.deepEqual(f.reads, [a.block_hash]);
  assert.deepEqual(result.blocks.get(a.block_hash), [a, b]);
  assert.equal(result.window.blockCounts[a.block_hash], 2);
});

test('a spend during positive-count streaming is replayed before publication', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = bounty(f.current.blocks[0]), pending = { ...a, status: 'pending_spend', spending_txid: hash(800) };
  f.rows.set(a.block_hash, [a]);
  f.afterRead = () => f.pages.push([change(pending, 1, f.current.tip)]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(a.block_hash), [pending]); assert.equal(result.cursor, '1');
  assert.equal(f.calls.length, 2);
});

for (const later of ['page', 'cycle']) test(`an authoritative zero cannot gain a bounty on a later ${later}`, async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = bounty(f.current.blocks[0]);
  let options = previous;
  if (later === 'page') {
    const old = bounty(f.current.blocks[2], 3, 701);
    f.pages.push([change(old, 1, f.current.tip)], [change(a, 2, f.current.tip)]);
  } else {
    const first = await discoverBounties({ ...f.options, ...previous }); options = nextOptions(first);
    f.pages.push([change(a, 1, f.current.tip)]);
  }
  await assert.rejects(discoverBounties({ ...f.options, ...options }), /contradicts an empty block/);
  assert.equal(options.cursor, '0'); assert.deepEqual(f.reads, []);
  assert.equal(options.previous.get(a.block_hash)?.length ?? 0, 0);
});

for (const advertised of [1, 3]) test(`a complete two-row stream cannot contradict count ${advertised}`, async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = bounty(f.current.blocks[0]); f.rows.set(a.block_hash, [a, bounty(f.current.blocks[0], 2)]);
  f.hook = (method, params, response) => {
    if (response.block_delta?.blocks.length) response.block_delta.blocks[0].bounty_count = advertised;
    return response;
  };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /stream contradicts/);
  assert.equal(previous.previous.has(a.block_hash), false); assert.equal(previous.cursor, '0');
});

test('immutable positive counts also reject extra rows on a later cycle', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = bounty(f.current.blocks[0]); f.rows.set(a.block_hash, [a]);
  const first = await discoverBounties({ ...f.options, ...previous });
  f.pages.push([change(bounty(f.current.blocks[0], 2), 1, f.current.tip)]);
  await assert.rejects(discoverBounties({ ...f.options, ...nextOptions(first) }), /exceeds its immutable block count/);
  assert.deepEqual(first.blocks.get(a.block_hash), [a]);
});

test('a new tip during streaming can append empty blocks inline but still needs the stream replay', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = bounty(f.current.blocks[0]); f.rows.set(a.block_hash, [a]);
  f.afterRead = () => { f.current = windowAt(702); };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.calls.length, 2); assert.deepEqual(f.reads, [a.block_hash]);
  assert.equal(result.tip.height, 702); assert.equal(result.blocks.get(a.block_hash)[0].confirmations, 2);
  assert.deepEqual(result.blocks.get(result.tip.hash), []);
});

test('an update after the page publication stays after its cursor and is consumed next cycle', async () => {
  const f = fixture(), previous = f.warm(), a = bounty(f.current.blocks[1], 1, 700);
  f.hook = (method, params, response, count) => {
    if (count === 1) f.pages.push([change(a, 1, f.current.tip)]);
    return response;
  };
  const first = await discoverBounties({ ...f.options, ...previous });
  assert.equal(first.cursor, '0'); assert.deepEqual(first.blocks.get(a.block_hash), []);
  const second = await discoverBounties({ ...f.options, ...nextOptions(first) });
  assert.equal(second.cursor, '1'); assert.deepEqual(second.blocks.get(a.block_hash), [a]);
  assert.equal(f.calls.length, 2);
});

const malformed = {
  capability: page => { page.block_deltas = true; },
  missing_capability: page => { delete page.block_deltas; },
  missing_payload: page => { delete page.block_delta; },
  missing_bounty_capability: page => { delete page.bounty_deltas; },
  base_height: page => { page.block_delta.base_height--; },
  base_hash: page => { page.block_delta.base_hash = hash(4); },
  short_prefix: page => { page.block_delta.blocks.pop(); },
  reversed: page => { page.block_delta.blocks.reverse(); },
  height_gap: page => { page.block_delta.blocks[0].height++; },
  duplicate_hash: page => { page.block_delta.blocks[1].hash = page.block_delta.blocks[0].hash; },
  reused_anchor: page => { page.block_delta.blocks[0].hash = page.block_delta.base_hash; },
  wrong_tip_hash: page => { page.block_delta.blocks.at(-1).hash = hash(42); },
  missing_count: page => { delete page.block_delta.blocks[0].bounty_count; },
  negative_count: page => { page.block_delta.blocks[0].bounty_count = -1; },
  excessive_count: page => { page.block_delta.blocks[0].bounty_count = 100001; },
  fractional_count: page => { page.block_delta.blocks[0].bounty_count = 0.5; },
  boolean_count: page => { page.block_delta.blocks[0].bounty_count = false; },
};
for (const [name, mutate] of Object.entries(malformed)) test(`malformed inline ${name} fails without publishing cache/cursor`, async () => {
  const f = fixture(), previous = f.warm(), original = structuredClone(previous.previousWindow);
  f.current = windowAt(702);
  f.hook = (method, params, response) => { mutate(response); return response; };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|missing|inconsistent/i);
  assert.equal(previous.cursor, '0'); assert.deepEqual(previous.previousWindow, original);
  assert.equal(previous.previous.size, 600); assert.deepEqual(f.reads, []);
});

test('null on an unchanged canonical tip is malformed, not an empty-block signal', async () => {
  const f = fixture(); f.hook = (method, params, response) => ({ ...response, block_delta: null });
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }), /Missing canonical block delta/);
});

for (const mode of ['unsupported', 'gap', 'reorg', 'rollback']) test(`${mode} falls back to complete block reads without guessing emptiness`, async () => {
  const f = fixture(), previous = f.warm();
  f.current = mode === 'gap' ? windowAt(706) : mode === 'reorg' ? windowAt(700, new Map([[700, hash(9999)]])) : mode === 'rollback' ? windowAt(699) : windowAt(701);
  if (mode === 'unsupported') f.hook = (method, params, response) => { delete response.block_deltas; delete response.block_delta; return response; };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.ok(f.calls.some(call => call.method === 'getrecentblockhashes'));
  assert.ok(f.reads.length >= 1); assert.deepEqual(result.tip, f.current.tip);
  assert.equal(f.calls.at(-1).method, 'getbountychanges');
});

test('getrecentblockhashes extras cannot authorize skipping a block stream', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(706);
  f.hook = (method, params, response) => method === 'getrecentblockhashes'
    ? { ...response, blockCounts: { [f.current.tip.hash]: 0 } } : response;
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.ok(f.reads.includes(f.current.tip.hash)); assert.equal(result.window.blockCounts, undefined);
});

test('counts survive ordinary hash fallback and keep only canonical hashes through a reorg', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const first = await discoverBounties({ ...f.options, ...previous }), empty = first.tip.hash;
  f.current = windowAt(707);
  const second = await discoverBounties({ ...f.options, ...nextOptions(first) });
  assert.equal(second.window.blockCounts[empty], 0);
  f.current = windowAt(707, new Map([[701, hash(9001)], [702, hash(9002)], [703, hash(9003)], [704, hash(9004)], [705, hash(9005)], [706, hash(9006)], [707, hash(9007)]]));
  const third = await discoverBounties({ ...f.options, ...nextOptions(second) });
  assert.equal(third.window.blockCounts?.[empty], undefined);
});

test('journal reset discards old count authority and obtains complete replacement streams', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const first = await discoverBounties({ ...f.options, ...previous }), a = bounty(f.current.blocks[0]);
  f.rows.set(a.block_hash, [a]); let reset = false;
  f.hook = (method, params, response) => {
    if (!reset) { reset = true; throw Object.assign(new Error('Cursor reset'), { code: -32011 }); }
    return response;
  };
  const result = await discoverBounties({ ...f.options, ...nextOptions(first) });
  assert.equal(f.resets.length, 1); assert.ok(f.reads.includes(a.block_hash));
  assert.deepEqual(result.blocks.get(a.block_hash), [a]);
  assert.equal(result.window.blockCounts?.[a.block_hash], undefined);
});

for (const bad of [{ [hash(42)]: 0 }, { [hash(1700)]: -1 }, { [hash(1700)]: '0' }]) test(`invalid caller count metadata is rejected: ${JSON.stringify(bad)}`, async () => {
  const f = fixture(), previous = f.warm(); previous.previousWindow.blockCounts = bad;
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Invalid cached block count/);
  assert.deepEqual(f.calls, []);
});
