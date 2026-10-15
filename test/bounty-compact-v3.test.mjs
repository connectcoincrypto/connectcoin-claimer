import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties, bountyImmutableDigest } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const windowAt = (height = 700) => ({ window: 600,
  tip: { height, hash: hash(1000 + height), mediantime: 1700000000 + height, chain: 'main', genesis_hash: GENESIS.main },
  blocks: Array.from({ length: 600 }, (_, i) => ({ height: height - i, hash: hash(1000 + height - i) })) });
const rowAt = (block, tipHeight = 701, id = 1) => ({ txid: hash(10000 + id), vout: 0, block_hash: block.hash, block_height: block.height,
  amount: '100000000', domain: 'example.com', connection_work_target: 'f'.repeat(64), root_certificates_version: 1,
  signature_algorithms_mask: 7, coinbase: false, confirmations: tipHeight - block.height + 1, status: 'available', spending_txid: null });
const added = (row, sequence = 1, tip_ref = -1) => ({ type: 'added', sequence, tip_ref, bounty: row });
const state = (row, sequence = 2, status = 'pending_spend', tip_ref = -1) => ({ type: status === 'available' ? 'available_again' : status,
  sequence, txid: row.txid, vout: row.vout, tip_ref, bounty_ref: bountyImmutableDigest(row), spending_txid_ref: true,
  bounty_delta: { status, spending_txid: status === 'available' ? null : hash(900) } });
const previousFrom = result => ({ previous: result.blocks, previousWindow: result.window, cursor: result.cursor });

function fixture() {
  const rows = new Map(), calls = [], reads = [], invalidations = [], resets = [], capabilities = {};
  let current = windowAt(), pages = [], hook, afterRead;
  const full = (params, changes = [], cursor = '0', has_more = false) => {
    const page = { compact: 3, tip: current.tip, changes, next_cursor: cursor, has_more };
    if (params.known_tip) {
      const distance = current.tip.height - params.known_tip.height;
      const canonical = current.blocks.some(block => block.height === params.known_tip.height && block.hash === params.known_tip.hash);
      page.block_delta = canonical && distance >= 0 && distance <= 5 ? {
        base_height: params.known_tip.height, base_hash: params.known_tip.hash,
        blocks: current.blocks.slice(0, distance).reverse().map(block => ({ ...block, bounty_count: (rows.get(block.hash) ?? []).length })),
      } : null;
    }
    if (page.changes.length === 0) delete page.changes;
    if (!page.has_more) delete page.has_more;
    return structuredClone(page);
  };
  const bound = (params, changes = [], cursor = null, has_more = false) => {
    const page = full(params, changes, cursor, has_more);
    assert.ok(page.block_delta);
    page.tip = current.tip.hash === params.known_tip.hash ? null : [current.tip.height, current.tip.hash, current.tip.mediantime];
    page.block_delta = page.block_delta.blocks.map((block, i, blocks) => [i === blocks.length - 1 ? null : block.hash, block.bounty_count]);
    if (page.next_cursor === null) delete page.next_cursor;
    return page;
  };
  const rpc = { async request(method, params = {}) {
    calls.push({ method, params: structuredClone(params) });
    let result;
    if (method === 'getrecentblockhashes') result = { ...current, bounty_counts: 1,
      blocks: current.blocks.slice(0, params.count ?? 600).map(block => ({ ...block, bounty_count: (rows.get(block.hash) ?? []).length })) };
    else {
      assert.equal(method, 'getbountychanges');
      result = pages.length ? pages.shift()(params) : params.known_state ? { compact: 3, unchanged: true } : full(params);
    }
    return structuredClone(await hook?.(method, params, result) ?? result);
  } };
  return { rows, calls, reads, invalidations, resets, capabilities, full, bound,
    get current() { return current; }, set current(value) { current = value; },
    set pages(value) { pages = value; }, set hook(value) { hook = value; }, set afterRead(value) { afterRead = value; },
    warm() { return { previous: new Map(current.blocks.map(block => [block.hash, structuredClone(rows.get(block.hash) ?? [])])),
      previousWindow: { ...structuredClone(current), blockCounts: Object.fromEntries(current.blocks.map(block => [block.hash, (rows.get(block.hash) ?? []).length])) }, cursor: '0' }; },
    options: { rpc, network: 'main', capabilities, onInvalidate: (row, reason) => invalidations.push({ row: structuredClone(row), reason }),
      onReset: info => resets.push(info), readBlock: async (blockHash, { budget }) => {
        reads.push({ hash: blockHash, budgetBefore: budget.count });
        const found = structuredClone(rows.get(blockHash) ?? []).map(row => ({ ...row, confirmations: current.tip.height - row.block_height + 1 }));
        budget.count += found.length; await afterRead?.(blockHash); return found;
      } } };
}

test('v3 ACK and omitted empty defaults keep exact state with one request', async () => {
  const f = fixture(), previous = f.warm();
  f.pages = [() => ({ compact: 3, tip: null, block_delta: [] })];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.tip, previous.previousWindow.tip); assert.equal(result.cursor, '0');
  assert.equal(f.calls.length, 1); assert.deepEqual(f.reads, []);
  await discoverBounties({ ...f.options, ...previousFrom(result) });
  assert.ok(f.calls.every(call => call.params.compact_version === 3));
});

test('v3 explicit valid defaults remain accepted rather than overwritten', async () => {
  const f = fixture(); f.pages = [() => ({ compact: 3, tip: null, block_delta: [], changes: [], tips: [], has_more: false, next_cursor: null })];
  assert.equal((await discoverBounties({ ...f.options, ...f.warm() })).cursor, '0');
});

test('v3 empty new block derives only acknowledged counts and preserves the cursor', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701); f.pages = [params => f.bound(params)];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.tip.height, 701); assert.equal(result.cursor, '0'); assert.equal(result.window.blockCounts[result.tip.hash], 0);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.reads, []);
});

test('v3 base-tip reference derives confirmations from historical publication, not current tip', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2], 700); f.rows.set(row.block_hash, [row]); const previous = f.warm();
  f.current = windowAt(701); f.pages = [params => f.bound(params, [state(row, 1, 'pending_spend', -2)], '1')];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(row.block_hash)[0].confirmations, 4);
  assert.equal(f.invalidations[0].row.confirmations, 3); assert.equal(result.cursor, '1'); assert.deepEqual(f.reads, []);
});

test('v3 explicit confirmations are validated, and valid unequal historical outer spender is preserved', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2], 700); f.rows.set(row.block_hash, [row]);
  const event = state(row, 1); event.bounty_delta.confirmations = 3; delete event.spending_txid_ref; event.spending_txid = hash(901);
  f.pages = [params => f.bound(params, [event], '1')];
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(result.blocks.get(row.block_hash)[0].spending_txid, hash(900));
});

test('v3 complete new block spans pages and resolves state references from unpublished candidates', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]), b = rowAt(f.current.blocks[0], 701, 2); f.rows.set(a.block_hash, [a, b]);
  f.pages = [params => f.bound(params, [added(a)], '1', true),
    params => f.bound(params, [state(a, 2), added(b, 3)], '3')];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.cursor, '3'); assert.deepEqual(f.reads, []); assert.equal(f.calls.length, 2);
  assert.deepEqual(result.blocks.get(a.block_hash), [{ ...a, ...state(a).bounty_delta }, b]);
  assert.equal(previous.previous.has(a.block_hash), false); assert.equal(previous.cursor, '0');
});

test('complete counts include unavailable and immature outputs, not only eligible rows', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const rows = [rowAt(f.current.blocks[0]), { ...rowAt(f.current.blocks[0], 701, 2), status: 'spent', spending_txid: hash(900) },
    { ...rowAt(f.current.blocks[0], 701, 3), coinbase: true, status: 'immature' }];
  f.rows.set(rows[0].block_hash, rows); f.pages = [params => f.bound(params, rows.map((row, i) => added(row, i + 1)), '3')];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(rows[0].block_hash), rows); assert.equal(f.invalidations.length, 2); assert.deepEqual(f.reads, []);
});

test('duplicate outpoints do not complete a block and partial candidate memory is released before the stream', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]), b = rowAt(f.current.blocks[0], 701, 2); f.rows.set(a.block_hash, [a, b]);
  f.pages = [params => f.bound(params, [added(a), added(a, 2)], '2')];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.reads, [{ hash: a.block_hash, budgetBefore: 0 }]); assert.equal(f.calls.length, 2);
  assert.deepEqual(result.blocks.get(a.block_hash), [a, b]);
});

test('partial candidate fallback replays a mutation that races its complete stream', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]), b = rowAt(f.current.blocks[0], 701, 2); f.rows.set(a.block_hash, [a, b]);
  f.pages = [params => f.bound(params, [added(a)], '1')];
  f.afterRead = () => { f.pages = [params => f.bound(params, [state(a, 2, 'spent')], '2')]; };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.cursor, '2'); assert.equal(result.blocks.get(a.block_hash)[0].status, 'spent'); assert.equal(f.reads.length, 1);
});

for (const failure of ['missing', 'changed']) test(`partial candidate stream ${failure} immutable row fails closed`, async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]), b = rowAt(f.current.blocks[0], 701, 2); f.rows.set(a.block_hash, [a, b]);
  f.pages = [params => { const page = f.bound(params, [added(a)], '1'); f.rows.set(a.block_hash,
    failure === 'missing' ? [b, rowAt(f.current.blocks[0], 701, 3)] : [{ ...a, amount: '1' }, b]); return page; }];
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /immutable journal metadata/);
  assert.equal(previous.previous.has(a.block_hash), false);
});

test('duplicate candidate with conflicting immutable metadata cannot be hidden by fallback', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]); f.rows.set(a.block_hash, [a]);
  f.pages = [params => f.bound(params, [added(a)], '1', true), params => f.bound(params, [added({ ...a, amount: '1' }, 2)], '2')];
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /immutable/); assert.deepEqual(f.reads, []);
});

test('reorg between candidate pages discards orphan candidates without publishing or charging them twice', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]), b = rowAt(f.current.blocks[0], 701, 2); f.rows.set(a.block_hash, [a, b]);
  f.pages = [params => f.bound(params, [added(a)], '1', true), params => {
    f.current.tip.hash = hash(99999); f.current.blocks[0].hash = f.current.tip.hash;
    const replacement = rowAt(f.current.blocks[0], 701, 3); f.rows.set(replacement.block_hash, [replacement]);
    return f.full(params, [added(replacement, 2)], '2');
  }];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.has(a.block_hash), false); assert.equal(result.blocks.get(f.current.tip.hash).length, 1);
  assert.ok(f.invalidations.some(value => value.row.txid === a.txid && value.reason === 'reorg')); assert.deepEqual(f.reads, []);
});

test('reset between candidate pages revokes candidate rows and obtains fresh current counts', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]), b = rowAt(f.current.blocks[0], 701, 2); f.rows.set(a.block_hash, [a, b]);
  f.pages = [params => f.bound(params, [added(a)], '1', true), () => { throw Object.assign(new Error('Reset'), { code: -32011 }); }];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(a.block_hash).length, 2); assert.deepEqual(f.reads, [{ hash: a.block_hash, budgetBefore: 0 }]);
  assert.ok(f.resets.some(info => info.reason === 'cursor-invalid'));
});

test('unknown v3 reference replays expanded at the original cursor before applying candidates', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]); f.rows.set(a.block_hash, [a]);
  f.pages = [params => f.bound(params, [state(a, 1)], '1'), params => {
    assert.equal(params.compact, undefined); assert.equal(params.cursor, '0');
    const page = f.full(params); delete page.compact;
    return { ...page, has_more: false, changes: [{ type: 'pending_spend', sequence: 1, txid: a.txid, vout: a.vout,
      bounty: { ...a, ...state(a).bounty_delta }, tip: f.current.tip }], next_cursor: '1', bounty_deltas: 1, block_deltas: 1 };
  }];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(a.block_hash)[0].status, 'pending_spend'); assert.equal(f.calls.length, 2); assert.deepEqual(f.reads, []);
});

test('v3 negotiation remembers v2 per connection epoch and never retries v3 on the next cycle', async () => {
  const f = fixture(); f.hook = (method, params) => {
    if (params.compact_version === 3) throw Object.assign(new Error('Old version'), { code: -32602 });
    return { compact: 2, unchanged: true };
  };
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.deepEqual(f.calls.map(call => call.params.compact_version), [3, 2]); assert.equal(f.capabilities.compactVersion, 2);
  await discoverBounties({ ...f.options, ...previousFrom(result) }); assert.equal(f.calls.at(-1).params.compact_version, 2);
  await discoverBounties({ ...f.options, capabilities: {}, ...previousFrom(result) });
  assert.deepEqual(f.calls.slice(-2).map(call => call.params.compact_version), [3, 2]);
});

const badPages = {
  changes_null: page => { page.changes = null; }, tips_null: page => { page.tips = null; },
  more_null: page => { page.has_more = null; }, missing_cursor_with_events: page => { page.changes = [{ type: 'window_exit' }]; },
  more_without_changes: page => { page.has_more = true; }, base_tip_with_suffix: page => { page.block_delta = [[null, 0]]; },
  base_tip_missing_delta: page => { delete page.block_delta; }, unknown_version: page => { page.compact = 4; },
  unbound_default_cursor: page => { page.tip = windowAt().tip; page.block_delta = null; },
  bad_ack: page => { page.unchanged = true; }, mixed_capability: page => { page.bounty_deltas = 1; },
};
for (const [name, mutate] of Object.entries(badPages)) test(`v3 malformed ${name} fails closed without downgrade`, async () => {
  const f = fixture(), previous = f.warm(), copy = structuredClone(previous);
  f.pages = [params => { const page = f.bound(params); mutate(page); return page; }];
  await assert.rejects(discoverBounties({ ...f.options, ...previous })); assert.equal(f.calls.length, 1);
  assert.deepEqual(f.capabilities, {}); assert.deepEqual(previous, copy);
});

const badEvents = {
  explicit_bad_confirmations: event => { event.bounty_delta.confirmations = 99; },
  explicit_null_confirmations: event => { event.bounty_delta.confirmations = null; },
  bad_digest: event => { event.bounty_ref = hash(999); },
  missing_status: event => { delete event.bounty_delta.status; }, missing_spender: event => { delete event.bounty_delta.spending_txid; },
  extra_mutable: event => { event.bounty_delta.domain = 'other.example'; },
};
for (const [name, mutate] of Object.entries(badEvents)) test(`v3 malformed ${name} cannot be erased by derivation`, async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2], 700); f.rows.set(row.block_hash, [row]);
  const event = state(row, 1); mutate(event); f.pages = [params => f.bound(params, [event], '1')];
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() })); assert.equal(f.calls.length, 1); assert.deepEqual(f.invalidations, []);
});

for (const reverse of [false, true]) for (const tableSize of [0, 1]) test(`v3 base sentinel cannot authorize wire index ${tableSize}, reversed ${reverse}`, async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2], 700); f.rows.set(row.block_hash, [row]);
  f.pages = [params => {
    const refs = reverse ? [tableSize, -2] : [-2, tableSize];
    const page = f.bound(params, refs.map((ref, i) => state(row, i + 1, 'pending_spend', ref)), '2');
    if (tableSize) page.tips = [f.current.tip]; return page;
  }];
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }), /compact bounty event/);
});

test('v3 base sentinel is rejected on an unbound full-tip page even with locally cached state', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2], 700); f.rows.set(row.block_hash, [row]);
  f.pages = [params => f.full(params, [state(row, 1, 'pending_spend', -2)], '1')];
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }), /base reference/);
});

test('v3 base tip cannot be borrowed on cold initialization or after a negotiated downgrade', async () => {
  const f = fixture(); f.pages = [() => ({ compact: 3, tip: null, block_delta: [] })];
  await assert.rejects(discoverBounties(f.options), /base reference/);
  const g = fixture(); g.capabilities.compactVersion = 2;
  await assert.rejects(discoverBounties({ ...g.options, ...g.warm() }), /Unrequested/);
});

test('a legacy state event without block identity dirties a candidate instead of promoting stale availability', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]), pending = { ...a, ...state(a).bounty_delta }; f.rows.set(a.block_hash, [a]);
  const legacy = changes => ({ tip: f.current.tip, changes, next_cursor: '2', has_more: false });
  f.pages = [params => f.bound(params, [added(a)], '1', true), () => {
    f.rows.set(a.block_hash, [pending]); return legacy([{ type: 'pending_spend', sequence: 2, txid: a.txid, vout: a.vout }]);
  }, () => legacy([])];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(a.block_hash), [pending]); assert.equal(result.cursor, '2');
  assert.deepEqual(f.reads, [{ hash: a.block_hash, budgetBefore: 0 }]);
});

test('expanded window exit without block identity cannot retire a retained candidate', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]); f.rows.set(a.block_hash, [a]);
  f.pages = [params => f.bound(params, [added(a)], '1', true), () => ({ tip: f.current.tip, next_cursor: '2', has_more: false,
    bounty_deltas: 1, changes: [{ type: 'window_exit', sequence: 2, txid: a.txid, vout: a.vout, bounty: null, tip: f.current.tip }] })];
  f.hook = (method, params, response) => {
    if (method === 'getbountychanges' && !params.compact && response.compact) {
      delete response.compact; response.bounty_deltas = 1; response.changes ??= []; response.has_more ??= false;
      if (Object.hasOwn(response, 'block_delta')) response.block_deltas = 1;
    }
    return response;
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.ok(f.resets.some(info => info.reason === 'journal-reset')); assert.equal(f.reads.length, 1);
  assert.deepEqual(result.blocks.get(a.block_hash), [a]);
});

test('full rows without authoritative counts still require a complete block stream and replay', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = rowAt(f.current.blocks[0]); f.rows.set(a.block_hash, [a]);
  const expanded = changes => ({ tip: f.current.tip, next_cursor: '1', has_more: false, bounty_deltas: 1, changes });
  f.pages = [() => expanded([{ type: 'added', sequence: 1, txid: a.txid, vout: a.vout, block_hash: a.block_hash, bounty: a, tip: f.current.tip }]),
    () => expanded([])];
  f.hook = (method, params, response) => {
    if (method === 'getrecentblockhashes') { delete response.bounty_counts; for (const block of response.blocks) delete block.bounty_count; }
    return response;
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.reads, [{ hash: a.block_hash, budgetBefore: 0 }]); assert.equal(result.cursor, '1');
  assert.deepEqual(result.blocks.get(a.block_hash), [a]); assert.equal(result.window.blockCounts[a.block_hash], undefined);
});

test('candidates outside selected lookback cannot complete or charge a retained block', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(702);
  const older = rowAt(f.current.blocks[1], 702), selected = rowAt(f.current.blocks[0], 702, 2);
  f.rows.set(older.block_hash, [older]); f.rows.set(selected.block_hash, [selected]);
  f.pages = [params => f.bound(params, [added(older), added(selected, 2)], '2')];
  const result = await discoverBounties({ ...f.options, ...previous, lookback: 1 });
  assert.equal(result.blocks.size, 1); assert.deepEqual(result.blocks.get(selected.block_hash), [selected]); assert.deepEqual(f.reads, []);
});
