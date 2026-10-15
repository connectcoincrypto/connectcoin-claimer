import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties, bountyImmutableDigest } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const windowAt = (height = 700) => ({ window: 600,
  tip: { height, hash: hash(1000 + height), mediantime: 1700000000 + height, chain: 'main', genesis_hash: GENESIS.main },
  blocks: Array.from({ length: 600 }, (_, i) => ({ height: height - i, hash: hash(1000 + height - i) })) });
const rowAt = (block, id = 1) => ({ txid: hash(10000 + id), vout: 0, block_hash: block.hash, block_height: block.height,
  amount: '100000000', domain: 'example.com', connection_work_target: 'f'.repeat(64), root_certificates_version: 1,
  signature_algorithms_mask: 7, coinbase: false, confirmations: 701 - block.height, status: 'available', spending_txid: null });
const stateEvent = (row, sequence = 1, type = 'pending_spend') => ({ type, sequence, txid: row.txid, vout: row.vout,
  tip_ref: -1, bounty_ref: bountyImmutableDigest(row), spending_txid_ref: true,
  bounty_delta: { status: 'pending_spend', spending_txid: hash(900), confirmations: row.confirmations } });
const previousFrom = result => ({ previous: result.blocks, previousWindow: result.window, cursor: result.cursor });

function fixture() {
  const initial = windowAt(), rows = new Map(), calls = [], reads = [], invalidations = [], resets = [], capabilities = {};
  let current = structuredClone(initial), pages = [], hook, before, afterRead;
  const warm = () => ({ previous: new Map(initial.blocks.map(block => [block.hash, structuredClone(rows.get(block.hash) ?? [])])),
    previousWindow: structuredClone(initial), cursor: '0' });
  const full = (params, changes = [], cursor = '0', has_more = false) => {
    const page = { compact: 2, tip: current.tip, tips: [], changes, next_cursor: cursor, has_more };
    if (params.known_tip) {
      const base = params.known_tip, distance = current.tip.height - base.height;
      const canonical = current.blocks.some(block => block.height === base.height && block.hash === base.hash);
      page.block_delta = canonical && distance >= 0 && distance <= 5 ? { base_height: base.height, base_hash: base.hash,
        blocks: current.blocks.slice(0, distance).reverse().map(block => ({ ...block, bounty_count: (rows.get(block.hash) ?? []).length })) } : null;
    }
    return structuredClone(page);
  };
  const bound = (params, changes = [], cursor = null, has_more = false) => {
    const page = full(params, changes, cursor, has_more);
    assert.ok(page.block_delta);
    page.tip = [current.tip.height, current.tip.hash, current.tip.mediantime];
    page.block_delta = page.block_delta.blocks.map((block, index, blocks) => [index === blocks.length - 1 ? null : block.hash, block.bounty_count]);
    return page;
  };
  const rpc = { async request(method, params = {}) {
    calls.push({ method, params: structuredClone(params) }); await before?.(method, params);
    let value;
    if (method === 'getrecentblockhashes') value = { ...current, bounty_counts: 1,
      blocks: current.blocks.slice(0, params.count ?? 600).map(block => ({ ...block, bounty_count: (rows.get(block.hash) ?? []).length })) };
    else {
      assert.equal(method, 'getbountychanges');
      if (pages.length) value = pages.shift()(params);
      else if (!params.known_state) value = full(params);
      else value = { compact: 2, unchanged: true };
    }
    return hook ? hook(method, params, structuredClone(value)) : structuredClone(value);
  } };
  return { calls, reads, rows, invalidations, resets, capabilities, warm, full, bound,
    get initial() { return initial; }, get current() { return current; }, set current(value) { current = value; },
    set pages(value) { pages = value; }, set hook(value) { hook = value; }, set before(value) { before = value; }, set afterRead(value) { afterRead = value; },
    options: { rpc, network: 'main', capabilities, onInvalidate: row => invalidations.push(row), onReset: row => resets.push(row),
      readBlock: async (blockHash, { budget }) => {
        reads.push(blockHash); const found = structuredClone(rows.get(blockHash) ?? []);
        budget.count += found.length; await afterRead?.(blockHash); return found;
      } } };
}

test('v2 ACK uses one request and retains the exact complete warm snapshot', async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]); f.rows.set(row.block_hash, [row]);
  let previous = f.warm();
  for (let i = 0; i < 10; i++) previous = previousFrom(await discoverBounties({ ...f.options, ...previous }));
  assert.equal(f.calls.length, 10); assert.deepEqual(f.reads, []); assert.equal(previous.cursor, '0');
  assert.deepEqual(previous.previous.get(row.block_hash), [row]);
  assert.ok(f.calls.every(call => call.params.compact_version === 2));
});

test('cold v2 fallback is explicit and replays after the authoritative hash snapshot', async () => {
  const f = fixture(), result = await discoverBounties(f.options);
  assert.equal(result.blocks.size, 600); assert.equal(result.cursor, '0');
  assert.deepEqual(f.calls.map(call => call.method), ['getbountychanges', 'getrecentblockhashes', 'getbountychanges']);
  assert.deepEqual(f.reads, []);
});

for (const count of [0, 1, 5]) test(`v2 request-bound ${count}-block suffix uses exact base and unchanged cursor`, async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(700 + count); f.pages = [params => f.bound(params)];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.tip, f.current.tip); assert.equal(result.cursor, '0');
  assert.equal(result.window.blocks[0].hash, f.current.tip.hash); assert.equal(result.blocks.size, 600);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.reads, []); assert.deepEqual(previous.previousWindow, f.initial);
});

test('v2 current-tip and equal-spender aliases retain immutable digest and final row validation', async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]); f.rows.set(row.block_hash, [row]);
  const event = stateEvent(row); f.pages = [params => f.bound(params, [event], '1')];
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(result.cursor, '1'); assert.deepEqual(result.blocks.get(row.block_hash), [{ ...row, ...event.bounty_delta }]);
  assert.equal(f.invalidations.length, 1); assert.deepEqual(f.reads, []);
});

test('v2 unequal historical outer spender is preserved, not replaced by final state', async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]); f.rows.set(row.block_hash, [row]);
  const event = stateEvent(row); delete event.spending_txid_ref; event.spending_txid = hash(901);
  f.pages = [params => f.bound(params, [event], '1')];
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(result.blocks.get(row.block_hash)[0].spending_txid, hash(900));
});

test('v2 historical full tips remain independent from the current publication tip', async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(); f.current = windowAt(701);
  f.pages = [params => { const page = f.bound(params, [{ ...stateEvent(row), tip_ref: 0 }], '1'); page.tips = [f.initial.tip]; return page; }];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(row.block_hash)[0].confirmations, 4); assert.deepEqual(f.reads, []);
});

test('v2 added identities reconstruct only from a complete validated nested row; stream replay is retained', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const row = { ...rowAt(f.current.blocks[0]), confirmations: 1 }; f.rows.set(row.block_hash, [row]);
  f.pages = [params => f.bound(params, [{ type: 'added', sequence: 1, tip_ref: -1, bounty: row }], '1')];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(row.block_hash), [row]); assert.deepEqual(f.reads, [row.block_hash]);
  assert.equal(f.calls.length, 2); assert.equal(f.calls[1].params.cursor, '1');
});

test('v2 mutation during a positive-count stream is replayed before publishing', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const row = { ...rowAt(f.current.blocks[0]), confirmations: 1 }; f.rows.set(row.block_hash, [row]);
  f.pages = [params => f.bound(params, [{ type: 'added', sequence: 1, tip_ref: -1, bounty: row }], '1')];
  f.afterRead = () => { f.pages = [params => f.bound(params, [stateEvent(row, 2)], '2')]; };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.cursor, '2'); assert.equal(result.blocks.get(row.block_hash)[0].status, 'pending_spend');
});

test('v2 pagination consumes every ordered page before advancing caller state', async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]); f.rows.set(row.block_hash, [row]);
  const first = stateEvent(row), second = { ...stateEvent(row, 2, 'spent'), bounty_delta: { ...first.bounty_delta, status: 'spent' } };
  f.pages = [params => f.bound(params, [first], '1', true), params => f.bound(params, [second], '2')];
  const previous = f.warm(), result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.cursor, '2'); assert.equal(result.blocks.get(row.block_hash)[0].status, 'spent');
  assert.deepEqual(f.calls.map(call => call.params.cursor), ['0', '1']); assert.equal(previous.cursor, '0');
});

test('unknown v2 immutable row replays the exact cursor expanded without losing its update', async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]), event = stateEvent(row);
  f.pages = [params => f.bound(params, [event], '1'), params => {
    assert.equal(params.compact, undefined); assert.equal(params.compact_version, undefined); assert.equal(params.cursor, '0');
    const page = f.full(params, [{ type: event.type, sequence: 1, txid: row.txid, vout: row.vout,
      bounty: { ...row, ...event.bounty_delta }, tip: f.current.tip }], '1');
    delete page.compact; delete page.tips;
    return { ...page, bounty_deltas: 1, block_deltas: 1 };
  }];
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(result.cursor, '1'); assert.deepEqual(result.blocks.get(row.block_hash), [{ ...row, ...event.bounty_delta }]);
  assert.equal(f.calls.length, 2);
});

test('unknown v2 row cannot hide a malformed sibling event behind expanded replay', async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]);
  f.pages = [params => f.bound(params, [stateEvent(row), { ...stateEvent(row, 2), spending_txid_ref: false }], '2')];
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }), /spender alias/);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.invalidations, []);
});

test('v2 full reorg fallback reads five hashes and does not infer an ordinary suffix', async () => {
  const f = fixture(), previous = f.warm();
  const replacement = structuredClone(f.current); replacement.tip.hash = hash(99999); replacement.blocks[0].hash = replacement.tip.hash; f.current = replacement;
  f.pages = [params => f.full(params)];
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.tip.hash, replacement.tip.hash);
  assert.deepEqual(f.calls.filter(call => call.method === 'getrecentblockhashes').map(call => call.params.count), [5]);
});

test('v2 journal reset discards old request bindings before rebuilding a complete snapshot', async () => {
  const f = fixture(); let first = true;
  f.before = () => { if (first) { first = false; throw Object.assign(new Error('Cursor reset'), { code: -32011 }); } };
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(result.blocks.size, 600); assert.equal(f.calls[1].params.cursor, undefined);
  assert.equal(f.calls[1].params.known_state, undefined); assert.ok(f.resets.length);
});

test('v2 parameter fallback retries the same cursor and is remembered only in supplied epoch capabilities', async () => {
  const f = fixture();
  f.before = (method, params) => { if (params.compact_version === 2) throw Object.assign(new Error('Old version'), { code: -32602 }); };
  f.hook = (method, params, page) => method === 'getbountychanges' ? { compact: 1, unchanged: true } : page;
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.deepEqual(f.calls.map(call => call.params.compact_version), [2, undefined]); assert.equal(f.capabilities.compactVersion, 1);
  await discoverBounties({ ...f.options, ...previousFrom(result) }); assert.equal(f.calls.length, 3);
  await discoverBounties({ ...f.options, capabilities: {}, ...previousFrom(result) }); assert.equal(f.calls.length, 5);
  assert.ok(f.calls.every(call => call.params.cursor === '0'));
});

test('valid v1 response from a server ignoring v2 is remembered after validation', async () => {
  const f = fixture(); f.hook = () => ({ compact: 1, unchanged: true });
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(f.capabilities.compactVersion, 1);
  await discoverBounties({ ...f.options, ...previousFrom(result) }); assert.equal(f.calls[1].params.compact_version, undefined);
});

const malformedPages = {
  unknown_version: page => { page.compact = 3; },
  string_version: page => { page.compact = '2'; },
  mixed_capabilities: page => { page.bounty_deltas = 1; },
  mixed_block_capabilities: page => { page.block_deltas = 1; },
  short_tip: page => { page.tip.pop(); },
  long_tip: page => { page.tip.push('main'); },
  malformed_hash: page => { page.tip[1] = 'bad'; },
  fractional_height: page => { page.tip[0] += 0.5; },
  contradictory_time: page => { page.tip[2]++; },
  negative_time: page => { page.tip[2] = -1; },
  object_delta_for_array_tip: page => { page.block_delta = { blocks: [] }; },
  null_delta_for_array_tip: page => { page.block_delta = null; },
  missing_delta: page => { delete page.block_delta; },
  extra_block: page => { page.block_delta.push([null, 0]); },
  null_cursor_with_more: page => { page.has_more = true; },
  full_tip_with_array_delta: page => { page.tip = windowAt().tip; },
  unbound_null_cursor: page => { page.tip = windowAt().tip; page.block_delta = null; },
};
for (const [name, mutate] of Object.entries(malformedPages)) test(`malformed v2 ${name} fails closed without negotiation or caller mutation`, async () => {
  const f = fixture(), previous = f.warm(), copy = structuredClone(previous);
  f.pages = [params => { const page = f.bound(params); mutate(page); return page; }];
  await assert.rejects(discoverBounties({ ...f.options, ...previous }));
  assert.equal(f.calls.length, 1); assert.deepEqual(previous, copy); assert.deepEqual(f.capabilities, {});
});

const malformedEvents = {
  wrong_reference: page => { page.changes[0].bounty_ref = hash(88); },
  mixed_spender: page => { page.changes[0].spending_txid = hash(900); },
  false_spender_ref: page => { page.changes[0].spending_txid_ref = false; },
  malformed_spender: page => { page.changes[0].bounty_delta.spending_txid = 'bad'; },
  missing_spender: page => { delete page.changes[0].bounty_delta.spending_txid; },
  extra_delta_field: page => { page.changes[0].bounty_delta.domain = 'forged.example'; },
  wrong_confirmations: page => { page.changes[0].bounty_delta.confirmations++; },
  bad_tip_reference: page => { page.changes[0].tip_ref = -2; },
  absent_tip_reference: page => { page.changes[0].tip_ref = 0; },
  later_sentinel_cannot_authorize_bad_index: page => { page.changes.unshift({ ...page.changes[0], tip_ref: 0 }); page.changes[1].sequence++; },
  duplicate_sequence: page => { page.changes.push(structuredClone(page.changes[0])); },
  null_cursor_with_changes: page => { page.next_cursor = null; },
  conflicting_network: page => { page.tips = [{ ...windowAt().tip, chain: 'testnet' }]; page.changes[0].tip_ref = 0; },
  conflicting_tip_time: page => { page.tips = [{ ...windowAt().tip, mediantime: 1 }]; page.changes[0].tip_ref = 0; },
};
for (const [name, mutate] of Object.entries(malformedEvents)) test(`malformed v2 event ${name} cannot publish or fall back`, async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), copy = structuredClone(previous);
  f.pages = [params => { const page = f.bound(params, [stateEvent(row)], '1'); mutate(page); return page; }];
  await assert.rejects(discoverBounties({ ...f.options, ...previous }));
  assert.equal(f.calls.length, 1); assert.deepEqual(previous, copy); assert.deepEqual(f.invalidations, []);
});

for (const field of ['txid', 'vout', 'block_hash', 'block_height']) test(`v2 added rejects mixed outer ${field}`, async () => {
  const f = fixture(), row = rowAt(f.initial.blocks[2]), previous = f.warm();
  f.pages = [params => f.bound(params, [{ type: 'added', sequence: 1, tip_ref: -1, bounty: row, [field]: row[field] }], '1')];
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Mixed compact added identity/);
  assert.equal(f.calls.length, 1);
});

for (const [name, edit] of Object.entries({
  missing_count: blocks => { blocks[0].pop(); }, negative_count: blocks => { blocks[0][1] = -1; },
  fractional_count: blocks => { blocks[0][1] = 0.5; }, huge_count: blocks => { blocks[0][1] = 100001; },
  null_nonendpoint: blocks => { blocks[0][0] = null; }, duplicate_hash: blocks => { blocks[1][0] = blocks[0][0]; },
  wrong_endpoint: blocks => { blocks[1][0] = hash(999); }, extra_pair_value: blocks => { blocks[0].push(1); },
})) test(`v2 block pair ${name} fails full canonical/count validation`, async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(702);
  f.pages = [params => { const page = f.bound(params); edit(page.block_delta); return page; }];
  await assert.rejects(discoverBounties({ ...f.options, ...previous })); assert.equal(f.calls.length, 1);
});

test('v2 request-bound page cannot be used on initialization without known_state', async () => {
  const f = fixture(); f.pages = [() => ({ compact: 2, tip: [700, f.current.tip.hash, f.current.tip.mediantime],
    tips: [], changes: [], next_cursor: null, has_more: false, block_delta: [] })];
  await assert.rejects(discoverBounties(f.options), /request-bound/); assert.equal(f.calls.length, 1);
});

test('v2 ACK with extra fields cannot change the saved cursor or header', async () => {
  const f = fixture(); f.pages = [() => ({ compact: 2, unchanged: true, next_cursor: 'forged' })];
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }), /unchanged/); assert.equal(f.calls.length, 1);
});

test('v2 response after negotiated v1 downgrade is rejected, not silently decoded', async () => {
  const f = fixture(); f.capabilities.compactVersion = 1;
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }), /Unrequested/); assert.equal(f.calls.length, 1);
});

for (const code of [-32001, -32002, -32029, -32601, 'ECONNRESET']) test(`v2 actual failure ${code} cannot disable validation`, async () => {
  const f = fixture(); f.before = () => { throw Object.assign(new Error('RPC failure'), { code }); };
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }));
  assert.equal(f.calls.length, 1); assert.deepEqual(f.capabilities, {});
});
