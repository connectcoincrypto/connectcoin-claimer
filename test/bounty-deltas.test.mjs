import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties, readBountyBlock } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const windowAt = (height = 700, replacements = new Map()) => {
  const blocks = Array.from({ length: Math.min(600, height + 1) }, (_, index) => ({ height: height - index,
    hash: replacements.get(height - index) ?? (height === index ? GENESIS.main : hash(height - index + 1000)) }));
  return { window: 600, blocks, tip: { height, hash: blocks[0].hash, mediantime: 1700000000 + height,
    chain: 'main', genesis_hash: GENESIS.main } };
};
const bountyAt = (block, id = 1, tipHeight = 700) => ({ txid: hash(100000 + id), vout: 0,
  block_hash: block.hash, block_height: block.height, amount: '10000000000', domain: 'example.com',
  connection_work_target: 'f'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7,
  coinbase: false, confirmations: tipHeight - block.height + 1, status: 'available', spending_txid: null });
const changed = (row, sequence, tip, type = 'pending_spend') => ({ type, sequence, txid: row.txid,
  vout: row.vout, ...(type === 'added' ? { block_hash: row.block_hash } : {}), tip: structuredClone(tip), bounty: structuredClone(row) });

function fixture({ deltas = true, height = 700 } = {}) {
  let current = windowAt(height), sequence = 0, bytes = 0, hook, afterStream;
  const calls = [], reads = [], invalidations = [], resets = [], queued = [], rows = new Map();
  const count = method => calls.filter(call => call.method === method).length;
  const record = response => { bytes += Buffer.byteLength(JSON.stringify(response)); return structuredClone(response); };
  const rpc = { async request(method, params = {}, options = {}) {
    calls.push({ method, params: structuredClone(params) });
    const overridden = await hook?.(method, count(method), params);
    if (overridden !== undefined) return record(overridden);
    if (method === 'getchaintip') return record(current.tip);
    if (method === 'getrecentblockhashes') return record({ ...current, blocks: current.blocks.slice(0, params.count ?? 600) });
    if (method === 'getbountychanges') {
      const changes = queued.shift() ?? [];
      if (changes.length) sequence = changes.at(-1).sequence;
      return record({ tip: current.tip, next_cursor: String(sequence), has_more: queued.length > 0,
        ...(deltas ? { bounty_deltas: 1 } : {}), changes: deltas ? changes : changes.map(({ bounty, tip, ...event }) => event) });
    }
    assert.equal(method, 'getblockbounties'); reads.push(params.block_hash);
    const snapshot = (rows.get(params.block_hash) ?? []).map(row => ({ ...row, confirmations: current.tip.height - row.block_height + 1 }));
    let chunks = 0;
    const chunk = value => { options.onChunk(record({ ...value, tip: current.tip })); chunks++; };
    chunk({ type: 'snapshot', block_hash: params.block_hash, unit: 'connects', cursor: String(sequence) });
    for (let offset = 0; offset < snapshot.length; offset += 1000) chunk({ type: 'bounties', items: snapshot.slice(offset, offset + 1000) });
    chunk({ type: 'state', cursor: String(sequence) });
    await afterStream?.(params.block_hash);
    return record({ records: snapshot.length, chunks });
  } };
  return { rpc, calls, reads, rows, queued, invalidations, resets, count,
    get bytes() { return bytes; }, get current() { return current; }, set current(value) { current = value; },
    set hook(value) { hook = value; }, set afterStream(value) { afterStream = value; },
    warm() { return { previousWindow: structuredClone(current), cursor: String(sequence),
      previous: new Map(current.blocks.map(block => [block.hash, structuredClone(rows.get(block.hash) ?? [])])) }; },
    options: { rpc, network: 'main', onInvalidate: (row, reason) => invalidations.push({ row, reason }),
      onReset: reason => resets.push(reason),
      readBlock: (hash, details) => readBountyBlock({ rpc, network: 'main', hash, ...details }) },
  };
}

test('many same-block updates use row-sized traffic and zero block rereads', async t => {
  const totals = [];
  for (const deltas of [false, true]) {
    const f = fixture({ deltas }), block = f.current.blocks[2];
    f.rows.set(block.hash, Array.from({ length: 4000 }, (_, index) => bountyAt(block, index)));
    let previous = f.warm();
    for (let sequence = 1; sequence <= 20; sequence++) {
      const row = { ...f.rows.get(block.hash)[sequence], status: 'pending_spend', spending_txid: hash(900000 + sequence) };
      f.rows.get(block.hash)[sequence] = row;
      f.queued.push([changed(row, sequence, f.current.tip)]);
      const result = await discoverBounties({ ...f.options, ...previous });
      assert.deepEqual(result.blocks.get(block.hash)[sequence], row);
      previous = { previous: result.blocks, previousWindow: result.window, cursor: result.cursor };
    }
    assert.equal(f.reads.length, deltas ? 0 : 20);
    assert.equal(f.count('getrecentblockhashes'), 0);
    assert.equal(f.count('getbountychanges'), deltas ? 20 : 40);
    assert.equal(f.count('getchaintip'), 0);
    totals.push(f.bytes);
  }
  assert.ok(totals[1] < totals[0] / 100, 'Incremental traffic must be proportional to changed rows, not the 4,000-row block.');
  t.diagnostic(`20 changes in a 4,000-row block: legacy=${totals[0]} bytes / 20 rereads; deltas=${totals[1]} bytes / 0 rereads.`);
});

test('ordered delta pages apply final publication rows and preserve the old published catalog', async () => {
  const f = fixture(), a = bountyAt(f.current.blocks[2]), b = bountyAt(f.current.blocks[2], 2);
  f.rows.set(a.block_hash, [a, b]); const previous = f.warm(), original = previous.previous.get(a.block_hash);
  const pending = { ...a, status: 'pending_spend', spending_txid: hash(900) };
  const spent = { ...b, status: 'spent', spending_txid: hash(901) };
  f.queued.push([changed(pending, 1, f.current.tip)], [changed(spent, 2, f.current.tip, 'spent')],
    [{ ...changed(a, 3, f.current.tip, 'pending_spend'), spending_txid: hash(999) }]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(a.block_hash), [a, spent]);
  assert.deepEqual(original, [a, b]);
  assert.notStrictEqual(result.blocks.get(a.block_hash), original);
  assert.equal(result.cursor, '3'); assert.deepEqual(f.reads, []);
  assert.deepEqual(f.calls.filter(call => call.method === 'getbountychanges').map(call => call.params.cursor), ['0', '1', '2']);
  assert.deepEqual(f.invalidations.map(value => value.reason), ['pending_spend', 'spent']);
});

test('new outpoints join complete cached blocks without losing existing rows', async () => {
  const f = fixture(), a = bountyAt(f.current.blocks[1]), b = bountyAt(f.current.blocks[1], 2);
  f.rows.set(a.block_hash, [a]); const previous = f.warm();
  f.queued.push([changed(b, 1, f.current.tip, 'added')]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(a.block_hash), [a, b]); assert.deepEqual(f.reads, []);
});

test('window-exit null rows are accepted only after their block leaves the canonical window', async () => {
  const f = fixture(), row = bountyAt(f.current.blocks.at(-1)); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(); f.current = windowAt(701);
  f.queued.push([{ ...changed(row, 1, f.current.tip, 'window_exit'), bounty: null }]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.has(row.block_hash), false);
  assert.ok(f.invalidations.some(value => value.reason === 'window_exit' && value.row.txid === row.txid));
  assert.deepEqual(previous.previous.get(row.block_hash), [row]);
});

test('a new block between delta pages is loaded completely before publication', async () => {
  const f = fixture(), previous = f.warm(), next = windowAt(701);
  const row = bountyAt(next.blocks[0], 1, 701), sibling = bountyAt(next.blocks[0], 2, 701);
  f.rows.set(row.block_hash, [row, sibling]);
  const old = bountyAt(f.current.blocks[1], 3);
  f.hook = (method, count) => {
    if (method !== 'getbountychanges') return;
    if (count === 1) return { tip: f.current.tip, bounty_deltas: 1, next_cursor: '1', has_more: true,
      changes: [changed(old, 1, f.current.tip, 'added')] };
    if (count === 2) {
      f.current = next;
      return { tip: next.tip, bounty_deltas: 1, next_cursor: '2', has_more: false,
        changes: [changed(row, 2, next.tip, 'added')] };
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(row.block_hash), [row, sibling]);
  assert.deepEqual(f.reads, [row.block_hash]);
});

test('new blocks load every bounty once and replay updates arriving during the stream', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const a = bountyAt(f.current.blocks[0], 1, 701), unannounced = bountyAt(f.current.blocks[0], 2, 701);
  f.rows.set(a.block_hash, [a, unannounced]);
  f.queued.push([changed(a, 1, f.current.tip, 'added')]);
  const pending = { ...a, status: 'pending_spend', spending_txid: hash(900) };
  f.afterStream = block => { if (block === a.block_hash) f.queued.push([changed(pending, 2, f.current.tip)]); };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(a.block_hash), [pending, unannounced]);
  assert.deepEqual(f.reads, [a.block_hash]); assert.equal(result.cursor, '2');
});

test('publication-tip confirmations are validated historically then refreshed to the final tip', async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), pending = { ...row, status: 'pending_spend', spending_txid: hash(900) };
  f.queued.push([changed(pending, 1, f.current.tip)]); f.current = windowAt(701);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(row.block_hash)[0].confirmations, 4);
  assert.equal(previous.previous.get(row.block_hash)[0].confirmations, 3);
  assert.deepEqual(f.reads, [f.current.tip.hash]);
});

test('confirmation refresh also owns unchanged cached rows instead of mutating the previous snapshot', async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(); f.current = windowAt(701);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(row.block_hash)[0].confirmations, 4);
  assert.equal(previous.previous.get(row.block_hash)[0].confirmations, 3);
});

const malformed = {
  txid: row => { row.txid = hash(9); },
  vout: row => { row.vout = 1; },
  block_hash: row => { row.block_hash = [row.block_hash]; },
  block_height: row => { row.block_height = 701; },
  wrong_canonical_height: row => { row.block_height--; row.confirmations++; },
  amount: row => { row.amount = '1000000000000000001'; },
  domain: row => { row.domain = 'bad..domain'; },
  connection_work_target: row => { row.connection_work_target = ['f'.repeat(64)]; },
  root_certificates_version: row => { row.root_certificates_version = 0; },
  signature_algorithms_mask: row => { row.signature_algorithms_mask = 8; },
  coinbase: row => { row.coinbase = 'false'; },
  confirmations: row => { row.confirmations++; },
  status: row => { row.status = 'unknown'; },
  pending_identity: row => { row.status = 'pending_spend'; },
  spent_identity: row => { row.status = 'spent'; },
  available_identity: row => { row.spending_txid = hash(9); },
  immature_identity: row => { row.status = 'immature'; },
  immature_spend: row => { row.coinbase = true; row.status = 'spent'; row.spending_txid = hash(9); },
  missing_spender: row => { delete row.spending_txid; },
  missing_coinbase: row => { delete row.coinbase; },
  immutable_amount: row => { row.amount = '42'; },
  immutable_domain: row => { row.domain = 'other.example.com'; },
};
for (const [name, mutate] of Object.entries(malformed)) test(`malformed delta ${name} fails without changing cache or cursor`, async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), originalRows = previous.previous.get(row.block_hash);
  const event = changed(row, 1, f.current.tip); mutate(event.bounty); f.queued.push([event]);
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|inconsistent/i);
  assert.strictEqual(previous.previous.get(row.block_hash), originalRows);
  assert.deepEqual(originalRows, [row]); assert.equal(previous.cursor, '0');
  assert.deepEqual(f.reads, []);
});

test('a non-exit null row and a missing expanded row cannot silently use the legacy path', async () => {
  for (const bounty of [null, undefined]) {
    const f = fixture(), row = bountyAt(f.current.blocks[2]), previous = f.warm();
    f.queued.push([{ ...changed(row, 1, f.current.tip), bounty }]);
    await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Invalid bounty (metadata|delta identity)/);
    assert.deepEqual(f.reads, []);
  }
});

for (const mutation of ['tip', 'network', 'block_hash', 'future-tip', 'capability']) test(`expanded ${mutation} metadata fails closed`, async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]), previous = f.warm(), event = changed(row, 1, f.current.tip);
  if (mutation === 'tip') delete event.tip;
  if (mutation === 'network') event.tip.genesis_hash = hash(9);
  if (mutation === 'block_hash') event.block_hash = [row.block_hash];
  if (mutation === 'future-tip') { event.tip.height++; event.tip.hash = hash(1701); }
  f.hook = method => method === 'getbountychanges' ? { tip: f.current.tip,
    bounty_deltas: mutation === 'capability' ? true : 1, changes: [event], next_cursor: '1', has_more: false } : undefined;
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|unexpected/i);
  assert.equal(previous.cursor, '0'); assert.deepEqual(f.reads, []);
});

test('publication window bounds are checked even for a delta outside the selected lookback', async () => {
  const f = fixture(), row = bountyAt({ hash: hash(1100), height: 100 });
  f.queued.push([changed(row, 1, f.current.tip, 'added')]);
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm(), lookback: 10 }), /Invalid bounty delta metadata/);
});

test('a failure after a valid applied delta leaves every previous row untouched for replay', async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), pending = { ...row, status: 'pending_spend', spending_txid: hash(900) };
  const invalid = changed(pending, 2, f.current.tip); invalid.bounty.amount = '-1';
  f.queued.push([changed(pending, 1, f.current.tip)], [invalid]);
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Invalid bounty metadata/);
  assert.deepEqual(previous.previous.get(row.block_hash), [row]); assert.equal(previous.cursor, '0');
});

test('legacy parameter rejection retries the exact cursor and retains whole-block refresh', async () => {
  const f = fixture({ deltas: false }), row = bountyAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), pending = { ...row, status: 'pending_spend', spending_txid: hash(900) };
  f.rows.set(row.block_hash, [pending]); f.queued.push([changed(pending, 1, f.current.tip)]);
  f.hook = (method, count, params) => {
    if (method === 'getbountychanges' && params.include_bounties) throw Object.assign(new Error('Unexpected parameter'), { code: -32602 });
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.calls.filter(call => call.method === 'getbountychanges').map(call => call.params),
    [{ cursor: '0', include_bounties: true, known_tip: { height: 700, hash: f.current.tip.hash } },
      { cursor: '0', include_bounties: true }, { cursor: '0' }, { cursor: '1' }]);
  assert.deepEqual(f.reads, [row.block_hash]); assert.deepEqual(result.blocks.get(row.block_hash), [pending]);
});

test('known-tip rejection preserves full bounty deltas and retries the same cursor without block reload', async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]), previous = f.warm();
  const pending = { ...row, status: 'pending_spend', spending_txid: hash(900) };
  f.queued.push([changed(pending, 1, f.current.tip)]);
  f.hook = (method, count, params) => {
    if (params.known_tip) throw Object.assign(new Error('Old optional schema'), { code: -32602 });
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.blocks.get(row.block_hash), [pending]); assert.deepEqual(f.reads, []);
  assert.deepEqual(f.calls.map(call => call.params), [
    { cursor: '0', include_bounties: true, known_tip: { height: 700, hash: f.current.tip.hash } },
    { cursor: '0', include_bounties: true },
  ]);
});

for (const code of [-32001, -32002, -32601, 'ECONNRESET']) test(`real RPC failure ${code} never falls back to legacy`, async () => {
  const f = fixture(), previous = f.warm();
  f.hook = method => { if (method === 'getbountychanges') throw Object.assign(new Error('Real failure'), { code }); };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), error => error.code === code);
  assert.equal(f.count('getbountychanges'), 1); assert.deepEqual(f.reads, []);
});

test('a rollback between journal and hash reads resets before applying displaced publication rows', async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), advanced = windowAt(701), rollback = windowAt(699);
  let reset = false;
  f.hook = (method, count) => {
    if (method === 'getbountychanges' && count === 1) return { tip: advanced.tip, next_cursor: '1', has_more: false,
      bounty_deltas: 1, changes: [changed({ ...row, confirmations: 4, status: 'pending_spend', spending_txid: hash(900) }, 1, advanced.tip)] };
    if (method === 'getrecentblockhashes' && !reset) { reset = true; f.current = rollback; }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(result.tip, rollback.tip); assert.equal(f.resets.length, 1);
  assert.equal(result.blocks.get(row.block_hash)[0].status, 'available');
  assert.equal(result.blocks.get(row.block_hash)[0].confirmations, 2);
  assert.deepEqual(previous.previous.get(row.block_hash), [row]);
  assert.ok(f.reads.includes(row.block_hash), 'Rollback requires complete post-reset snapshots.');
});

test('a journal reset revokes delta staging before a fresh stream failure', async () => {
  const f = fixture(), row = bountyAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), pending = { ...row, status: 'pending_spend', spending_txid: hash(900) };
  f.queued.push([changed(pending, 1, f.current.tip)], []);
  f.hook = (method, count) => {
    if (method === 'getbountychanges' && count === 2) throw Object.assign(new Error('Reset'), { code: -32011 });
    if (method === 'getblockbounties') { assert.equal(f.resets.length, 1); throw new Error('Stream failed'); }
  };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Stream failed/);
  assert.deepEqual(previous.previous.get(row.block_hash), [row]); assert.equal(previous.cursor, '0');
});
