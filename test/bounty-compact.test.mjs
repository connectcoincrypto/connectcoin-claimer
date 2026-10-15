import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { discoverBounties, bountyStateDigest, bountyImmutableDigest } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const sha = fields => createHash('sha256').update(JSON.stringify(fields)).digest('hex');
const stateHash = (tip, cursor) => sha(['bounty-state-v1', tip.chain, tip.genesis_hash, tip.height, tip.hash, tip.mediantime, cursor]);
const immutableHash = row => sha(['bounty-immutable-v1', row.txid, row.vout, row.block_hash, row.block_height,
  row.amount, row.domain, row.connection_work_target, row.root_certificates_version, row.signature_algorithms_mask, row.coinbase]);
const windowAt = (height = 700) => {
  const blocks = Array.from({ length: Math.min(height + 1, 600) }, (_, i) => ({ height: height - i, hash: height === i ? GENESIS.main : hash(1000 + height - i) }));
  return { window: 600, blocks, tip: { height, hash: blocks[0].hash, mediantime: 1700000000 + height, chain: 'main', genesis_hash: GENESIS.main } };
};
const rowAt = (block, tipHeight = 700, id = 1) => ({ txid: hash(100000 + id), vout: 0, block_hash: block.hash,
  block_height: block.height, amount: '100000000', domain: 'example.com', connection_work_target: 'f'.repeat(64),
  root_certificates_version: 1, signature_algorithms_mask: 7, coinbase: false,
  confirmations: tipHeight - block.height + 1, status: 'available', spending_txid: null });
const eventAt = (row, sequence, tip, type = 'pending_spend', rootSpender = row?.spending_txid) => ({
  type, sequence, txid: row.txid, vout: row.vout, ...(type === 'added' ? { block_hash: row.block_hash } : {}),
  ...(rootSpender ? { spending_txid: rootSpender } : {}), bounty: structuredClone(row), tip: structuredClone(tip),
});
const optionsFrom = result => ({ previous: result.blocks, previousWindow: result.window, cursor: result.cursor });

function fixture() {
  let current = windowAt(), sequence = 0, before, after, afterRead, bytes = 0;
  const rows = new Map(), pages = [], calls = [], reads = [], invalidations = [], resets = [];
  const rpc = { async request(method, params = {}) {
    calls.push({ method, params: structuredClone(params) });
    await before?.(method, params);
    let response;
    if (method === 'getrecentblockhashes') response = { ...current, blocks: current.blocks.slice(0, params.count ?? 600)
      .map(block => ({ ...block, ...(params.include_bounty_counts ? { bounty_count: (rows.get(block.hash) ?? []).length } : {}) })),
      ...(params.include_bounty_counts ? { bounty_counts: 1 } : {}) };
    else {
      assert.equal(method, 'getbountychanges');
      const changes = pages.shift() ?? [];
      if (changes.length) sequence = changes.at(-1).sequence;
      response = { tip: current.tip, next_cursor: String(sequence), has_more: pages.length > 0, changes, bounty_deltas: 1 };
      if (params.known_tip) {
        const base = params.known_tip, distance = current.tip.height - base.height;
        response.block_deltas = 1;
        response.block_delta = distance >= 0 && distance <= 5 && current.blocks.some(block => block.height === base.height && block.hash === base.hash)
          ? { base_height: base.height, base_hash: base.hash, blocks: current.blocks.slice(0, distance).reverse()
            .map(block => ({ ...block, bounty_count: (rows.get(block.hash) ?? []).length })) } : null;
      }
      if (params.compact) {
        if (!changes.length && !pages.length && params.known_state === stateHash(current.tip, String(sequence))) response = { compact: 1, unchanged: true };
        else {
          const tips = [], keys = [];
          response = { ...response, compact: 1, tips, changes: changes.map(event => {
            const key = JSON.stringify(event.tip);
            let tip_ref = keys.indexOf(key);
            if (tip_ref < 0) { tip_ref = keys.length; keys.push(key); tips.push(event.tip); }
            const { tip, bounty, ...rest } = event;
            return { ...rest, tip_ref, ...(['added', 'window_exit'].includes(event.type) ? { bounty } : {
              bounty_ref: immutableHash(bounty), bounty_delta: { status: bounty.status, spending_txid: bounty.spending_txid, confirmations: bounty.confirmations },
            }) };
          }) };
        }
      }
    }
    response = await after?.(method, params, structuredClone(response)) ?? response;
    bytes += Buffer.byteLength(JSON.stringify(response)); return structuredClone(response);
  } };
  return { rows, pages, calls, reads, invalidations, resets,
    get current() { return current; }, set current(value) { current = value; }, get bytes() { return bytes; },
    set before(value) { before = value; }, set after(value) { after = value; }, set afterRead(value) { afterRead = value; },
    warm() { return { previous: new Map(current.blocks.map(block => [block.hash, structuredClone(rows.get(block.hash) ?? [])])),
      previousWindow: structuredClone(current), cursor: String(sequence) }; },
    options: { rpc, network: 'main', onInvalidate: row => invalidations.push(row), onReset: reason => resets.push(reason),
      readBlock: async (hash, { budget }) => {
        reads.push(hash); const result = structuredClone(rows.get(hash) ?? []).map(row => ({ ...row, confirmations: current.tip.height - row.block_height + 1 }));
        budget.count += result.length; await afterRead?.(hash); return result;
      } },
  };
}

test('wire digests match independent canonical vectors', () => {
  assert.equal(bountyStateDigest({ chain: 'main', genesis_hash: 'a'.repeat(64), height: 123, hash: 'b'.repeat(64), mediantime: 1700000000 }, 'opaque-cursor-v1'),
    'a028924ae24da57f10b87198d8ae90f660bcf67ad7e09e80985e744f42d8a5a7');
  assert.equal(bountyImmutableDigest({ txid: 'c'.repeat(64), vout: 2, block_hash: 'd'.repeat(64), block_height: 120,
    amount: '100000000', domain: 'example.com', connection_work_target: 'e'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7, coinbase: false }),
    '49ef00b7fa42a74c1576f41c0e4d9fbc1cc08025b0785bdd12e0736a8f8d3b73');
});

test('100 warm ACKs retain the exact state with one request each and no guessed empty blocks', async t => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  let previous = f.warm();
  for (let i = 0; i < 100; i++) {
    const result = await discoverBounties({ ...f.options, ...previous });
    assert.deepEqual(result.blocks.get(row.block_hash), [row]); assert.equal(result.window.blockCounts, undefined);
    previous = optionsFrom(result);
  }
  assert.equal(f.calls.length, 100); assert.deepEqual(f.reads, []); assert.equal(f.bytes, 3000);
  assert.ok(f.calls.every(call => call.params.known_state === stateHash(f.current.tip, '0')));
  t.diagnostic(`100 unchanged compact polls: ${f.bytes} result bytes, 100 calls, no hash/block reads.`);
});

test('cold authoritative zero counts avoid all 600 streams but still replay after the hash read', async () => {
  const f = fixture(), result = await discoverBounties(f.options);
  assert.equal(f.calls.length, 3); assert.deepEqual(f.reads, []); assert.equal(result.blocks.size, 600);
  assert.equal(Object.keys(result.window.blockCounts).length, 600);
  assert.equal(f.calls[0].params.known_state, undefined);
  assert.equal(f.calls[1].params.include_bounty_counts, true);
  assert.equal(f.calls[2].params.known_state, stateHash(f.current.tip, '0'));
});

for (const [type, status, spender, coinbase] of [
  ['pending_spend', 'pending_spend', hash(900), false], ['spent', 'spent', hash(901), false],
  ['available_again', 'available', null, false], ['matured', 'available', null, true],
]) test(`compact ${type} reuses validated immutable fields and applies final ${status}`, async () => {
  const f = fixture(), row = { ...rowAt(f.current.blocks[coinbase ? 100 : 2]), coinbase };
  f.rows.set(row.block_hash, [row]); const previous = f.warm();
  const next = { ...row, status, spending_txid: spender }; f.pages.push([eventAt(next, 1, f.current.tip, type)]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.calls.length, 1); assert.deepEqual(f.reads, []); assert.deepEqual(result.blocks.get(row.block_hash), [next]);
  assert.deepEqual(previous.previous.get(row.block_hash), [row]);
});

test('coalesced event label and root spender never override final mutable state', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  f.pages.push([eventAt(row, 1, f.current.tip, 'pending_spend', hash(900)), eventAt(row, 2, f.current.tip, 'available_again')]);
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.deepEqual(result.blocks.get(row.block_hash), [row]); assert.deepEqual(f.invalidations, []);
});

test('historical publication tips validate confirmations independently from the current tip', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const previous = f.warm(), oldTip = f.current.tip, next = { ...row, status: 'pending_spend', spending_txid: hash(900) };
  f.pages.push([eventAt(next, 1, oldTip)]); f.current = windowAt(701);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(row.block_hash)[0].confirmations, row.confirmations + 1);
  assert.equal(result.blocks.get(row.block_hash)[0].status, 'pending_spend'); assert.deepEqual(f.reads, []);
});

test('unknown immutable references replay the same cursor expanded before publishing any event', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const row = { ...rowAt(f.current.blocks[0], 701), status: 'pending_spend', spending_txid: hash(900) };
  f.rows.set(row.block_hash, [row]); const event = eventAt(row, 1, f.current.tip);
  f.pages.push([event]);
  f.after = (method, params, response) => { if (params.compact && response.changes?.length) f.pages.unshift([event]); return response; };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.calls[0].params.cursor, '0'); assert.equal(f.calls[1].params.cursor, '0');
  assert.equal(f.calls[1].params.compact, undefined); assert.equal(f.calls[1].params.known_state, undefined);
  assert.deepEqual(f.reads, [row.block_hash]); assert.deepEqual(result.blocks.get(row.block_hash), [row]);
  assert.equal(result.cursor, '1'); assert.equal(previous.previous.has(row.block_hash), false);
});

test('added full rows can resolve following compact states on that page, while positive blocks still get complete snapshots', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const row = rowAt(f.current.blocks[0], 701), next = { ...row, status: 'spent', spending_txid: hash(900) };
  f.rows.set(row.block_hash, [next]); f.pages.push([eventAt(row, 1, f.current.tip, 'added'), eventAt(next, 2, f.current.tip, 'spent')]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.calls.length, 2); assert.deepEqual(f.reads, [row.block_hash]); assert.deepEqual(result.blocks.get(row.block_hash), [next]);
});

test('a spend racing positive-count streaming is replayed, not lost behind an ACK', async () => {
  const f = fixture(), previous = f.warm(); f.current = windowAt(701);
  const row = rowAt(f.current.blocks[0], 701), next = { ...row, status: 'spent', spending_txid: hash(900) };
  f.rows.set(row.block_hash, [row]); f.pages.push([eventAt(row, 1, f.current.tip, 'added')]);
  f.afterRead = () => { f.pages.push([eventAt(next, 2, f.current.tip, 'spent')]); };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.cursor, '2'); assert.deepEqual(result.blocks.get(row.block_hash), [next]); assert.equal(f.calls.length, 2);
});

test('an update after ACK stays after its cursor and is consumed next cycle', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const next = { ...row, status: 'pending_spend', spending_txid: hash(900) }; let raced = false;
  f.after = (method, params, response) => { if (!raced && response.unchanged) { raced = true; f.pages.push([eventAt(next, 1, f.current.tip)]); } return response; };
  const first = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(first.cursor, '0'); assert.deepEqual(first.blocks.get(row.block_hash), [row]);
  const second = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.equal(second.cursor, '1'); assert.deepEqual(second.blocks.get(row.block_hash), [next]);
});

for (const bad of [ { unchanged: true }, { compact: true, unchanged: true }, { compact: 1, unchanged: false },
  { compact: 1, unchanged: true, tip: windowAt().tip }, { compact: 1, unchanged: true, next_cursor: 'forged' },
  { compact: 1 }, { compact: 1, changes: [] } ]) test(`malformed ACK/full page cannot change cached state: ${JSON.stringify(bad)}`, async () => {
  const f = fixture(), previous = f.warm(); f.after = () => bad;
  await assert.rejects(discoverBounties({ ...f.options, ...previous }));
  assert.equal(f.calls.length, 1); assert.equal(previous.cursor, '0'); assert.deepEqual(f.reads, []);
});

test('an ACK without this request having sent known_state is rejected', async () => {
  const f = fixture(); f.after = () => ({ compact: 1, unchanged: true });
  await assert.rejects(discoverBounties(f.options), /Invalid unchanged/); assert.equal(f.calls[0].params.known_state, undefined);
});

const badCompact = {
  reference: p => { p.changes[0].bounty_ref = hash(42); },
  tip_missing: p => { p.tips = []; }, tip_index: p => { p.changes[0].tip_ref = 9; },
  tip_fraction: p => { p.changes[0].tip_ref = 0.5; }, tip_unacknowledged: p => { delete p.compact; },
  wrong_genesis: p => { p.tips[0].genesis_hash = hash(9); }, future_publication: p => { p.tips[0] = windowAt(701).tip; },
  mutable_extra: p => { p.changes[0].bounty_delta.amount = '1'; }, mutable_missing: p => { delete p.changes[0].bounty_delta.confirmations; },
  bad_status: p => { p.changes[0].bounty_delta.status = 'available'; },
  bad_spender: p => { p.changes[0].bounty_delta.spending_txid = 'broken'; },
  bad_confirmations: p => { p.changes[0].bounty_delta.confirmations++; },
  duplicated_full: p => { p.changes[0].bounty = {}; }, duplicated_tip: p => { p.changes[0].tip = p.tips[0]; },
  duplicate_sequence: p => { p.changes.push(structuredClone(p.changes[0])); },
};
for (const [name, mutate] of Object.entries(badCompact)) test(`compact ${name} fails closed without fallback/cache mutation`, async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]); const previous = f.warm();
  f.pages.push([eventAt({ ...row, status: 'pending_spend', spending_txid: hash(900) }, 1, f.current.tip)]);
  f.after = (method, params, response) => { mutate(response); return response; };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }));
  assert.equal(f.calls.length, 1); assert.deepEqual(previous.previous.get(row.block_hash), [row]); assert.equal(previous.cursor, '0');
});

for (const [name, mutate] of Object.entries({
  missing_ack: p => { delete p.bounty_counts; }, bad_ack: p => { p.bounty_counts = true; },
  missing_count: p => { delete p.blocks[1].bounty_count; }, negative: p => { p.blocks[1].bounty_count = -1; },
  fraction: p => { p.blocks[1].bounty_count = 0.5; }, string: p => { p.blocks[1].bounty_count = '0'; },
  excessive: p => { p.blocks[1].bounty_count = 100001; },
})) test(`initial authoritative counts reject ${name} before loading or publishing`, async () => {
  const f = fixture(); f.after = (method, params, response) => { if (method === 'getrecentblockhashes') mutate(response); return response; };
  await assert.rejects(discoverBounties(f.options)); assert.deepEqual(f.reads, []);
});

test('positive initial counts require complete streams of the exact advertised size', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  f.after = (method, params, response) => { if (method === 'getrecentblockhashes') response.blocks[2].bounty_count = 2; return response; };
  await assert.rejects(discoverBounties(f.options), /stream contradicts/); assert.deepEqual(f.reads, [row.block_hash]);
});

test('count option rejection retries without it and never treats missing counts as zero', async () => {
  const f = fixture(); f.before = (method, params) => { if (params.include_bounty_counts) throw Object.assign(new Error('Old schema'), { code: -32602 }); };
  const result = await discoverBounties(f.options);
  assert.equal(f.reads.length, 600); assert.equal(result.window.blockCounts, undefined);
  assert.deepEqual(f.calls.filter(c => c.method === 'getrecentblockhashes').map(c => c.params), [{ include_bounty_counts: true }, {}]);
});

test('compact rejection drops only compact/known_state at the same cursor', async () => {
  const f = fixture(); f.before = (method, params) => { if (params.compact) throw Object.assign(new Error('Old compact schema'), { code: -32602 }); };
  const result = await discoverBounties({ ...f.options, ...f.warm() });
  assert.equal(f.calls.length, 3); assert.equal(result.cursor, '0');
  assert.equal(f.calls[0].params.compact_version, 2);
  assert.equal(f.calls[1].params.compact_version, undefined); assert.equal(f.calls[1].params.compact, true);
  assert.deepEqual(f.calls[2].params, { cursor: '0', include_bounties: true, known_tip: { height: 700, hash: f.current.tip.hash } });
});

for (const code of [-32001, -32002, -32029, -32601, 'ECONNRESET']) test(`genuine compact failure ${code} never negotiates away validation`, async () => {
  const f = fixture(); f.before = () => { throw Object.assign(new Error('Backend failure'), { code }); };
  await assert.rejects(discoverBounties({ ...f.options, ...f.warm() }), error => error.code === code); assert.equal(f.calls.length, 1);
});

test('journal invalidation revokes previous ACK/count context and replays a fresh snapshot', async () => {
  const f = fixture(), first = await discoverBounties(f.options); f.calls.length = 0; let reset = false;
  f.before = (method, params) => { if (!reset) { reset = true; throw Object.assign(new Error('Journal reset'), { code: -32011 }); } };
  const row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.equal(f.calls[1].params.cursor, undefined); assert.equal(f.calls[1].params.known_state, undefined);
  assert.equal(f.calls[1].params.known_tip, undefined);
  assert.deepEqual(f.calls.filter(call => call.method === 'getrecentblockhashes').map(call => call.params), [{ include_bounty_counts: true }]);
  assert.deepEqual(f.reads, [row.block_hash]);
  assert.deepEqual(result.blocks.get(row.block_hash), [row]); assert.equal(Object.keys(result.window.blockCounts).length, 600);
  assert.equal(result.window.blockCounts[row.block_hash], 1);
});

for (const resetKind of ['cursor-invalid', 'data-unavailable', 'resync_required']) test(`mass expiry with ${resetKind} rebuilds fresh counts without opening empty block streams`, async () => {
  const f = fixture(), oldBlock = f.current.blocks.at(-1), retained = f.current.blocks[50];
  const expired = Array.from({ length: 500 }, (_, id) => rowAt(oldBlock, 700, id));
  const remaining = Array.from({ length: 284 }, (_, id) => rowAt(retained, 700, 1000 + id));
  f.rows.set(oldBlock.hash, expired); f.rows.set(retained.hash, remaining);
  const first = await discoverBounties(f.options), saved = structuredClone(first.blocks);
  f.calls.length = 0; f.reads.length = 0; f.current = windowAt(701);
  f.rows.set(oldBlock.hash, [{ ...expired[0], status: 'spent', spending_txid: hash(900) }, ...expired.slice(1)]);
  // These final states were not announced to this reset journal. The complete
  // positive-count stream, not just event rows, must recover all of them.
  f.rows.set(retained.hash, remaining.map((row, index) => ({ ...row,
    ...(index < 2 ? { status: index ? 'pending_spend' : 'spent', spending_txid: hash(901 + index) } : {}) })));
  let reset = false;
  f.before = method => {
    if (!reset && method === 'getbountychanges' && resetKind !== 'resync_required') {
      reset = true; throw Object.assign(new Error('Reset'), { code: resetKind === 'cursor-invalid' ? -32011 : -32004 });
    }
  };
  f.after = (method, params, response) => {
    if (!reset && method === 'getbountychanges') {
      reset = true; return { ...response, changes: [{ type: 'resync_required' }] };
    }
    return response;
  };
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.deepEqual(f.reads, [retained.hash]); assert.equal(result.blocks.size, 600);
  assert.equal(result.blocks.has(oldBlock.hash), false); assert.equal(result.window.blockCounts[oldBlock.hash], undefined);
  assert.equal(result.blocks.get(retained.hash).length, 284);
  assert.deepEqual(result.blocks.get(retained.hash).map(row => row.status), ['spent', 'pending_spend', ...Array(282).fill('available')]);
  assert.ok(result.blocks.get(retained.hash).every(row => row.confirmations === 52));
  assert.equal(Object.keys(result.window.blockCounts).length, 600);
  assert.equal(result.window.blockCounts[retained.hash], 284);
  assert.deepEqual(f.calls.filter(call => call.method === 'getrecentblockhashes').map(call => call.params), [{ include_bounty_counts: true }]);
  assert.equal(f.calls[1].params.cursor, undefined); assert.equal(f.calls[1].params.known_tip, undefined);
  assert.equal(f.calls[1].params.known_state, undefined);
  assert.equal(f.calls.at(-1).method, 'getbountychanges'); assert.equal(f.calls.at(-1).params.cursor, '0');
  assert.deepEqual(first.blocks, saved, 'No partial recovery mutates the caller catalog.');
});

test('a missing cursor cannot bind the old hash suffix or reuse old zero counts', async () => {
  const f = fixture(), first = await discoverBounties(f.options), row = rowAt(f.current.blocks[2]);
  f.rows.set(row.block_hash, [row]); f.calls.length = 0;
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first), cursor: null });
  assert.equal(f.calls[0].params.known_tip, undefined); assert.equal(f.calls[0].params.known_state, undefined);
  assert.deepEqual(f.reads, [row.block_hash]); assert.deepEqual(result.blocks.get(row.block_hash), [row]);
  assert.equal(result.window.blockCounts[row.block_hash], 1);
  assert.equal(first.window.blockCounts[row.block_hash], 0); assert.deepEqual(first.blocks.get(row.block_hash), []);
});

test('a same-tip reset still replays spending changes after its replacement stream', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]);
  const first = await discoverBounties(f.options); f.calls.length = 0; f.reads.length = 0;
  let reset = false;
  f.before = () => { if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); } };
  const spent = { ...row, status: 'spent', spending_txid: hash(901) };
  f.afterRead = () => { f.pages.push([eventAt(spent, 1, f.current.tip, 'spent')]); };
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.equal(result.cursor, '1'); assert.deepEqual(result.blocks.get(row.block_hash), [spent]);
  assert.deepEqual(f.reads, [row.block_hash]); assert.ok(f.invalidations.some(value => value.txid === row.txid));
  assert.deepEqual(first.blocks.get(row.block_hash), [row]);
});

for (const race of ['new-block', 'reorg', 'rollback']) test(`a ${race} during the reset manifest preserves canonical counts and the final replay fence`, async () => {
  const f = fixture(), oldRow = rowAt(f.current.blocks[0]), retained = rowAt(f.current.blocks[50], 700, 2);
  f.rows.set(oldRow.block_hash, [oldRow]); f.rows.set(retained.block_hash, [retained]);
  const first = await discoverBounties(f.options); f.calls.length = 0; f.reads.length = 0;
  let reset = false, raced = false, newRow;
  f.before = () => { if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); } };
  f.after = (method, params, response) => {
    if (method === 'getrecentblockhashes' && !raced) {
      raced = true;
      if (race === 'new-block') f.current = windowAt(701);
      else if (race === 'reorg') {
        f.current = windowAt(); f.current.tip.hash = hash(99999); f.current.blocks[0].hash = f.current.tip.hash;
      } else f.current = windowAt(699);
      const block = race === 'rollback' ? f.current.blocks.at(-1) : f.current.blocks[0];
      newRow = rowAt(block, f.current.tip.height, 3); f.rows.set(block.hash, [newRow]);
      f.pages.push([eventAt(newRow, 1, f.current.tip, 'added')]);
    }
    return response;
  };
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.deepEqual(result.tip, f.current.tip); assert.equal(result.cursor, '1');
  assert.deepEqual(result.blocks.get(newRow.block_hash), [newRow]);
  assert.equal(result.blocks.size, 600); assert.equal(Object.keys(result.window.blockCounts).length, 600);
  assert.ok(f.reads.every(blockHash => (f.rows.get(blockHash) ?? []).length > 0), 'No empty streams may be inferred from a lost manifest.');
  assert.equal(f.calls.at(-1).method, 'getbountychanges'); assert.equal(f.calls.at(-1).params.cursor, '1');
  assert.equal(f.calls.filter(call => call.method === 'getrecentblockhashes')[0].params.count, undefined);
  if (race !== 'new-block') {
    assert.equal(result.blocks.has(oldRow.block_hash), false); assert.equal(result.window.blockCounts[oldRow.block_hash], undefined);
    assert.ok(f.invalidations.some(value => value.txid === oldRow.txid));
  }
  assert.deepEqual(first.blocks.get(oldRow.block_hash), [oldRow]);
});

test('a manifest already newer than the reset watermark retains its full counts through replay', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[50]); f.rows.set(row.block_hash, [row]);
  const first = await discoverBounties(f.options); f.calls.length = 0; f.reads.length = 0;
  let reset = false, advanced = false, added;
  f.before = method => {
    if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); }
    if (method === 'getrecentblockhashes' && !advanced) {
      advanced = true; f.current = windowAt(701); added = rowAt(f.current.blocks[0], 701, 2); f.rows.set(added.block_hash, [added]);
      f.pages.push([eventAt(added, 1, f.current.tip, 'added')]);
    }
  };
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.deepEqual(result.tip, f.current.tip); assert.equal(result.cursor, '1'); assert.equal(Object.keys(result.window.blockCounts).length, 600);
  assert.deepEqual(f.reads, [row.block_hash, added.block_hash]); assert.deepEqual(result.blocks.get(added.block_hash), [added]);
  assert.equal(f.calls[1].params.known_tip, undefined);
  assert.deepEqual(f.calls.filter(call => call.method === 'getrecentblockhashes').map(call => call.params.count), [undefined, 5]);
  assert.equal(f.calls.at(-1).method, 'getbountychanges');
});

test('a reset can recover a complete disjoint window without requiring an obsolete ancestor', async () => {
  const f = fixture(), first = await discoverBounties(f.options); f.calls.length = 0;
  f.current = windowAt(1400); const row = rowAt(f.current.blocks[20], 1400); f.rows.set(row.block_hash, [row]);
  let reset = false;
  f.before = () => { if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); } };
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.deepEqual(result.tip, f.current.tip); assert.deepEqual(f.reads, [row.block_hash]);
  assert.deepEqual(result.blocks.get(row.block_hash), [row]); assert.equal(Object.keys(result.window.blockCounts).length, 600);
  assert.equal(f.calls.filter(call => call.method === 'getrecentblockhashes').length, 1);
  assert.equal(result.blocks.has(first.tip.hash), false);
});

test('epoch cancellation during the reset manifest stops streams and publication', async () => {
  const f = fixture(), first = await discoverBounties(f.options); f.calls.length = 0;
  let reset = false, cancelled = false;
  f.before = () => { if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); } };
  f.after = (method, params, response) => { if (method === 'getrecentblockhashes') cancelled = true; return response; };
  await assert.rejects(discoverBounties({ ...f.options, ...optionsFrom(first),
    check: () => { if (cancelled) throw Object.assign(new Error('Epoch changed'), { name: 'AbortError' }); },
  }), { name: 'AbortError' });
  assert.deepEqual(f.reads, []); assert.equal(f.calls.at(-1).method, 'getrecentblockhashes');
  assert.equal(first.cursor, '0'); assert.equal(first.blocks.size, 600);
});

for (const count of [0, 2]) test(`fresh reset count ${count} still rejects a contradictory complete stream or journal row`, async () => {
  const f = fixture(), first = await discoverBounties(f.options), row = rowAt(f.current.blocks[2]);
  f.rows.set(row.block_hash, [row]); f.calls.length = 0;
  let reset = false, manifest = false;
  f.before = () => { if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); } };
  f.after = (method, params, response) => {
    if (method === 'getrecentblockhashes') {
      manifest = true; response.blocks.find(block => block.hash === row.block_hash).bounty_count = count;
    } else if (manifest && count === 0) {
      // A zero may avoid its stream, but cannot conceal a later contradictory
      // row from the mandatory journal replay fence.
      return { tip: f.current.tip, next_cursor: '1', has_more: false, bounty_deltas: 1,
        changes: [eventAt(row, 1, f.current.tip, 'added')] };
    }
    return response;
  };
  await assert.rejects(discoverBounties({ ...f.options, ...optionsFrom(first) }), /empty block|immutable block count/);
  assert.equal(first.window.blockCounts[row.block_hash], 0); assert.deepEqual(first.blocks.get(row.block_hash), []);
});

for (const legacy of ['missing', 'reject']) test(`a reset on an RPC with ${legacy} count support still loads every unknown-count block`, async () => {
  const f = fixture(), first = await discoverBounties(f.options), row = rowAt(f.current.blocks[2]);
  f.rows.set(row.block_hash, [row]); f.calls.length = 0;
  let reset = false;
  f.before = (method, params) => {
    if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); }
    if (legacy === 'reject' && method === 'getrecentblockhashes' && params.include_bounty_counts) throw Object.assign(new Error('Unsupported'), { code: -32602 });
  };
  f.after = (method, params, response) => {
    if (method === 'getrecentblockhashes') { delete response.bounty_counts; for (const block of response.blocks) delete block.bounty_count; }
    return response;
  };
  const result = await discoverBounties({ ...f.options, ...optionsFrom(first) });
  assert.equal(f.reads.length, 600); assert.deepEqual(result.blocks.get(row.block_hash), [row]);
  assert.equal(result.window.blockCounts, undefined);
  assert.equal(f.calls.filter(call => call.method === 'getrecentblockhashes').length, legacy === 'reject' ? 2 : 1);
  assert.equal(f.calls.at(-1).method, 'getbountychanges');
});

const invalidResetManifest = {
  short: page => { page.blocks.pop(); },
  missing_capability: page => { delete page.bounty_counts; },
  invalid_count: page => { page.blocks[100].bounty_count = -1; },
  old_same_hash_time: page => { page.tip.mediantime++; },
  same_hash_ancestry: page => { page.blocks[100].hash = hash(99999); },
  same_hash_height: page => { const a = page.blocks[100].hash; page.blocks[100].hash = page.blocks[101].hash; page.blocks[101].hash = a; },
};
for (const [kind, mutate] of Object.entries(invalidResetManifest)) test(`reset manifest ${kind} fails closed without a weaker fallback or partial publication`, async () => {
  const f = fixture(), first = await discoverBounties(f.options); f.calls.length = 0;
  let reset = false;
  f.before = () => { if (!reset) { reset = true; throw Object.assign(new Error('Reset'), { code: -32011 }); } };
  f.after = (method, params, response) => { if (method === 'getrecentblockhashes') mutate(response); return response; };
  await assert.rejects(discoverBounties({ ...f.options, ...optionsFrom(first) }));
  assert.equal(f.calls.filter(call => call.method === 'getrecentblockhashes').length, 1); assert.deepEqual(f.reads, []);
  assert.equal(first.cursor, '0'); assert.equal(Object.keys(first.window.blockCounts).length, 600);
});

const hiddenFailures = {
  known_reference: p => { p.changes[1].bounty_ref = hash(42); },
  root_identity: p => { p.changes[1].block_hash = hash(42); },
  missing_cursor: p => { delete p.next_cursor; }, invalid_cursor: p => { p.next_cursor = ''; },
  unchanged_cursor: p => { p.next_cursor = '0'; }, malformed_has_more: p => { p.has_more = 'false'; },
  invalid_capability: p => { p.bounty_deltas = 2; }, invalid_block_capability: p => { p.block_deltas = 2; },
  missing_block_delta: p => { delete p.block_delta; }, invalid_block_base: p => { p.block_delta.base_hash = hash(42); },
  contradictory_block_count: p => { p.block_delta.blocks.push({ height: 701, hash: hash(1701), bounty_count: 0 }); },
};
for (const [name, mutate] of Object.entries(hiddenFailures)) test(`an unknown reference never hides ${name} behind expanded fallback`, async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]); const previous = f.warm();
  const unknown = { ...row, txid: hash(100002), status: 'pending_spend', spending_txid: hash(900) };
  f.pages.push([eventAt(unknown, 1, f.current.tip), eventAt({ ...row, status: 'pending_spend', spending_txid: hash(901) }, 2, f.current.tip)]);
  f.after = (method, params, response) => { if (params.compact) mutate(response); return response; };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }));
  assert.equal(f.calls.length, 1); assert.deepEqual(f.invalidations, []);
  assert.equal(previous.cursor, '0'); assert.deepEqual(previous.previous.get(row.block_hash), [row]);
});

test('an unknown reference cannot hide an added row contradicting known immutable metadata', async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]); const previous = f.warm();
  const unknown = { ...row, txid: hash(100002), status: 'pending_spend', spending_txid: hash(900) };
  f.pages.push([eventAt(unknown, 1, f.current.tip), eventAt({ ...row, amount: '1' }, 2, f.current.tip, 'added')]);
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /immutable bounty metadata/);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.invalidations, []); assert.deepEqual(previous.previous.get(row.block_hash), [row]);
});

test('an unknown reference cannot hide an added row contradicting an acknowledged zero', async () => {
  const f = fixture(), previous = f.warm(), row = rowAt(f.current.blocks[2]);
  previous.previousWindow.blockCounts = { [row.block_hash]: 0 };
  const unknown = { ...row, txid: hash(100002), status: 'pending_spend', spending_txid: hash(900) };
  f.pages.push([eventAt(unknown, 1, f.current.tip), eventAt(row, 2, f.current.tip, 'added')]);
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /immutable block count/);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.invalidations, []); assert.deepEqual(previous.previous.get(row.block_hash), []);
});

test('an unknown reference with an explicit hash cannot contradict an acknowledged zero', async () => {
  const f = fixture(), previous = f.warm(), row = { ...rowAt(f.current.blocks[2]), status: 'spent', spending_txid: hash(900) };
  previous.previousWindow.blockCounts = { [row.block_hash]: 0 };
  f.pages.push([{ ...eventAt(row, 1, f.current.tip, 'spent'), block_hash: row.block_hash }]);
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /immutable block count/);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.invalidations, []);
});

for (const resolvedBy of ['cache', 'root']) test(`an unknown reference cannot hide a retained window exit resolved by ${resolvedBy}`, async () => {
  const f = fixture(), row = rowAt(f.current.blocks[2]); f.rows.set(row.block_hash, [row]); const previous = f.warm();
  const unknown = { ...row, txid: hash(100002), status: 'spent', spending_txid: hash(900) };
  f.pages.push([eventAt(unknown, 1, f.current.tip, 'spent'), { ...eventAt(row, 2, f.current.tip, 'window_exit'),
    bounty: null, ...(resolvedBy === 'root' ? { block_hash: row.block_hash } : {}) }]);
  const reset = new Error('Expected rescan gate');
  await assert.rejects(discoverBounties({ ...f.options, ...previous, onReset: () => { throw reset; } }), error => error === reset);
  assert.equal(f.calls.length, 1); assert.equal(previous.cursor, '0'); assert.deepEqual(f.invalidations, []);
});

test('an unknown reference cannot hide a full added row assigning a known hash to another height', async () => {
  const f = fixture(), previous = f.warm(), row = rowAt(f.current.blocks[2]);
  const unknown = { ...row, txid: hash(100002), status: 'spent', spending_txid: hash(900) };
  const contradictory = { ...row, block_height: 699, confirmations: 2 };
  f.pages.push([eventAt(unknown, 1, f.current.tip, 'spent'), eventAt(contradictory, 2, f.current.tip, 'added')]);
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Invalid bounty metadata/);
  assert.equal(f.calls.length, 1); assert.deepEqual(f.invalidations, []);
});
