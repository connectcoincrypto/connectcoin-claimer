import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties, bountyKey } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const makeWindow = (height = 700, replacements = new Map()) => {
  const blocks = Array.from({ length: Math.min(height + 1, 600) }, (_, i) => ({
    height: height - i,
    hash: replacements.get(height - i) ?? (height === i ? GENESIS.main : hash(height - i + 1000)),
  }));
  return { window: 600, blocks, tip: { height, hash: blocks[0].hash, mediantime: 1700000000 + height,
    chain: 'main', genesis_hash: GENESIS.main } };
};
const row = (block, id = 1, status = 'available') => ({
  txid: hash(100000 + id), vout: 0, block_hash: block.hash, block_height: block.height,
  amount: '10000000000', domain: 'example.com', connection_work_target: 'f'.repeat(64),
  root_certificates_version: 1, signature_algorithms_mask: 7, status,
});
const event = (bounty, type, sequence) => ({ type, sequence, txid: bounty.txid, vout: bounty.vout,
  block_hash: bounty.block_hash });

function fixture(initial = makeWindow()) {
  const calls = [], reads = [], invalidated = [], resets = [], published = [];
  const rows = new Map();
  let current = structuredClone(initial), hook, readHook, bytes = 0, journal = 0;
  const counts = new Map();
  const rpc = { async request(method, params = {}) {
    const count = (counts.get(method) ?? 0) + 1;
    counts.set(method, count); calls.push({ method, params: structuredClone(params) });
    let response = hook ? await hook(method, count, params) : undefined;
    if (response === undefined) {
      if (method === 'getrecentblockhashes') response = { ...current, blocks: current.blocks.slice(0, params.count ?? 600) };
      else if (method === 'getchaintip') response = current.tip;
      else {
        assert.equal(method, 'getbountychanges', 'Discovery must use only its read-only RPC methods.');
        response = { tip: current.tip, next_cursor: `cursor-${++journal}`, has_more: false, changes: [] };
      }
    }
    bytes += Buffer.byteLength(JSON.stringify(response));
    return structuredClone(response);
  } };
  const options = {
    rpc, network: 'main', onInvalidate: (item, reason) => invalidated.push({ key: bountyKey(item), reason }),
    onReset: details => resets.push(details), onWindow: value => published.push(structuredClone(value)),
    readBlock: async (block, details) => {
      reads.push(block); await readHook?.(block, details);
      const result = structuredClone(rows.get(block) ?? []);
      details.budget.count += result.length;
      return result;
    },
  };
  return {
    options, calls, reads, rows, invalidated, resets, published,
    count: method => counts.get(method) ?? 0,
    get bytes() { return bytes; }, get current() { return current; },
    set current(value) { current = structuredClone(value); },
    set hook(value) { hook = value; }, set readHook(value) { readHook = value; },
    warm() { return { previousWindow: structuredClone(current), cursor: 'previous',
      previous: new Map(current.blocks.map(block => [block.hash, structuredClone(rows.get(block.hash) ?? [])])) }; },
  };
}

test('cold discovery downloads one complete window and closes with a post-stream journal fence', async t => {
  const f = fixture(), oldWindowBytes = Buffer.byteLength(JSON.stringify(f.current));
  const result = await discoverBounties(f.options);
  assert.equal(f.count('getrecentblockhashes'), 1);
  assert.equal(f.count('getchaintip'), 0);
  assert.equal(f.count('getbountychanges'), 2);
  assert.equal(f.reads.length, 600);
  assert.deepEqual(result.window, f.current);
  assert.equal(result.blocks.size, 600);
  assert.ok(f.bytes < 2 * oldWindowBytes * 0.55, 'One full window plus small fences should roughly halve cold metadata traffic.');
  assert.equal(f.calls[0].method, 'getbountychanges', 'The pre-transfer watermark remains mandatory.');
  assert.equal(f.calls.at(-1).method, 'getbountychanges');
  t.diagnostic(`Metadata bytes: full window=${oldWindowBytes}, old two-window baseline=${2 * oldWindowBytes}, cold optimized=${f.bytes}.`);
});

test('an unchanged validated window downloads no block list or block streams on the next cycle', async t => {
  const f = fixture(), previous = f.warm(), oldWindowBytes = Buffer.byteLength(JSON.stringify(f.current));
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 0);
  assert.equal(f.count('getchaintip'), 0);
  assert.equal(f.count('getbountychanges'), 1, 'One complete page is a coherent tip+cursor fence.');
  assert.equal(f.reads.length, 0);
  assert.deepEqual(result.window, f.current);
  assert.ok(f.bytes < oldWindowBytes * 0.02, 'Warm RPC metadata should be small compared with one 600-block list.');
  assert.equal(f.resets.length, 0);
  t.diagnostic(`Metadata bytes: old two-window baseline=${2 * oldWindowBytes}, warm optimized=${f.bytes}.`);
});

test('the returned full window remains usable when the selected lookback grows', async () => {
  const f = fixture(), first = await discoverBounties({ ...f.options, lookback: 10 });
  assert.equal(first.blocks.size, 10);
  assert.equal(first.window.blocks.length, 600);
  const second = await discoverBounties({ ...f.options, previous: first.blocks, previousWindow: first.window,
    cursor: first.cursor, lookback: 20 });
  assert.equal(f.count('getrecentblockhashes'), 1, 'Changing local lookback must not require another full hash transfer.');
  assert.equal(f.reads.length, 20);
  assert.equal(second.blocks.size, 20);
});

test('a new block refreshes the complete window using five hashes and preserves unmodified cached blocks', async () => {
  const f = fixture(), previous = f.warm();
  f.current = makeWindow(701);
  const fresh = row(f.current.blocks[0]); f.rows.set(fresh.block_hash, [fresh]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 1);
  assert.deepEqual(f.calls.find(call => call.method === 'getrecentblockhashes').params, { count: 5, include_bounty_counts: true });
  assert.deepEqual(f.reads, [fresh.block_hash]);
  assert.equal(result.blocks.size, 600);
  assert.equal(result.blocks.has(previous.previousWindow.blocks.at(-1).hash), false);
  assert.equal(result.blocks.get(fresh.block_hash)[0].txid, fresh.txid);
  assert.deepEqual(result.tip, f.current.tip);
});

test('an adaptive response cannot contradict metadata of the journal tip that triggered it', async () => {
  const f = fixture(), previous = f.warm();
  f.current = makeWindow(701);
  f.hook = (method, count, params) => method === 'getrecentblockhashes'
    ? { ...f.current, blocks: f.current.blocks.slice(0, params.count ?? 600),
      tip: { ...f.current.tip, mediantime: f.current.tip.mediantime + 1 } } : undefined;
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /inconsistent metadata/i);
  assert.equal(f.published.length, 0);
  assert.equal(f.reads.length, 0);
});

test('an adaptive prefix reaching height zero must contain the expected genesis hash', async () => {
  const f = fixture(makeWindow(2)), previous = f.warm();
  f.current = makeWindow(3);
  f.hook = method => {
    if (method !== 'getrecentblockhashes') return;
    const value = structuredClone(f.current); value.blocks.at(-1).hash = hash(5555); return value;
  };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Invalid recent-block sequence/);
  assert.equal(f.published.length, 0);
});

test('same-height reorganization invalidates replaced rows instead of reusing the old hashes', async () => {
  const f = fixture(), old = row(f.current.blocks[0]); f.rows.set(old.block_hash, [old]);
  const previous = f.warm();
  f.current = makeWindow(700, new Map([[700, hash(999900)]]));
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 1);
  assert.deepEqual(f.reads, [f.current.tip.hash]);
  assert.equal(result.blocks.has(old.block_hash), false);
  assert.deepEqual(f.invalidated, [{ key: bountyKey(old), reason: 'reorg' }]);
});

test('matching height and hash with contradictory median time fails closed', async () => {
  const f = fixture(), previous = f.warm();
  f.current = { ...f.current, tip: { ...f.current.tip, mediantime: f.current.tip.mediantime + 1 } };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /inconsistent metadata/i);
});

for (const reorg of [false, true]) test(`a ${reorg ? 'reorg' : 'new block'} during block reads is detected by the replay fence`, async () => {
  const f = fixture(), previous = f.warm();
  previous.previous.delete(f.current.blocks[2].hash);
  f.hook = (method, count) => {
    if (method === 'getbountychanges' && count === 2) {
      f.current = reorg ? makeWindow(700, new Map([[700, hash(888800)]])) : makeWindow(701);
      const added = row(f.current.blocks[0]); f.rows.set(added.block_hash, [added]);
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 1);
  assert.equal(f.count('getchaintip'), 0, 'The final complete page supplies its own atomic tip.');
  assert.ok(f.count('getbountychanges') >= 3, 'Replay must continue after the replacement window is loaded.');
  assert.deepEqual(result.tip, f.current.tip);
  assert.equal(result.blocks.get(result.tip.hash).length, 1);
});

test('a spent change arriving while a newly detected block is read is replayed before publication', async () => {
  const f = fixture(), bounty = row(f.current.blocks[1]); f.rows.set(bounty.block_hash, [bounty]);
  const previous = f.warm(); let changed = false, emitted = false;
  f.current = makeWindow(701);
  f.hook = (method, count) => {
    if (method === 'getbountychanges' && changed && !emitted) {
      emitted = true;
      return { tip: f.current.tip, next_cursor: 'spent-change', has_more: false,
        changes: [event(bounty, 'spent', 1)] };
    }
  };
  f.readHook = block => {
    if (block === makeWindow(701).tip.hash) {
      changed = true; f.rows.set(bounty.block_hash, [{ ...bounty, status: 'spent' }]);
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(emitted, true);
  assert.equal(result.blocks.get(bounty.block_hash)[0].status, 'spent');
  assert.ok(f.invalidated.some(item => item.key === bountyKey(bounty) && item.reason === 'spent'));
  assert.equal(previous.previous.get(bounty.block_hash)[0].status, 'available', 'The old published map remains untouched.');
});

test('cached-window discovery drains all journal pages and refreshes mempool and spent rows', async () => {
  const f = fixture(), a = row(f.current.blocks[2], 1), b = row(f.current.blocks[3], 2);
  f.rows.set(a.block_hash, [a]); f.rows.set(b.block_hash, [b]);
  const previous = f.warm();
  const pages = [
    { next_cursor: 'page-1', has_more: true, changes: [event(a, 'pending_spend', 11)] },
    { next_cursor: 'page-2', has_more: true, changes: [event(b, 'spent', 12)] },
    { next_cursor: 'page-3', has_more: false, changes: [event(a, 'available_again', 13)] },
  ];
  f.rows.set(b.block_hash, [{ ...b, status: 'spent' }]);
  f.hook = (method, count) => method === 'getbountychanges' && count <= pages.length
    ? { tip: f.current.tip, ...pages[count - 1] } : undefined;
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 0);
  assert.equal(f.count('getbountychanges'), 4);
  assert.deepEqual(new Set(f.reads), new Set([a.block_hash, b.block_hash]));
  assert.equal(result.blocks.get(a.block_hash)[0].status, 'available');
  assert.equal(result.blocks.get(b.block_hash)[0].status, 'spent');
  assert.ok(f.invalidated.some(item => item.key === bountyKey(a) && item.reason === 'pending_spend'));
  assert.ok(f.invalidated.some(item => item.key === bountyKey(b) && item.reason === 'spent'));
  assert.deepEqual(f.calls.filter(call => call.method === 'getbountychanges').slice(0, 4).map(call => call.params.cursor),
    ['previous', 'page-1', 'page-2', 'page-3']);
});

for (const code of [-32004, -32011, 'resync_required']) test(`journal reset ${code} discards the window shortcut and obtains a complete snapshot`, async () => {
  const f = fixture(), previous = f.warm();
  f.hook = (method, count) => {
    if (method === 'getbountychanges' && count === 1) {
      if (typeof code === 'number') throw Object.assign(new Error('reset'), { code });
      return { tip: f.current.tip, next_cursor: 'reset', has_more: false, changes: [{ type: code }] };
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 1);
  assert.equal(f.reads.length, 600);
  assert.equal(f.resets.length, 1);
  assert.deepEqual(result.window, f.current);
});

for (const method of ['getbountychanges', 'getrecentblockhashes', 'journal-replay']) test(`a malformed ${method} tip still fails closed`, async () => {
  const f = fixture();
  f.hook = (name, count) => {
    if (method === 'journal-replay' ? name !== 'getbountychanges' || count !== 2 : name !== method) return;
    const tip = { ...f.current.tip, genesis_hash: hash(123) };
    if (name === 'getrecentblockhashes') return { ...f.current, tip };
    if (name === 'getbountychanges') return { tip, next_cursor: 'malformed', has_more: false, changes: [] };
    return tip;
  };
  await assert.rejects(discoverBounties(f.options), /invalid|unexpected/i);
});

for (const mutate of [
  value => value.blocks.pop(),
  value => { value.blocks[10].height--; },
  value => { value.blocks[10].hash = value.blocks[11].hash; },
  value => { value.blocks[0].hash = hash(12); },
  value => { value.window = 599; },
]) test(`malformed full window is never published (${mutate.toString()})`, async () => {
  const f = fixture(), malformed = structuredClone(f.current); mutate(malformed);
  f.hook = method => method === 'getrecentblockhashes' ? malformed : undefined;
  await assert.rejects(discoverBounties(f.options), /window|sequence/i);
});

for (const mutate of [
  value => value.blocks.pop(),
  value => { value.blocks[1].hash = value.blocks[2].hash; },
  value => { value.tip.chain = 'testnet'; },
]) test(`an invalid caller-supplied cached window is not silently trusted (${mutate.toString()})`, async () => {
  const f = fixture(), previous = f.warm(); mutate(previous.previousWindow);
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|unexpected|window|sequence/i);
});

for (const bad of [
  { changes: [event({ txid: hash(12), vout: 0, block_hash: hash(15) }, 'spent', -1)] },
  { changes: [], has_more: true },
  { changes: [], next_cursor: '' },
]) test(`window reuse retains journal validation (${JSON.stringify(bad)})`, async () => {
  const f = fixture(), previous = f.warm();
  f.hook = method => method === 'getbountychanges'
    ? { tip: f.current.tip, next_cursor: 'bad-page', has_more: false, changes: [], ...bad } : undefined;
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|excessive/i);
});

test('a missing cursor requires fresh hash anchoring and reloads the entire bounty catalog even when the tip is unchanged', async () => {
  const f = fixture(), previous = f.warm();
  const result = await discoverBounties({ ...f.options, ...previous, cursor: null });
  assert.equal(f.count('getrecentblockhashes'), 1);
  assert.equal(f.reads.length, 600);
  assert.deepEqual(f.resets, [{ reason: 'initial' }]);
  assert.deepEqual(result.window, f.current);
});

test('published hash-window metadata cannot be mutated by callers or through the previous cache', async () => {
  const f = fixture(), previous = f.warm();
  const result = await discoverBounties({ ...f.options, ...previous });
  const originalHash = result.window.blocks[1].hash;
  previous.previousWindow.blocks[1].hash = hash(123);
  previous.previousWindow.tip.mediantime++;
  assert.equal(result.window.blocks[1].hash, originalHash);
  assert.equal(result.window.tip.mediantime, f.current.tip.mediantime);
  assert.throws(() => { result.window.blocks[1].hash = hash(456); }, TypeError);
  assert.throws(() => { result.window.blocks.pop(); }, TypeError);
  assert.throws(() => { result.window.tip.height++; }, TypeError);
});

test('a new block during paginated replay still obtains its bounty snapshot before publishing', async () => {
  const f = fixture(), previous = f.warm(), next = makeWindow(701), bounty = row(next.blocks[0]);
  f.rows.set(bounty.block_hash, [bounty]);
  f.hook = (method, count) => {
    if (method !== 'getbountychanges') return;
    if (count === 1) return { tip: f.current.tip, next_cursor: 'before-block', has_more: true,
      changes: [event(row(f.current.blocks[1], 7), 'available_again', 1)] };
    if (count === 2) {
      f.current = next;
      return { tip: next.tip, next_cursor: 'new-block', has_more: false, changes: [event(bounty, 'added', 2)] };
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 1);
  assert.equal(result.blocks.get(bounty.block_hash)[0].txid, bounty.txid);
  assert.deepEqual(result.tip, next.tip);
  assert.ok(f.reads.includes(bounty.block_hash));
});

test('failure after consuming a journal page preserves the caller cursor, window and published rows for replay', async () => {
  const f = fixture(), bounty = row(f.current.blocks[1]); f.rows.set(bounty.block_hash, [bounty]);
  const previous = f.warm(), beforeWindow = structuredClone(previous.previousWindow), originalRows = previous.previous.get(bounty.block_hash);
  f.hook = (method, count, params) => {
    if (method === 'getbountychanges' && params.cursor === 'previous') return { tip: f.current.tip, next_cursor: 'advanced',
      has_more: false, changes: [event(bounty, 'spent', 1)] };
  };
  f.readHook = () => { throw new Error('Incomplete bounty snapshot.'); };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /Incomplete bounty snapshot/);
  assert.equal(previous.cursor, 'previous');
  assert.deepEqual(previous.previousWindow, beforeWindow);
  assert.strictEqual(previous.previous.get(bounty.block_hash), originalRows);
  assert.equal(originalRows[0].status, 'available');
  f.readHook = undefined;
  f.rows.set(bounty.block_hash, [{ ...bounty, status: 'spent' }]);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(result.blocks.get(bounty.block_hash)[0].status, 'spent');
  assert.equal(f.calls.filter(call => call.method === 'getbountychanges' && call.params.cursor === 'previous').length, 2,
    'A failed unpublished cycle must replay again from the old cursor.');
});

test('a rollback to a lower chain height rejects displaced-tip rows as reorgs', async () => {
  const f = fixture(), bounty = row(f.current.blocks[0]); f.rows.set(bounty.block_hash, [bounty]);
  const previous = f.warm(); f.current = makeWindow(699);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.equal(f.count('getrecentblockhashes'), 3);
  assert.deepEqual(f.calls.filter(call => call.method === 'getrecentblockhashes').map(call => call.params), [{ count: 5, include_bounty_counts: true }, { count: 100 }, {}]);
  assert.deepEqual(result.tip, f.current.tip);
  assert.equal(result.blocks.has(bounty.block_hash), false);
  assert.ok(f.invalidated.some(item => item.key === bountyKey(bounty) && item.reason === 'reorg'));
  assert.equal(result.blocks.size, 600);
});

for (const field of ['mediantime', 'height']) test(`contradictory ${field} for the same hash at the final fence is rejected`, async () => {
  const f = fixture(), previous = f.warm();
  previous.previous.delete(f.current.blocks[2].hash);
  f.hook = (method, count) => method === 'getbountychanges' && count === 2 ? {
    tip: { ...f.current.tip, [field]: f.current.tip[field] + 1 }, next_cursor: 'bad-fence', has_more: false, changes: [],
  } : undefined;
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /inconsistent metadata/i);
  assert.equal(previous.cursor, 'previous');
  assert.deepEqual(previous.previousWindow, f.current);
});

test('the published immutable snapshot owns its metadata independently of raw RPC response objects', async () => {
  const source = makeWindow(); let cursor = 0;
  const rpc = { async request(method) {
    if (method === 'getrecentblockhashes') return source;
    if (method === 'getchaintip') return source.tip;
    assert.equal(method, 'getbountychanges');
    return { tip: source.tip, next_cursor: `c${++cursor}`, has_more: false, changes: [] };
  } };
  const result = await discoverBounties({ rpc, network: 'main', readBlock: async () => [] });
  const expected = structuredClone(result.window);
  source.blocks[1].hash = hash(42); source.tip.mediantime++; source.blocks.pop(); source.window = 1;
  assert.deepEqual(result.window, expected);
  assert.equal(Object.isFrozen(result.window), true);
  assert.equal(Object.isFrozen(result.window.tip), true);
  assert.equal(Object.isFrozen(result.window.blocks), true);
  assert.ok(result.window.blocks.every(Object.isFrozen));
});
