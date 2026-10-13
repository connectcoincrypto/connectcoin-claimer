import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties, bountyKey } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const canonicalHash = height => height === 0 ? GENESIS.main : hash(height + 1000);
function makeWindow(height = 700, depth = 0, branch = 1) {
  const blocks = Array.from({ length: Math.min(600, height + 1) }, (_, index) => ({
    height: height - index,
    hash: index < depth ? hash(1000000 * branch + height - index) : canonicalHash(height - index),
  }));
  return { window: 600, blocks, tip: { hash: blocks[0].hash, height, mediantime: 1700000000 + height,
    chain: 'main', genesis_hash: GENESIS.main } };
}
function bounty(block, id = 1, status = 'available') {
  return { txid: hash(9000000 + id), vout: 0, block_hash: block.hash, block_height: block.height,
    amount: '10000000000', domain: 'example.com', connection_work_target: 'f'.repeat(64),
    root_certificates_version: 1, signature_algorithms_mask: 7, status };
}

function fixture(initial = makeWindow()) {
  let current = structuredClone(initial), hook, readHook, sequence = 0;
  const calls = [], reads = [], published = [], invalidated = [], resets = [], rows = new Map();
  const counts = new Map();
  const rpc = { async request(method, params = {}) {
    calls.push({ method, params: structuredClone(params) });
    const count = (counts.get(method) ?? 0) + 1; counts.set(method, count);
    let result = await hook?.(method, params, count);
    if (result === undefined) {
      if (method === 'getrecentblockhashes') result = { ...current, blocks: current.blocks.slice(0, params.count ?? 600) };
      else if (method === 'getchaintip') result = current.tip;
      else {
        assert.equal(method, 'getbountychanges');
        result = { tip: current.tip, next_cursor: `cursor-${++sequence}`, has_more: false, changes: [] };
      }
    }
    return structuredClone(result);
  } };
  const options = { rpc, network: 'main',
    onInvalidate: (item, reason) => invalidated.push({ key: bountyKey(item), reason }),
    onWindow: value => published.push(structuredClone(value)),
    onReset: details => resets.push(details),
    readBlock: async (block, details) => {
      reads.push(block); await readHook?.(block, details);
      const result = structuredClone(rows.get(block) ?? []);
      details.budget.count += result.length;
      return result;
    },
  };
  return { options, calls, reads, published, invalidated, resets, rows,
    counts: () => calls.filter(call => call.method === 'getrecentblockhashes').map(call => call.params.count ?? 600),
    warm: () => ({ previousWindow: structuredClone(current), cursor: 'previous-cursor',
      previous: new Map(current.blocks.map(block => [block.hash, structuredClone(rows.get(block.hash) ?? [])])) }),
    get current() { return current; }, set current(value) { current = structuredClone(value); },
    set hook(value) { hook = value; }, set readHook(value) { readHook = value; },
  };
}

function assertComplete(result, expected) {
  assert.deepEqual(result.window, expected, 'The published window must be the whole canonical window, never just the prefix.');
  assert.equal(result.blocks.size, expected.blocks.length);
  assert.deepEqual(new Set(result.blocks.keys()), new Set(expected.blocks.map(block => block.hash)));
  assert.equal(Object.isFrozen(result.window), true);
  assert.equal(Object.isFrozen(result.window.blocks), true);
  assert.ok(result.window.blocks.every(Object.isFrozen));
}

test('a new tip downloads five hashes and stitches the full cached tail', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(701);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts(), [5]);
  assertComplete(result, f.current);
  assert.deepEqual(f.reads, [f.current.tip.hash]);
  assert.equal(f.calls.at(-1).method, 'getchaintip');
});

for (const [depth, expected] of [[3, [5]], [4, [5]], [5, [5, 100]], [99, [5, 100]], [100, [5, 100, 600]], [450, [5, 100, 600]]]) {
  test(`a ${depth}-block reorganization uses ${expected.join(' then ')} hashes`, async () => {
    const f = fixture(), old = bounty(f.current.blocks[0]); f.rows.set(old.block_hash, [old]);
    const previous = f.warm(); f.current = makeWindow(700, depth);
    const fresh = bounty(f.current.blocks[0], 2); f.rows.set(fresh.block_hash, [fresh]);
    const result = await discoverBounties({ ...f.options, ...previous });
    assert.deepEqual(f.counts(), expected);
    assertComplete(result, f.current);
    assert.equal(f.reads.length, depth, 'Only replaced blocks need new bounty streams.');
    assert.equal(result.blocks.has(old.block_hash), false);
    assert.equal(result.blocks.get(fresh.block_hash)[0].txid, fresh.txid);
    assert.ok(f.invalidated.some(item => item.key === bountyKey(old) && item.reason === 'reorg'));
    assert.equal(previous.previous.get(old.block_hash)[0].status, 'available');
  });
}

test('a chain without any known anchor escalates to a complete 600-hash snapshot', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(1400);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts(), [5, 100, 600]);
  assertComplete(result, f.current);
  assert.equal(f.reads.length, 600);
});

test('a rollback with a known anchor but missing old tail still fetches all 600', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(699);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts(), [5, 100, 600]);
  assertComplete(result, f.current);
  assert.deepEqual(f.reads, [canonicalHash(100)], 'The unavailable oldest hash must not be invented or omitted.');
});

test('a rollback before a 600-block history exists can reuse the cached genesis tail', async () => {
  const f = fixture(makeWindow(20)), previous = f.warm(); f.current = makeWindow(19);
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts(), [5]);
  assertComplete(result, f.current);
  assert.equal(f.reads.length, 0);
});

for (const height of [0, 1, 3, 4, 5]) {
  test(`count=5 accepts the exact genesis-bounded length at height ${height}`, async () => {
    const f = fixture(makeWindow(Math.max(0, height - 1))), previous = f.warm();
    // At genesis, a journal reset forces revalidation even with an unchanged tip.
    f.current = makeWindow(height);
    if (height === 0) f.hook = (method, params, count) => {
      if (method === 'getbountychanges' && count === 1) throw Object.assign(new Error('expired cursor'), { code: -32011 });
    };
    const result = await discoverBounties({ ...f.options, ...previous });
    assert.deepEqual(f.counts(), [5]);
    assertComplete(result, f.current);
    assert.equal(result.window.blocks.at(-1).hash, GENESIS.main);
  });
}

test('cold discovery requests the full window rather than probing with no known hashes', async () => {
  const f = fixture(); const result = await discoverBounties(f.options);
  assert.deepEqual(f.counts(), [600]);
  assertComplete(result, f.current);
  assert.equal(f.reads.length, 600);
});

test('a legacy server rejecting count falls back to the validated full response', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(701);
  f.hook = (method, params) => {
    if (method === 'getrecentblockhashes' && Object.hasOwn(params, 'count')) {
      throw Object.assign(new Error('Invalid params'), { code: -32602 });
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts(), [5, 600]);
  assertComplete(result, f.current);
});

test('a legacy server ignoring count may return a complete, validated 600-hash response', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(701);
  f.hook = method => method === 'getrecentblockhashes' ? f.current : undefined;
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts(), [5]);
  assertComplete(result, f.current);
});

test('transport failures on a prefix are not mistaken for unsupported count', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(701);
  f.hook = method => {
    if (method === 'getrecentblockhashes') throw Object.assign(new Error('disconnected'), { code: 'RPC_UNAVAILABLE' });
  };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /disconnected/);
  assert.deepEqual(f.counts(), [5]);
  assert.equal(f.published.length, 0);
});

for (const [name, mutate] of [
  ['truncated prefix', value => value.blocks.pop()],
  ['unexpected six-block prefix', value => value.blocks.push({ height: value.tip.height - 5, hash: canonicalHash(value.tip.height - 5) })],
  ['wrong height', value => { value.blocks[2].height--; }],
  ['duplicate hash', value => { value.blocks[2].hash = value.blocks[3].hash; }],
  ['noncanonical hash', value => { value.blocks[2].hash = 'z'.repeat(64); }],
  ['tip mismatch', value => { value.blocks[0].hash = hash(123456); }],
  ['wrong protocol window', value => { value.window = 5; }],
  ['wrong network', value => { value.tip.genesis_hash = hash(123456); }],
]) {
  test(`a malformed adaptive response fails closed: ${name}`, async () => {
    const f = fixture(), previous = f.warm(); f.current = makeWindow(701);
    f.hook = method => {
      if (method !== 'getrecentblockhashes') return;
      const value = structuredClone({ ...f.current, blocks: f.current.blocks.slice(0, 5) }); mutate(value); return value;
    };
    await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|unexpected|window|sequence|metadata/i);
    assert.deepEqual(f.counts(), [5], 'Malformed data must not be papered over by a larger query.');
    assert.equal(f.published.length, 0);
    assert.equal(f.reads.length, 0);
  });
}

test('a known hash claimed at another height is rejected instead of used as an anchor', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(701);
  f.hook = method => {
    if (method !== 'getrecentblockhashes') return;
    const value = structuredClone({ ...f.current, blocks: f.current.blocks.slice(0, 5) });
    value.blocks[1].hash = canonicalHash(650);
    return value;
  };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|inconsistent|conflict|height|ancestr/i);
  assert.equal(f.published.length, 0);
});

test('a prefix contradicting the ancestors of a known hash is rejected', async () => {
  const f = fixture(), previous = f.warm(); f.current = makeWindow(701);
  f.hook = method => {
    if (method !== 'getrecentblockhashes') return;
    const value = structuredClone({ ...f.current, blocks: f.current.blocks.slice(0, 5) });
    value.blocks[3].hash = hash(456789);
    return value;
  };
  await assert.rejects(discoverBounties({ ...f.options, ...previous }), /invalid|inconsistent|conflict|ancestr/i);
  assert.equal(f.published.length, 0);
});

test('a tip change between the five and hundred responses never mixes their branches', async () => {
  const f = fixture(), previous = f.warm(), first = makeWindow(700, 10, 1), second = makeWindow(700, 2, 2);
  f.current = first;
  f.hook = (method, params, count) => {
    if (method === 'getrecentblockhashes' && count === 2) f.current = second;
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts().slice(0, 2), [5, 100]);
  assertComplete(result, second);
  for (const block of first.blocks.slice(0, 10)) assert.equal(result.blocks.has(block.hash), false);
  assert.equal(f.published.some(window => window.blocks.some(block => first.blocks.slice(0, 10).some(old => old.hash === block.hash))), false);
});

test('a journal reset retains hash anchors but re-reads every bounty stream after an ABA tip', async () => {
  const f = fixture(), item = bounty(f.current.blocks[10]); f.rows.set(item.block_hash, [item]);
  const previous = f.warm(); let resetSent = false;
  f.rows.set(item.block_hash, [{ ...item, status: 'spent' }]);
  f.hook = (method, params, count) => {
    if (method === 'getbountychanges' && !resetSent) {
      resetSent = true;
      return { tip: makeWindow(700, 3).tip, next_cursor: 'reset-between-branches', has_more: false,
        changes: [{ type: 'resync_required' }] };
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assertComplete(result, f.current);
  assert.ok(f.counts().every(count => count === 5));
  assert.ok(f.counts().length >= 1, 'An unchanged tip after a journal reset still requires a fresh hash query.');
  assert.equal(f.resets.length, 1);
  assert.equal(f.reads.length, 600, 'Hash reuse must never become bounty-state reuse after reset.');
  assert.equal(new Set(f.reads).size, 600);
  assert.equal(result.blocks.get(item.block_hash)[0].status, 'spent');
  assert.equal(previous.previous.get(item.block_hash)[0].status, 'available');
  assert.ok(f.calls.filter(call => call.method === 'getbountychanges').some(call => !Object.hasOwn(call.params, 'cursor')));
});

test('spent changes during adaptive reorganization reads are replayed before publication', async () => {
  const f = fixture(), item = bounty(f.current.blocks[20]); f.rows.set(item.block_hash, [item]);
  const previous = f.warm(); f.current = makeWindow(700, 3);
  let changed = false, replayed = false;
  f.readHook = block => {
    if (block === f.current.tip.hash) {
      changed = true; f.rows.set(item.block_hash, [{ ...item, status: 'spent' }]);
    }
  };
  f.hook = method => {
    if (method === 'getbountychanges' && changed && !replayed) {
      replayed = true;
      return { tip: f.current.tip, next_cursor: 'spent-during-reorg', has_more: false,
        changes: [{ type: 'spent', sequence: 1, txid: item.txid, vout: item.vout, block_hash: item.block_hash }] };
    }
  };
  const result = await discoverBounties({ ...f.options, ...previous });
  assert.deepEqual(f.counts(), [5]);
  assertComplete(result, f.current);
  assert.equal(replayed, true);
  assert.equal(result.blocks.get(item.block_hash)[0].status, 'spent');
  assert.ok(f.invalidated.some(entry => entry.key === bountyKey(item) && entry.reason === 'spent'));
  assert.equal(previous.previous.get(item.block_hash)[0].status, 'available');
});
