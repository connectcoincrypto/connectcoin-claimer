import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverBounties, BountyDiscoveryBusy } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const tip = { height: 2, hash: hash(102), mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };
const blocks = [{ height: 2, hash: tip.hash }, { height: 1, hash: hash(101) }, { height: 0, hash: GENESIS.main }];
const window = { tip, blocks, window: 600 };
const bounty = { txid: hash(500), vout: 0, block_hash: hash(101), block_height: 1,
  amount: '100000000', domain: 'example.com', connection_work_target: 'f'.repeat(64),
  root_certificates_version: 1, signature_algorithms_mask: 7, coinbase: false,
  confirmations: 2, status: 'available', spending_txid: null };
const change = sequence => ({ type: 'available_again', sequence, txid: bounty.txid, vout: 0, block_hash: bounty.block_hash });
const page = (sequence, changes = [], has_more = false) => ({ tip, changes, has_more, next_cursor: String(sequence) });

function fixture() {
  const resets = [], reads = [], calls = [];
  let handler = () => undefined, readHandler;
  const previous = new Map(blocks.map(block => [block.hash, block.hash === bounty.block_hash ? [{ ...bounty }] : []]));
  const rpc = { async request(method, params = {}) {
    calls.push({ method, ...params });
    const response = await handler(method, params);
    if (response !== undefined) return response;
    if (method === 'getrecentblockhashes') return window;
    if (method === 'getchaintip') return tip;
    assert.fail('Unexpected journal request');
  } };
  const options = { rpc, network: 'main', previous, previousWindow: window, cursor: '0',
    onReset: details => resets.push(details),
    readBlock: async hash => {
      reads.push(hash);
      return await readHandler?.(hash) ?? (hash === bounty.block_hash ? [{ ...bounty }] : []);
    },
  };
  return { options, resets, reads, calls, previous,
    set handler(value) { handler = value; }, set readHandler(value) { readHandler = value; } };
}

test('the complete default 10,000-event journal plus its final replay is accepted atomically', async () => {
  const f = fixture();
  f.handler = (method, params) => {
    if (method !== 'getbountychanges') return;
    const from = Number(params.cursor), to = Math.min(10000, from + 100);
    return page(to, Array.from({ length: to - from }, (_, i) => change(from + i + 1)), to < 10000);
  };
  const result = await discoverBounties(f.options);
  assert.equal(result.cursor, '10000');
  assert.equal(f.calls.filter(call => call.method === 'getbountychanges').length, 101);
  assert.deepEqual(f.reads, [bounty.block_hash]);
  assert.deepEqual(f.resets, []);
  assert.equal(result.blocks.get(bounty.block_hash)[0].status, 'available');
  assert.equal(f.options.cursor, '0', 'The caller cursor is never advanced page by page.');
});

test('a valid backlog beyond the work budget uses a new watermark and complete snapshot', async () => {
  const f = fixture();
  let fresh = false, spent = false, afterStream = false, sequence = 20000;
  f.handler = (method, params) => {
    if (method !== 'getbountychanges') return;
    if (params.cursor === undefined) {
      assert.equal(f.resets.at(-1).reason, 'work-budget', 'Close admission before acquiring the replacement watermark.');
      fresh = true; return page(sequence);
    }
    if (!fresh) {
      const from = Number(params.cursor), to = from + 100;
      return page(to, Array.from({ length: 100 }, (_, i) => change(from + i + 1)), true);
    }
    if (afterStream && !spent) {
      spent = true; sequence++;
      return page(sequence, [{ ...change(sequence), type: 'pending_spend', spending_txid: hash(501) }]);
    }
    return page(sequence);
  };
  f.readHandler = blockHash => {
    if (blockHash !== bounty.block_hash) return [];
    afterStream = true;
    return [{ ...bounty, status: spent ? 'pending_spend' : 'available', spending_txid: spent ? hash(501) : null }];
  };
  const result = await discoverBounties(f.options);
  assert.equal(fresh, true);
  assert.deepEqual(f.resets, [{ reason: 'work-budget' }]);
  assert.ok(blocks.every(block => f.reads.includes(block.hash)), 'Every block must be reread after resetting the watermark.');
  assert.equal(result.blocks.get(bounty.block_hash)[0].status, 'pending_spend', 'Changes DURING snapshot transfer cannot vanish.');
  assert.equal(result.cursor, '20001');
  assert.equal(f.previous.get(bounty.block_hash)[0].status, 'available', 'No partially staged row changes the published catalog.');
});

test('more than 32 coherent reload attempts causes a safe rescan, not a fatal error', async () => {
  const f = fixture();
  let sequence = 0, remaining = 33;
  f.handler = (method, params) => {
    if (method !== 'getbountychanges') return;
    if (params.cursor === undefined) return page(sequence);
    if (remaining-- > 0) return page(++sequence, [change(sequence)]);
    return page(sequence);
  };
  const result = await discoverBounties(f.options);
  assert.equal(result.cursor, '33');
  assert.deepEqual(f.resets, [{ reason: 'work-budget' }]);
  assert.ok(blocks.every(block => f.reads.includes(block.hash)));
});

for (const mode of ['pages', 'coherence', 'journal-reset']) test(`sustained ${mode} changes yield locally with admission closed and no partial publication`, async () => {
  const f = fixture();
  let sequence = 0;
  f.handler = (method, params) => {
    if (method !== 'getbountychanges') return;
    if (params.cursor === undefined) return page(sequence);
    if (mode === 'journal-reset') return page(++sequence, [{ type: 'resync_required' }]);
    return page(++sequence, [change(sequence)], mode === 'pages');
  };
  // Fresh snapshots also encounter the same churn, after the watermark call.
  if (mode === 'journal-reset') f.handler = method => method === 'getbountychanges' ? page(++sequence, [{ type: 'resync_required' }]) : undefined;
  await assert.rejects(discoverBounties(f.options), error => error instanceof BountyDiscoveryBusy && error.code === 'CLAIMS_SYNC_BUSY');
  assert.equal(f.resets.length, 4);
  assert.equal(f.options.cursor, '0');
  assert.equal(f.previous.get(bounty.block_hash)[0].status, 'available');
  assert.ok(f.calls.filter(call => call.method === 'getbountychanges').length <= 4 * 128, 'Discovery must back off under perpetual churn.');
});

for (const kind of ['sequence', 'cursor', 'empty-more', 'tip']) test(`malformed ${kind} after 100 valid pages remains fatal data, not a retryable budget`, async () => {
  const f = fixture();
  let calls = 0;
  f.handler = (method, params) => {
    if (method !== 'getbountychanges') return;
    const from = Number(params.cursor), to = from + 1;
    const response = page(to, [change(to)], true);
    if (++calls === 101) {
      if (kind === 'sequence') response.changes[0].sequence = from;
      if (kind === 'cursor') response.next_cursor = params.cursor;
      if (kind === 'empty-more') response.changes = [];
      if (kind === 'tip') response.tip = { ...tip, genesis_hash: hash(42) };
    }
    return response;
  };
  await assert.rejects(discoverBounties(f.options), error => !(error instanceof BountyDiscoveryBusy) && /invalid|unexpected|inconsistent/i.test(error.message));
  assert.equal(calls, 101);
  assert.deepEqual(f.resets, []);
});
