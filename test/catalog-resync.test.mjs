import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ClaimerService } from '../src/service.mjs';
import { discoverBounties, bountyKey } from '../src/core/bounty-discovery.mjs';
import { GENESIS } from '../src/core/config.mjs';

const hash = value => value.toString(16).padStart(64, '0');
const tip = { height: 2, hash: hash(102), mediantime: 1700000000, chain: 'main', genesis_hash: GENESIS.main };
const blocks = [{ height: 2, hash: tip.hash }, { height: 1, hash: hash(101) }, { height: 0, hash: GENESIS.main }];
const window = { tip, blocks, window: 600 };
const row = (id = 1) => ({ txid: hash(id), vout: 0, block_hash: hash(101), block_height: 1,
  amount: '10000000000', domain: `d${id}.example.com`, connection_work_target: 'f'.repeat(64),
  root_certificates_version: 1, signature_algorithms_mask: 7, status: 'available' });
const claimId = bounty => hash(1000 + Number(BigInt(`0x${bounty.txid}`)));
const catalog = rows => ({ blocks: new Map([[hash(101), rows]]), cursor: 'current', tip });
const tick = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate) {
  const end = Date.now() + 3000;
  while (Date.now() < end) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 2)); }
  throw new Error('Catalog resync test did not settle');
}

for (const trigger of [-32004, -32011, 'resync_required']) test(`catalog reset ${trigger} stages a full snapshot and reports one safe reason`, async () => {
  const bounty = row(), previous = new Map([[hash(101), [bounty]]]), resets = [], reads = [], calls = [];
  let sequence = 0;
  const rpc = { async request(method, params = {}) {
    calls.push({ method, params });
    if (method === 'getrecentblockhashes') return window;
    assert.equal(method, 'getbountychanges');
    if (params.cursor === 'old') {
      if (typeof trigger === 'number') throw Object.assign(new Error('untrusted private server response'), { code: trigger });
      return { tip, next_cursor: 'reset-watermark', has_more: false, changes: [{ type: trigger }] };
    }
    return { tip, next_cursor: `new-${++sequence}`, has_more: false, changes: [] };
  } };
  const result = await discoverBounties({ rpc, network: 'main', previous, cursor: 'old',
    onReset: details => resets.push(details), readBlock: async block => { reads.push(block); return block === hash(101) ? [bounty] : []; } });
  assert.deepEqual(reads, [GENESIS.main, hash(101), hash(102)]);
  assert.equal(result.blocks.size, 3);
  assert.strictEqual(previous.get(hash(101))[0], bounty, 'Staging must not mutate the published catalog.');
  assert.equal(resets.length, 1, 'A reset is reported once, not again on the next loop.');
  assert.deepEqual(resets[0], trigger === -32004 ? { reason: 'data-unavailable', code: trigger }
    : trigger === -32011 ? { reason: 'cursor-invalid', code: trigger } : { reason: 'journal-reset' });
  assert.equal(calls.filter(call => call.method === 'getbountychanges' && !call.params.cursor).length, 1);
  assert.ok(sequence >= 2, 'The fresh watermark must be replayed after reading every block.');
});

test('a reset still replays changes during block transfer before publishing', async () => {
  const bounty = row(), invalidated = [], reads = [];
  let changes = 0, spent = false;
  const rpc = { async request(method, params = {}) {
    if (method === 'getrecentblockhashes') return window;
    if (params.cursor === 'old') throw Object.assign(new Error('expired'), { code: -32011 });
    const events = ++changes === 2 ? [{ type: 'spent', sequence: 1, txid: bounty.txid, vout: 0, block_hash: bounty.block_hash }] : [];
    if (events.length) spent = true;
    return { tip, next_cursor: `cursor-${changes}`, has_more: false, changes: events };
  } };
  const result = await discoverBounties({ rpc, network: 'main', previous: new Map([[bounty.block_hash, [bounty]]]), cursor: 'old',
    onInvalidate: item => invalidated.push(bountyKey(item)),
    readBlock: async block => { reads.push(block); return block === bounty.block_hash ? [{ ...bounty, status: spent ? 'spent' : 'available' }] : []; } });
  assert.equal(reads.filter(block => block === bounty.block_hash).length, 2);
  assert.equal(result.blocks.get(bounty.block_hash)[0].status, 'spent');
  assert.ok(invalidated.includes(bountyKey(bounty)));
});

test('reset does not turn malformed journal or incomplete block transfer into an accepted snapshot', async () => {
  let calls = 0;
  const rpc = { async request(method) {
    if (method === 'getrecentblockhashes') return window;
    return { tip, next_cursor: `cursor-${++calls}`, has_more: false,
      changes: calls > 1 ? [{ type: 'spent', sequence: -1, txid: hash(1), vout: 0 }] : [] };
  } };
  await assert.rejects(discoverBounties({ rpc, network: 'main', readBlock: async () => [] }), /Invalid bounty change event/);
  calls = 0;
  await assert.rejects(discoverBounties({ rpc, network: 'main', readBlock: async () => { throw new Error('Incomplete bounty snapshot.'); } }), /Incomplete bounty snapshot/);
});

async function fixture(t, initial = [row(1), row(2)]) {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-resync-test-'));
  const attempts = [], events = [], sent = [], releases = [];
  let poolStarts = 0, poolCloses = 0, discover;
  class Rpc extends EventEmitter {
    async connect() {}
    async request(method, params, options = {}) {
      if (method === 'gettransaction') return { tip, transaction: { hex: params.txid } };
      assert.equal(method, 'sendrawtransaction'); options.beforeSend?.(); sent.push(params.transaction_hex);
      return { txid: params.transaction_hex };
    }
    close() {}
  }
  const rpc = new Rpc();
  const service = new ClaimerService({
    config: { receivingAddress: 'ccpublicreceivingaddress', connectionsPerSecond: 600, concurrency: 4,
      minExpectedReturn: 0.01, rpc: { host: 'invalid.example', port: 48190 }, network: 'main', lookbackBlocks: 600, feeRate: 1500 },
    statePath: join(directory, 'state.json'), rpcFactory: () => rpc,
    discover: options => discover ? discover(options) : catalog(initial),
    transactionId: raw => raw,
    prepare: ({ bounty, fee }) => ({ bounty: { ...bounty, target: bounty.connection_work_target, rootVersion: 1, mask: 7 },
      txid: claimId(bounty), fee, payout: bounty.amount }),
    attach: prepared => ({ txid: prepared.txid, hex: prepared.txid }),
    poolFactory: () => ({ pacesStarts: true, async start() { poolStarts++; }, async close() { poolCloses++; }, async resolve() {},
      attempt(context, options) {
        return new Promise(resolve => {
          const attempt = { context, ...options, settled: false };
          const finish = extra => {
            if (attempt.settled) return;
            attempt.settled = true; options.signal.removeEventListener('abort', abort);
            const result = { started: true, captured: false, validationPassed: false, seconds: 0.01,
              proof: null, verified: false, cancelled: false, ...extra };
            if (!result.cancelled) options.onCapture(result);
            options.onResult(result); resolve(result);
          };
          const abort = () => finish({ cancelled: true, validationPassed: null });
          attempt.finish = finish; attempts.push(attempt);
          if (options.signal.aborted) abort(); else { options.signal.addEventListener('abort', abort, { once: true }); options.onStarted(); }
        });
      },
    }),
    setTimer: (callback, delay) => ({ callback, delay, unref() {} }), clearTimer() {},
    emit: (event, details) => events.push({ event, details }),
  });
  t.after(async () => { for (const release of releases) release.resolve(); await service.stop(); await rm(directory, { recursive: true, force: true }); });
  await service.start(); await until(() => attempts.length === 4);
  return { service, rpc, attempts, events, sent, initial,
    get poolStarts() { return poolStarts; }, get poolCloses() { return poolCloses; },
    beginResync({ rows = initial, snapshot = window, beforePublish = () => {} } = {}) {
      const entered = Promise.withResolvers(), release = Promise.withResolvers(); releases.push(release);
      discover = async options => {
        await options.onReset({ reason: 'cursor-invalid', code: -32011 }); options.onWindow(snapshot);
        entered.resolve(); await release.promise; options.check(); await beforePublish(options);
        return { ...catalog(rows), tip: snapshot.tip };
      };
      return { cycle: service.cycle(), entered: entered.promise, release: () => release.resolve() };
    },
  };
}

test('catalog barrier keeps helper/captures/accounting and sends a new verified proof only after atomic publication', async t => {
  const f = await fixture(t), { service } = f;
  const generation = service.engine.generation, helper = service.engine.pool, starts = service.metrics.connectionsStarted;
  const resync = f.beginResync(); await resync.entered;
  assert.equal(service.ready, false); assert.equal(service.status, 'resyncing');
  assert.equal(service.engine.paused, false); assert.equal(service.engine.pool, helper);
  assert.equal(service.engine.generation, generation); assert.equal(f.poolCloses, 0);
  assert.ok(f.attempts.every(attempt => !attempt.signal.aborted));
  const winner = f.attempts[0], key = winner.bountyId;
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => service.engine.pendingProofs.has(key)); await tick();
  assert.equal(f.sent.length, 0); assert.equal(service.metrics.valid, 1);
  assert.equal(service.engine.successCounts.get(key), 1n);
  assert.equal(service.engine.pendingProofs.get(key).proof, '020100');
  resync.release(); await resync.cycle;
  await until(() => f.sent.length === 1 && service.engine.snapshot().completed === 1);
  assert.equal(service.ready, true); assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
  assert.equal(service.engine.generation, generation); assert.ok(service.metrics.connectionsStarted >= starts);
});

test('new preparation waits for catalog publication without a retry loop or stale metadata', async t => {
  const f = await fixture(t), resync = f.beginResync(); await resync.entered;
  let settled = false;
  const preparing = f.service.prepare(f.initial[0]).then(result => { settled = true; return result; });
  await tick(); await tick(); assert.equal(settled, false);
  resync.release(); await resync.cycle;
  assert.equal((await preparing).txid, claimId(f.initial[0]));
});

test('a catalog reset fences a broadcast already queued for an RPC write and retains its exact proof', async t => {
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  t.after(() => release.resolve());
  const f = await fixture(t);
  const request = f.rpc.request.bind(f.rpc);
  f.rpc.request = async (method, params, options) => {
    if (method === 'sendrawtransaction') { entered.resolve(); await release.promise; }
    return request(method, params, options);
  };
  const winner = f.attempts[0];
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await entered.promise;
  const resync = f.beginResync(); await resync.entered;
  release.resolve();
  await until(() => f.service.engine.submitting.size === 0);
  assert.equal(f.sent.length, 0, 'The pre-write check must observe a reset that occurred inside the RPC queue.');
  const saved = f.service.journal.unresolved();
  assert.equal(saved.length, 1); assert.equal(saved[0].status, 'pending');
  assert.equal(saved[0].transactionHex, winner.context.txid);
  assert.equal(f.service.reserved.has(winner.bountyId), true);
  assert.equal(f.service.running, true); assert.equal(f.poolCloses, 0);
  resync.release(); await resync.cycle;
});

test('reorganization cancels only affected captures and never submits their proof', async t => {
  const affected = row(1), safe = { ...row(2), block_hash: GENESIS.main, block_height: 0 };
  const f = await fixture(t, [affected, safe]);
  const changed = { ...window, blocks: [{ height: 2, hash: tip.hash }, { height: 1, hash: hash(999) }, blocks[2]] };
  const resync = f.beginResync({ rows: [safe], snapshot: changed }); await resync.entered;
  const bad = f.attempts.find(attempt => attempt.bountyId === bountyKey(affected));
  const good = f.attempts.find(attempt => attempt.bountyId === bountyKey(safe));
  assert.ok(bad && good); assert.equal(bad.signal.aborted, true); assert.equal(good.signal.aborted, false);
  good.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => f.service.engine.pendingProofs.has(bountyKey(safe)));
  assert.equal(f.sent.length, 0);
  resync.release(); await resync.cycle; await until(() => f.sent.length === 1);
  assert.deepEqual(f.sent, [claimId(safe)]); assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
});

test('a bounty missing from the complete replacement snapshot loses its gated proof without broadcast', async t => {
  const f = await fixture(t), winner = f.attempts[0], key = winner.bountyId;
  const resync = f.beginResync({ rows: f.initial.filter(bounty => bountyKey(bounty) !== key) }); await resync.entered;
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => f.service.engine.pendingProofs.has(key));
  resync.release(); await resync.cycle; await tick();
  assert.equal(f.sent.length, 0); assert.equal(f.service.engine.pendingProofs.has(key), false);
  assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
});

test('normal window aging retains an already-running capture and its gated proof through publication', async t => {
  const f = await fixture(t), winner = f.attempts[0];
  const agedTip = { ...tip, height: 602, hash: hash(702) };
  const agedWindow = { tip: agedTip, window: 600,
    blocks: Array.from({ length: 600 }, (_, i) => ({ height: 602 - i, hash: hash(702 - i) })) };
  const resync = f.beginResync({ rows: [], snapshot: agedWindow }); await resync.entered;
  assert.equal(winner.signal.aborted, false);
  assert.equal(f.service.engine.queue.get(winner.bountyId).retired, true);
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => f.service.engine.pendingProofs.has(winner.bountyId));
  assert.equal(f.sent.length, 0);
  resync.release(); await resync.cycle; await until(() => f.sent.length === 1);
  assert.equal(f.sent[0], winner.context.txid);
  assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
});

test('stop wakes a proof waiting behind the catalog barrier without deadlocking or broadcasting', async t => {
  const f = await fixture(t), resync = f.beginResync(); await resync.entered;
  f.attempts[0].finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => f.service.engine.pendingProofs.size === 1);
  const stopping = f.service.stop(); resync.release();
  await Promise.all([stopping, resync.cycle]);
  assert.equal(f.sent.length, 0); assert.equal(f.service.snapshot().status, 'stopped');
  assert.equal(f.service.engine.tasks.size, 0); assert.equal(f.poolCloses, 1);
  assert.equal(f.service.journal.unresolved().length, 1, 'Explicit stop must preserve the verified winner durably.');
  assert.equal(f.service.journal.unresolved()[0].transactionHex, f.attempts[0].context.txid);
});

test('malformed replacement metadata fails closed without publishing or sending a gated proof', async t => {
  const f = await fixture(t), changed = f.initial.map(bounty => ({ ...bounty, amount: '9999999999' }));
  const resync = f.beginResync({ rows: changed }); await resync.entered;
  f.attempts[0].finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => f.service.engine.pendingProofs.size === 1);
  resync.release(); await resync.cycle;
  assert.equal(f.service.snapshot().status, 'failed'); assert.match(f.service.lastError, /metadata changed/);
  assert.equal(f.sent.length, 0); assert.equal(f.service.ready, false);
});
