import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ClaimerService } from '../src/service.mjs';
import { discoverBounties, bountyKey, BountyDiscoveryBusy } from '../src/core/bounty-discovery.mjs';
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
test('journal reset closes the catalog before a subsequent hash timeout can conceal it', async () => {
  const events = [], unavailable = Object.assign(new Error('Controlled hash timeout'), { code: 'RPC_UNAVAILABLE' });
  let pages = 0;
  const rpc = { async request(method) {
    events.push(method);
    if (method === 'getbountychanges') return { tip, next_cursor: `watermark-${++pages}`, has_more: false,
      changes: pages === 1 ? [{ type: 'resync_required' }] : [] };
    if (method === 'getrecentblockhashes') {
      assert.ok(events.includes('reset:journal-reset'), 'reset must precede even a blocked hash request');
      throw unavailable;
    }
    assert.fail(`Unexpected request ${method}`);
  } };
  await assert.rejects(discoverBounties({ rpc, network: 'main', previous: new Map([[hash(101), [row()]]]), cursor: 'old',
    onReset: details => events.push(`reset:${details.reason}`),
    onWindow: () => assert.fail('a failed rescan cannot publish a window'),
    readBlock: () => assert.fail('a failed rescan cannot publish rows'),
  }), error => error === unavailable);
  assert.deepEqual(events, ['getbountychanges', 'reset:journal-reset', 'getbountychanges', 'getrecentblockhashes']);
});

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
    if (method === 'getchaintip') return tip;
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
    if (method === 'getchaintip') return tip;
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
    if (method === 'getchaintip') return tip;
    return { tip, next_cursor: `cursor-${++calls}`, has_more: false,
      changes: calls > 1 ? [{ type: 'spent', sequence: -1, txid: hash(1), vout: 0 }] : [] };
  } };
  await assert.rejects(discoverBounties({ rpc, network: 'main', readBlock: async () => [] }), /Invalid bounty change event/);
  calls = 0;
  await assert.rejects(discoverBounties({ rpc, network: 'main', readBlock: async () => { throw new Error('Incomplete bounty snapshot.'); } }), /Incomplete bounty snapshot/);
});

async function fixture(t, initial = [row(1), row(2)]) {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-resync-test-'));
  const attempts = [], events = [], sent = [], releases = [], admissions = [];
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
      async setAdmissionAllowed(allowed) { admissions.push(allowed); },
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
  return { service, rpc, attempts, events, sent, initial, admissions,
    get poolStarts() { return poolStarts; }, get poolCloses() { return poolCloses; },
    refresh({ rows = initial, invalidated = [] } = {}) {
      discover = async options => {
        for (const [bounty, reason] of invalidated) options.onInvalidate(bounty, reason);
        options.check(); return catalog(rows);
      };
      return service.cycle();
    },
    beginResync({ rows = initial, snapshot = window, beforePublish = () => {} } = {}) {
      const entered = Promise.withResolvers(), release = Promise.withResolvers(); releases.push(release);
      discover = async options => {
        await options.onReset({ reason: 'cursor-invalid', code: -32011 }); options.onWindow(snapshot);
        entered.resolve(); await release.promise; options.check(); await beforePublish(options);
        return { ...catalog(rows), tip: snapshot.tip };
      };
      return { cycle: service.cycle(), entered: entered.promise, release: () => release.resolve() };
    },
    ageOut(snapshot) {
      discover = async options => {
        options.onWindow(snapshot);
        for (const rows of options.previous.values()) for (const bounty of rows) options.onInvalidate(bounty, 'window_exit');
        options.check();
        return { blocks: new Map(), cursor: 'aged', tip: snapshot.tip, window: snapshot };
      };
      return service.cycle();
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

test('catalog reset stops prepared capture replenishment until coherent publication while preserving its counters', async t => {
  const initial = [row(1), row(2)].map(bounty => ({ ...bounty, connection_work_target: '0' + 'f'.repeat(63) }));
  const f = await fixture(t, initial), { service } = f;
  const before = f.attempts.length, generation = service.engine.generation, helper = service.engine.pool;
  const resync = f.beginResync(); await resync.entered;
  assert.equal(service.engine.catalogBlocked, true); assert.equal(f.admissions.at(-1), false);
  for (const attempt of f.attempts.slice()) attempt.finish({ captured: true, validationPassed: true, proof: null, verified: false });
  await until(() => service.engine.connections.size === 0);
  for (let n = 0; n < 25; n++) await tick();
  assert.equal(f.attempts.length, before, 'A prepared target miss must not bypass the closed catalog gate');
  assert.equal(service.metrics.valid, before); assert.equal(service.metrics.connectionsStarted, before);
  assert.equal([...service.engine.successCounts.values()].reduce((sum, value) => sum + value, 0n), BigInt(before));
  assert.strictEqual(service.engine.pool, helper); assert.equal(service.engine.generation, generation);
  resync.release(); await resync.cycle; await until(() => f.attempts.length > before);
  assert.equal(service.engine.catalogBlocked, false); assert.equal(f.admissions.at(-1), true);
  assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
});

test('stopping a resync wakes catalog waiters without reopening native admission', async t => {
  const f = await fixture(t), resync = f.beginResync(); await resync.entered;
  const before = f.attempts.length; const stopping = f.service.stop();
  assert.equal(f.service.catalogGate, null); assert.equal(f.service.engine.catalogBlocked, true);
  assert.equal(f.admissions.at(-1), false);
  resync.release(); await Promise.all([stopping, resync.cycle]);
  assert.equal(f.attempts.length, before); assert.equal(f.sent.length, 0);
});

for (const code of [-32001, -32011, -32029, -32030, 'CLAIMS_SYNC_BUSY']) test(`transient resync read ${code} keeps captures and the exact proof until a coherent retry`, async t => {
  const f = await fixture(t), { service } = f;
  f.rpc.socket = { destroyed: false };
  const generation = service.engine.generation, helper = service.engine.pool;
  const resync = f.beginResync({ beforePublish() {
    throw code === 'CLAIMS_SYNC_BUSY' ? new BountyDiscoveryBusy() : Object.assign(new Error('Controlled read failure'), { code });
  } });
  await resync.entered;
  const winner = f.attempts[0], key = winner.bountyId;
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => service.engine.pendingProofs.has(key));
  const proof = service.engine.pendingProofs.get(key);
  resync.release(); await resync.cycle;
  assert.equal(service.status, 'resyncing'); assert.equal(service.ready, false); assert.ok(service.catalogGate);
  assert.strictEqual(service.engine.pool, helper); assert.equal(service.engine.generation, generation);
  assert.strictEqual(service.engine.pendingProofs.get(key), proof); assert.equal(service.metrics.valid, 1);
  assert.equal(service.engine.successCounts.get(key), 1n); assert.equal(f.poolCloses, 0); assert.equal(f.sent.length, 0);
  assert.equal(f.admissions.at(-1), false);
  const retry = f.beginResync(); await retry.entered; retry.release(); await retry.cycle;
  await until(() => f.sent.length === 1 && service.engine.snapshot().completed === 1);
  assert.equal(service.ready, true); assert.equal(service.engine.generation, generation);
  assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
  assert.equal(f.sent[0], winner.context.txid); assert.equal(f.admissions.at(-1), true);
});

for (const code of [-32001, 'CLAIMS_SYNC_BUSY']) for (const failure of ['disconnect', 'destroyed socket', 'fatal']) test(`resync ${code} ${failure} cannot use the transient-read preservation path`, async t => {
  const f = await fixture(t), { service } = f; f.rpc.socket = { destroyed: false };
  const generation = service.engine.generation;
  const resync = f.beginResync({ beforePublish() {
    if (failure === 'disconnect') { f.rpc.socket.destroyed = true; f.rpc.emit('disconnected'); }
    if (failure === 'destroyed socket') f.rpc.socket.destroyed = true;
    throw Object.assign(code === 'CLAIMS_SYNC_BUSY' ? new BountyDiscoveryBusy() : Object.assign(new Error('Controlled lifecycle failure'), { code }),
      failure === 'fatal' ? { helperFatal: true } : {});
  } });
  await resync.entered; resync.release(); await resync.cycle;
  assert.equal(service.ready, false); assert.equal(f.poolCloses, 1); assert.equal(service.engine.pool, null);
  assert.ok(service.engine.generation > generation); assert.ok(f.attempts.every(attempt => attempt.signal.aborted));
  assert.equal(f.admissions.at(-1), false); assert.equal(f.sent.length, 0);
  if (failure === 'fatal') { assert.equal(service.running, false); assert.equal(service.status, 'failed'); }
  else { assert.equal(service.running, true); assert.equal(service.status, 'reconnecting'); }
});

test('exhausted real discovery budgets retain the verified winner until a fresh coherent retry', async t => {
  const f = await fixture(t, [row(1)]), { service } = f;
  f.rpc.socket = { destroyed: false };
  const generation = service.engine.generation, helper = service.engine.pool;
  const winner = f.attempts[0], key = winner.bountyId;
  let sequence = 0, resets = 0, savedProof;
  const catalogRpc = { async request(method, params = {}) {
    if (method === 'getchaintip') return tip;
    if (method === 'getrecentblockhashes') return window;
    assert.equal(method, 'getbountychanges');
    // Every response is structurally valid. A new availability event races
    // each completed block read, exhausting coherence rather than validation.
    const changes = params.cursor ? [{ type: 'available_again', sequence: ++sequence,
      txid: f.initial[0].txid, vout: 0, block_hash: hash(101) }] : [];
    return { tip, next_cursor: `changing-${sequence}`, has_more: false, changes };
  } };
  service.discover = options => discoverBounties({ ...options, rpc: catalogRpc,
    readBlock: async block => block === hash(101) ? f.initial : [],
    onReset: async details => {
      assert.equal(details.reason, 'work-budget');
      await options.onReset(details);
      if (++resets === 1) {
        winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
        await until(() => service.engine.pendingProofs.has(key));
        savedProof = service.engine.pendingProofs.get(key);
      }
    },
  });
  await service.cycle();
  assert.equal(resets, 4); assert.equal(service.status, 'resyncing');
  assert.equal(service.running, true); assert.equal(service.ready, false);
  assert.ok(service.catalogGate); assert.equal(service.engine.catalogBlocked, true);
  assert.equal(service.cursor, null, 'A failed bounded rescan must not retry the old journal prefix again.');
  assert.strictEqual(service.engine.pendingProofs.get(key), savedProof);
  assert.strictEqual(service.engine.pool, helper); assert.equal(service.engine.generation, generation);
  assert.equal(service.metrics.valid, 1); assert.equal(service.engine.successCounts.get(key), 1n);
  assert.equal(f.sent.length, 0); assert.equal(f.poolCloses, 0);
  service.discover = async options => {
    assert.equal(options.cursor, null);
    await options.onReset({ reason: 'initial' });
    return catalog(f.initial);
  };
  await service.cycle();
  await until(() => service.engine.snapshot().completed === 1);
  assert.deepEqual(f.sent, [winner.context.txid]);
  assert.equal(service.metrics.valid, 1); assert.equal(service.engine.successCounts.get(key), 1n);
  assert.equal(service.engine.generation, generation); assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
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

test('ordinary catalog refresh preserves its own reserved submission waiting for RPC capacity', async t => {
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  t.after(() => release.resolve());
  const f = await fixture(t, [row(1)]), { service } = f;
  const request = f.rpc.request.bind(f.rpc);
  let signal;
  f.rpc.request = async (method, params, options) => {
    if (method === 'sendrawtransaction') { signal = options.signal; entered.resolve(); await release.promise; }
    return request(method, params, options);
  };
  const winner = f.attempts[0], key = winner.bountyId;
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await entered.promise;
  const job = service.engine.queue.get(key), proof = service.engine.pendingProofs.get(key);
  const attempts = service.engine.snapshot().attempts, starts = service.metrics.connectionsStarted;
  const generation = service.engine.generation;
  assert.equal(service.reserved.has(key), true); assert.equal(job.submitting, true);
  for (let i = 0; i < 3; i++) {
    await f.refresh();
    assert.equal(signal.aborted, false);
    assert.strictEqual(service.engine.queue.get(key), job);
    assert.strictEqual(service.engine.pendingProofs.get(key), proof);
    assert.equal(service.engine.submitting.size, 1);
    assert.equal(service.engine.snapshot().attempts, attempts);
    assert.equal(service.metrics.connectionsStarted, starts);
    assert.equal(service.engine.successCounts.get(key), 1n);
    assert.equal(service.metrics.valid, 1); assert.equal(service.metrics.targetReached, 1);
    assert.equal(f.sent.length, 0);
  }
  release.resolve(); await until(() => service.engine.snapshot().completed === 1);
  assert.deepEqual(f.sent, [winner.context.txid]);
  assert.equal(service.journal.unresolved().length, 0);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.engine.deferredBroadcasts.size, 0);
  assert.equal(service.engine.snapshot().attempts, attempts);
  assert.equal(service.metrics.connectionsStarted, starts);
  assert.equal(service.metrics.valid, 1); assert.equal(service.metrics.targetReached, 1);
  assert.equal(service.engine.generation, generation);
  assert.equal(f.poolStarts, 1); assert.equal(f.poolCloses, 0);
});

for (const invalidation of ['spent', 'pending_spend', 'reorg', 'unsupported-root']) test(`reserved submission cannot bypass ${invalidation} invalidation`, async t => {
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  t.after(() => release.resolve());
  const f = await fixture(t, [row(1)]), { service } = f;
  const request = f.rpc.request.bind(f.rpc);
  let signal;
  f.rpc.request = async (method, params, options) => {
    if (method === 'sendrawtransaction') { signal = options.signal; entered.resolve(); await release.promise; }
    return request(method, params, options);
  };
  const winner = f.attempts[0], key = winner.bountyId;
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await entered.promise;
  const rows = invalidation === 'reorg' ? [] : [{ ...f.initial[0],
    ...(invalidation === 'unsupported-root' ? { root_certificates_version: 2 } : { status: invalidation }) }];
  const refreshing = f.refresh({ rows, invalidated: invalidation === 'reorg' ? [[f.initial[0], 'reorg']] : [] });
  await until(() => signal.aborted);
  release.resolve(); await refreshing; await until(() => service.engine.submitting.size === 0);
  assert.equal(f.sent.length, 0); assert.equal(service.engine.snapshot().completed, 0);
  assert.equal(service.reserved.has(key), true);
  assert.equal(service.journal.unresolved()[0].transactionHex, winner.context.txid,
    'Cancelling admission must not erase the exact verified transaction already saved.');
  if (invalidation === 'unsupported-root') {
    assert.equal(service.running, false); assert.match(service.lastError, /metadata changed/);
  } else {
    assert.equal(service.engine.pendingProofs.has(key), false);
    assert.equal(service.running, true);
  }
});

for (const source of ['journal', 'snapshot']) test(`a first verified winner survives ${source} pending-spend before its initial journal write`, async t => {
  const f = await fixture(t, [row(1)]), { service } = f, winner = f.attempts[0], key = winner.bountyId;
  const pendingRow = { ...f.initial[0], status: 'pending_spend', spending_txid: hash(900) };
  const resync = f.beginResync({ rows: [pendingRow], beforePublish: options => {
    if (source === 'journal') options.onInvalidate(f.initial[0], 'pending_spend');
  } });
  await resync.entered;
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => service.engine.pendingProofs.has(key));
  assert.equal(service.journal.entries().length, 0);
  const attempts = service.engine.snapshot().attempts, starts = service.metrics.connectionsStarted;
  resync.release(); await resync.cycle; await service.journal.flush();
  assert.equal(service.journal.entries()[0]?.transactionHex, winner.context.txid,
    'A transient conflicting spend must not erase an unsent verified winner.');
  assert.equal(service.journal.entries()[0].status, 'pending');
  assert.equal(service.reserved.has(key), true); assert.equal(f.sent.length, 0);
  const request = f.rpc.request.bind(f.rpc);
  service.validateSaved = record => record.transactionHex; // Synthetic fixture bytes only.
  f.rpc.request = async (method, params, options) => {
    if (method === 'gettransaction') {
      assert.equal(params.txid, winner.context.txid);
      throw Object.assign(new Error('Not indexed'), { code: -32004 });
    }
    return request(method, params, options);
  };
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.equal(f.sent.length, 0, 'Pending-spend remains a broadcast barrier.');
  await f.refresh({ rows: f.initial });
  service.recoveryDue.clear(); await service.reconcileBroadcasts();
  assert.deepEqual(f.sent, [winner.context.txid]);
  assert.equal(service.engine.snapshot().completed, 1);
  assert.equal(service.engine.snapshot().attempts, attempts);
  assert.equal(service.metrics.connectionsStarted, starts);
  assert.equal(service.metrics.valid, 1); assert.equal(service.metrics.targetReached, 1);
  assert.equal(service.journal.entries()[0].status, 'accepted');
});

test('pending-spend preserves the winner in memory if its journal write fails, then stop can flush it', async t => {
  const f = await fixture(t, [row(1)]), { service } = f, winner = f.attempts[0], key = winner.bountyId;
  const resync = f.beginResync({ rows: [{ ...f.initial[0], status: 'pending_spend', spending_txid: hash(900) }] });
  await resync.entered;
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => service.engine.pendingProofs.has(key));
  const update = service.journal.update.bind(service.journal);
  service.journal.update = async () => { throw new Error('Controlled journal write failure'); };
  resync.release(); await resync.cycle;
  await until(() => Boolean(service.fatalError)); await service.engineDrain;
  assert.equal(service.running, false); assert.equal(service.ready, false);
  assert.equal(service.engine.pendingProofs.has(key), false);
  assert.equal(service.heldProofs.get(key)?.proof, '020100');
  assert.equal(service.reserved.has(key), true);
  assert.equal(service.engine.snapshot().completed, 0);
  assert.equal(service.metrics.valid, 1); assert.equal(f.sent.length, 0);
  service.journal.update = update;
  await service.stop();
  assert.equal(service.heldProofs.size, 0);
  assert.equal(service.journal.entries()[0]?.transactionHex, winner.context.txid);
  assert.equal(service.journal.entries()[0].status, 'pending');
  assert.equal(f.sent.length, 0);
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

for (const stage of ['RPC queue', 'node-rejection backoff']) test(`normal aging sends an already-verified claim from ${stage} without rediscovery`, async t => {
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  t.after(() => release.resolve());
  const f = await fixture(t, [row(1)]), { service } = f;
  const winner = f.attempts[0], key = winner.bountyId, job = service.engine.queue.get(key);
  const prepared = job.prepared, generation = service.engine.generation;
  const request = f.rpc.request.bind(f.rpc), attached = [], submitted = [];
  const attach = service.attachProof;
  service.attachProof = (proposal, proof) => { attached.push({ proposal, proof }); return attach(proposal, proof); };
  // This fixture uses txids as synthetic serialized transactions. Production
  // receipt/replay integrity is covered with real serialization in service.test.
  service.validateSaved = record => record.transactionHex;
  f.rpc.request = async (method, params, options) => {
    if (stage === 'node-rejection backoff' && method === 'gettransaction') {
      assert.equal(params.txid, winner.context.txid);
      throw Object.assign(new Error('Claim not indexed.'), { code: -32004 });
    }
    assert.equal(method, 'sendrawtransaction', 'A verified claim needs no new funding or availability lookup.');
    submitted.push(params.transaction_hex);
    if (submitted.length === 1) {
      entered.resolve();
      if (stage === 'RPC queue') await release.promise;
      else throw Object.assign(new Error('Recoverable node rejection.'), { code: -32020, data: { node_code: -26 } });
    }
    return request(method, params, options);
  };
  winner.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await entered.promise;
  if (stage === 'node-rejection backoff') {
    await until(() => service.engine.submitting.size === 0 && !service.engine.hasActive(key));
    assert.equal(service.engine.pendingProofs.has(key), false, 'Durable journal now owns the rejected winner.');
    assert.equal(service.journal.entries()[0].status, 'pending');
    assert.equal(service.journal.entries()[0].transactionHex, winner.context.txid);
  }
  const pending = service.engine.pendingProofs.get(key), attempts = service.engine.snapshot().attempts;
  const connectionsStarted = service.metrics.connectionsStarted;
  const agedTip = { ...tip, height: 602, hash: hash(702) };
  const agedWindow = { tip: agedTip, window: 600,
    blocks: Array.from({ length: 600 }, (_, i) => ({ height: 602 - i, hash: hash(702 - i) })) };
  await service.cycling;
  await f.ageOut(agedWindow);
  assert.equal(service.blocks.size, 0);
  assert.equal(service.blockWindow.blocks.some(block => block.hash === row(1).block_hash), false);
  assert.equal(service.catalogGate, null); assert.equal(service.ready, true);
  if (stage === 'RPC queue') {
    assert.strictEqual(service.engine.queue.get(key), job); assert.equal(job.retired, true);
    assert.strictEqual(service.engine.pendingProofs.get(key), pending);
    assert.strictEqual(job.prepared, prepared); assert.equal(pending.proof, '020100');
  } else {
    assert.equal(service.engine.pendingProofs.has(key), false);
    assert.equal(service.journal.entries()[0].transactionHex, winner.context.txid);
    assert.equal(service.reserved.has(key), true);
  }
  assert.equal(service.engine.successCounts.get(key), stage === 'RPC queue' ? 1n : undefined);
  assert.equal(service.metrics.valid, 1); assert.equal(service.metrics.targetReached, 1);
  assert.equal(service.engine.snapshot().attempts, attempts);
  assert.equal(service.metrics.connectionsStarted, connectionsStarted);
  if (stage === 'RPC queue') release.resolve();
  else { service.recoveryDue.clear(); await service.reconcileBroadcasts(); }
  await until(() => service.engine.snapshot().completed === 1);
  assert.deepEqual(f.sent, [winner.context.txid]);
  assert.deepEqual(submitted, Array(stage === 'RPC queue' ? 1 : 2).fill(winner.context.txid));
  assert.ok(attached.every(entry => entry.proposal === prepared && entry.proof === '020100'));
  assert.equal(service.journal.unresolved().length, 0);
  assert.equal(service.journal.entries()[0].status, 'accepted');
  assert.equal(service.engine.generation, generation);
  assert.equal(service.engine.snapshot().attempts, attempts);
  assert.equal(service.metrics.connectionsStarted, connectionsStarted);
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
