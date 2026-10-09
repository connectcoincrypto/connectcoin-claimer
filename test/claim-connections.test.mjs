import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { ClaimsEngine } from '../src/core/claims.mjs';

const hash = n => n.toString(16).padStart(64, '0');
const key = row => `${row.txid}:${row.vout}`;
const row = (id = 1, domain = 'example.com') => ({ txid: hash(id), vout: 0, amount: '1000000000', domain,
  status: 'available', connection_work_target: 'f'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7 });
const context = bounty => ({ domain: bounty.domain, txid: hash(1000 + Number(BigInt(`0x${bounty.txid}`))), input_index: 0,
  connection_work_target: bounty.connection_work_target, root_certificates_version: 1,
  signature_algorithms_mask: bounty.signature_algorithms_mask, validation_time: 1800000000 });
const tick = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate, message = 'connection coordinator') {
  const until = Date.now() + 5000;
  while (Date.now() < until) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 2)); }
  throw new Error(`Timed out waiting for ${message}`);
}

function fixture(t, overrides = {}) {
  const { transformPool, ...engineOverrides } = overrides;
  const attempts = [], submissions = [], preparations = [], resolves = [], starts = [];
  let constructions = 0, closes = 0;
  const poolFactory = () => {
    constructions++;
    const pool = {
      async start(options) { starts.push(options); },
      async resolve(domain, { signal } = {}) { if (signal?.aborted) throw Object.assign(new Error('cancelled'), { name: 'AbortError' }); resolves.push(domain); },
      attempt(ctx, options) {
        return new Promise((resolve, reject) => {
          const attempt = { context: ctx, ...options, settled: false, dispatchedAt: performance.now() };
          const finish = (extra = {}) => {
            if (attempt.settled) return;
            attempt.settled = true;
            options.signal?.removeEventListener('abort', abort);
            const value = { started: true, captured: false, validationPassed: false, seconds: 0.01, proof: null, verified: false, cancelled: false, ...extra };
            if (!value.cancelled) options.onCapture?.(value);
            options.onResult?.(value);
            resolve(value);
          };
          const abort = () => finish({ started: true, validationPassed: null, cancelled: true });
          attempt.finish = finish; attempt.reject = reject;
          attempts.push(attempt);
          options.signal?.addEventListener('abort', abort, { once: true });
          if (options.signal?.aborted) abort(); else options.onStarted?.();
        });
      },
      async close() { closes++; },
    };
    return transformPool ? transformPool(pool) : pool;
  };
  const engine = new ClaimsEngine({
    isUnlocked: () => true, randomIndex: () => 0,
    options: { connectionsPerSecond: 256, concurrency: 4 }, poolFactory,
    prepare: async bounty => { preparations.push(key(bounty)); return { context: context(bounty), bounty, payout: bounty.amount }; },
    submit: async (prepared, proof, { signal } = {}) => { assert.equal(signal?.aborted, false); submissions.push(key(prepared.bounty)); return prepared.context.txid; },
    ...engineOverrides,
  });
  t.after(() => engine.stop());
  return { engine, attempts, submissions, preparations, resolves, starts, get constructions() { return constructions; }, get closes() { return closes; } };
}

test('simultaneous fresh winners and queued proofs share the four-submission limit', async t => {
  const sent = [], releases = [];
  let active = 0, maximum = 0;
  const { engine, attempts } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 24 },
    transformPool: pool => ({ ...pool, pacesStarts: true }),
    submit: async (prepared, _proof, { signal }) => {
      sent.push(key(prepared.bounty)); maximum = Math.max(maximum, ++active);
      await new Promise(resolve => { releases.push(resolve); signal.addEventListener('abort', resolve, { once: true }); });
      active--; return prepared.context.txid;
    },
  });
  // Release held mock RPCs even if an assertion fails, so cleanup cannot hang.
  t.after(() => { for (const release of releases) release(); });
  // Domain fairness supplies twelve independent leaders; same-domain slots
  // intentionally share one leader now. Extra slots accommodate economic turns.
  engine.enqueue(Array.from({ length: 12 }, (_, i) => row(i + 1, `d${String(i).padStart(2, '0')}.example`)));
  for (const job of engine.queue.values()) {
    job.prepared = { bounty: job.bounty, context: context(job.bounty) };
    engine.dns.set(job.bounty.domain, { ok: true, expires: Date.now() + 60000 });
  }
  engine.start();
  await until(() => new Set(attempts.map(item => item.bountyId)).size === 12);
  for (const attempt of attempts) attempt.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => sent.length >= 4);
  await tick(); await tick();
  assert.equal(active, 4); assert.equal(sent.length, 4);
  for (let batch = 0; batch < 3; batch++) {
    for (const release of releases.splice(0)) release();
    await until(() => engine.snapshot().completed === (batch + 1) * 4);
    if (batch < 2) await until(() => active === 4);
  }
  assert.equal(maximum, 4); assert.equal(new Set(sent).size, 12);
  assert.equal(engine.pendingProofs.size, 0);
});

test('one persistent pool runs multiple bounties concurrently with a single global slot bound', async t => {
  const fixtureData = fixture(t), { engine, attempts, starts } = fixtureData;
  engine.enqueue([row(1, 'alpha.example'), row(2, 'beta.example')]); engine.start();
  await until(() => attempts.length === 4);
  assert.equal(engine.activeKeys().size, 2);
  assert.equal(fixtureData.constructions, 1); assert.equal(starts.length, 1);
  assert.deepEqual(starts[0], { connectionsPerSecond: 256, concurrency: 4 });
  await tick(); assert.equal(attempts.length, 4, 'held tasks must not be exceeded by another domain');
  assert.ok(attempts.every(value => !value.signal.aborted));
  await engine.stop(); assert.ok(attempts.every(value => value.signal.aborted));
  assert.equal(engine.activeKeys().size, 0); assert.equal(fixtureData.closes, 1);
});

test('connection starts are paced globally across domains instead of granting each domain its own rate', async t => {
  const { engine, attempts } = fixture(t, { options: { connectionsPerSecond: 10, concurrency: 4 } });
  engine.enqueue([row(1, 'alpha.example'), row(2, 'beta.example')]); engine.start();
  await until(() => attempts.length >= 3);
  assert.ok(attempts[2].dispatchedAt - attempts[0].dispatchedAt >= 180, 'three starts at 10/s require approximately 200ms even across different domains');
  assert.ok(new Set(attempts.map(value => value.context.domain)).size > 1);
});

test('a pool with an actual socket-start rate gate is not throttled again by the JavaScript timer', async t => {
  const { engine, attempts } = fixture(t, {
    options: { connectionsPerSecond: 1, concurrency: 4 },
    transformPool: pool => ({ ...pool, pacesStarts: true }),
  });
  engine.enqueue([row(1, 'alpha.example'), row(2, 'beta.example')]); engine.start();
  await until(() => attempts.length === 4);
  assert.equal(engine.nextStart, 0, 'the persistent helper owns the one global clock at socket start');
  assert.equal(engine.snapshot().attempts, 4);
});

test('successful captures, not hash wins, enforce strict 2E cutoff and survive stop/start and refresh', async t => {
  const { engine, attempts } = fixture(t, { options: { connectionsPerSecond: 256, concurrency: 1 } });
  const bounty = row(); engine.enqueue([bounty]); engine.start();
  for (let i = 0; i < 3; i++) {
    await until(() => attempts.length === i + 1);
    assert.equal(attempts[i].successfulConnections, BigInt(i));
    attempts[i].finish({ captured: true, validationPassed: true });
  }
  await until(() => !engine.hasActive(key(bounty)));
  assert.equal(engine.successCounts.get(key(bounty)), 3n);
  const factor = engine.factors.get(key(bounty));
  await engine.stop(); engine.enqueue([bounty]); engine.retainCatalog([bounty]); engine.start();
  await tick(); await tick();
  assert.equal(attempts.length, 3); assert.equal(engine.factors.get(key(bounty)), factor);
  assert.equal(engine.successCounts.get(key(bounty)), 3n);
});

test('failed TCP/TLS captures do not consume the successful-connection budget', async t => {
  const { engine, attempts } = fixture(t, { options: { connectionsPerSecond: 256, concurrency: 1 } });
  const bounty = row(); engine.enqueue([bounty]); engine.start();
  await until(() => attempts.length === 1);
  attempts[0].finish({ captured: false, validationPassed: false, message: 'isolated TLS capture failed' });
  await until(() => attempts.length === 2, 'worker failure pause and next connection');
  assert.equal(attempts[1].successfulConnections, 0n);
  assert.equal(engine.successCounts.get(key(bounty)) ?? 0n, 0n);
  attempts[1].finish({ captured: true, validationPassed: true });
  await until(() => (engine.successCounts.get(key(bounty)) ?? 0n) === 1n);
});

test('a proof already in flight remains eligible after other captures cross the 2E cutoff', async t => {
  const { engine, attempts, submissions } = fixture(t);
  const bounty = row(); engine.enqueue([bounty]); engine.start();
  await until(() => attempts.length === 4);
  for (let i = 0; i < 3; i++) attempts[i].finish({ captured: true, validationPassed: true });
  await until(() => engine.successCounts.get(key(bounty)) === 3n);
  assert.equal(attempts[3].signal.aborted, false);
  attempts[3].finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => submissions.length === 1);
  assert.deepEqual(submissions, [key(bounty)]); assert.equal(attempts.length, 4);
});

test('the first verified proof cancels only same-bounty siblings and submits once', async t => {
  const { engine, attempts, submissions } = fixture(t);
  const alpha = row(1, 'alpha.example'), beta = row(2, 'beta.example');
  engine.enqueue([alpha, beta]); engine.start(); await until(() => attempts.length === 4);
  const siblings = attempts.filter(value => value.bountyId === key(alpha));
  const other = attempts.find(value => value.bountyId === key(beta));
  assert.ok(siblings.length >= 2); assert.ok(other);
  siblings[0].finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => submissions.includes(key(alpha)));
  assert.ok(siblings.slice(1).every(value => value.signal.aborted));
  assert.equal(other.signal.aborted, false);
  other.finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => submissions.length === 2);
  assert.deepEqual(submissions.sort(), [key(alpha), key(beta)].sort());
});

test('prepared public transaction is reused across individual connections while validation time refreshes', async t => {
  let validationTime = 1800000000;
  const { engine, attempts, preparations } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 1 }, getValidationTime: () => validationTime,
  });
  const bounty = row(); engine.enqueue([bounty]); engine.start();
  await until(() => attempts.length === 1); const first = attempts[0].context;
  validationTime++; attempts[0].finish({ captured: true, validationPassed: true });
  await until(() => attempts.length === 2);
  assert.equal(preparations.length, 1); assert.equal(engine.proposals.size, 1);
  assert.equal(attempts[1].context.txid, first.txid);
  assert.equal(attempts[1].context.validation_time, validationTime);
  assert.equal(first.validation_time, 1800000000, 'the first live context is immutable');
});

test('an unknown broadcast outcome closes the global gate and cancels unrelated active work', async t => {
  let submitted = 0;
  const { engine, attempts } = fixture(t, { submit: async () => { submitted++; throw Object.assign(new Error('unknown mocked broadcast'), { unknownOutcome: true }); } });
  engine.enqueue([row(1, 'alpha.example'), row(2, 'beta.example')]); engine.start();
  await until(() => attempts.length === 4);
  attempts[0].finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => !engine.enabled && !engine.activeKeys().size);
  assert.equal(submitted, 1); assert.equal(attempts.length, 4);
  assert.ok(attempts.slice(1).every(value => value.signal.aborted));
});

test('the public proposal cache stays at 256 and never evicts a held active challenge', { timeout: 15000 }, async t => {
  // This tests cache eviction, not pacing. Let the isolated adapter own starts
  // so exhausting each leader's budget does not multiply real timer waits.
  const { engine, attempts, preparations } = fixture(t, { transformPool: pool => ({ ...pool, pacesStarts: true }) });
  const bounties = Array.from({ length: 257 }, (_, index) => row(index + 1));
  engine.enqueue(bounties); engine.start(); await until(() => attempts.length >= 2);
  const held = attempts[0], heldProposal = engine.proposals.get(held.bountyId);
  assert.ok(heldProposal);
  for (let index = 1; new Set(preparations).size < 257; index++) {
    await until(() => attempts.length > index, 'next public proposal');
    attempts[index].finish({ captured: true, validationPassed: true });
    assert.ok(engine.proposals.size <= 256);
    assert.strictEqual(engine.proposals.get(held.bountyId), heldProposal);
    assert.equal(held.signal.aborted, false);
  }
  assert.equal(new Set(preparations).size, 257);
  assert.equal(engine.proposals.size, 256);
  assert.strictEqual(engine.proposals.get(held.bountyId), heldProposal);
});

test('catalog resync preserves successful budget, factor and fixed public proposal; final cleanup releases them', async t => {
  const { engine, attempts } = fixture(t, { options: { connectionsPerSecond: 256, concurrency: 1 } });
  const bounty = row(); engine.enqueue([bounty]); engine.start();
  await until(() => attempts.length === 1);
  attempts[0].finish({ captured: true, validationPassed: true });
  await until(() => engine.successCounts.get(key(bounty)) === 1n);
  await engine.suspend();
  const factor = engine.factors.get(key(bounty)), prepared = engine.proposals.get(key(bounty));
  engine.clear({ preserveSelection: true }); engine.enqueue([bounty]); engine.retainCatalog([bounty]);
  assert.equal(engine.successCounts.get(key(bounty)), 1n);
  assert.equal(engine.factors.get(key(bounty)), factor);
  assert.strictEqual(engine.proposals.get(key(bounty)), prepared);
  engine.remove(bounty.txid, bounty.vout); engine.retainCatalog([]);
  assert.equal(engine.successCounts.has(key(bounty)), false);
  assert.equal(engine.factors.has(key(bounty)), false);
  assert.equal(engine.proposals.has(key(bounty)), false);
});

test('a recoverably rejected proof retries the same transaction after 2E cutoff without new TLS', async t => {
  const submitted = [];
  const { engine, attempts } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 1 }, retryDelayMs: 1,
    submit: async (prepared, proof) => {
      submitted.push({ prepared, proof });
      if (submitted.length === 1) throw Object.assign(new Error('mock recoverable node rejection'), { code: -32020, data: { node_code: -26 } });
      return prepared.context.txid;
    },
  });
  const bounty = row(); engine.enqueue([bounty]); engine.start();
  for (let i = 0; i < 3; i++) {
    await until(() => attempts.length === i + 1);
    attempts[i].finish({ captured: true, validationPassed: true, ...(i === 2 ? { proof: '020100', verified: true } : {}) });
  }
  await until(() => engine.snapshot().completed === 1);
  assert.equal(attempts.length, 3); assert.equal(submitted.length, 2);
  assert.strictEqual(submitted[1].prepared, submitted[0].prepared);
  assert.equal(submitted[1].proof, submitted[0].proof);
  assert.equal(engine.successCounts.get(key(bounty)), 3n);
});

test('authoritative helper success totals never regress when capture observations finish out of order', async t => {
  const { engine, attempts } = fixture(t);
  const bounty = row(); engine.enqueue([bounty]); engine.start();
  await until(() => attempts.length === 4);
  attempts[2].finish({ captured: true, validationPassed: true, successfulConnections: '3' });
  await until(() => engine.successCounts.get(key(bounty)) === 3n);
  attempts[0].finish({ captured: true, validationPassed: true, successfulConnections: '1' });
  attempts[1].finish({ captured: true, validationPassed: true, successfulConnections: '2' });
  await tick();
  assert.equal(engine.successCounts.get(key(bounty)), 3n);
  assert.equal(attempts[3].signal.aborted, false, 'out-of-order totals cannot cancel work already started');
});

const cancelledWait = signal => new Promise((resolve, reject) => {
  const abort = () => reject(Object.assign(new Error('isolated cancellation'), { name: 'AbortError' }));
  if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
});

test('exhausted preparation slots cannot block a different already prepared and resolved domain', async t => {
  let pendingPrepares = 0;
  const { engine, attempts } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 1 },
    prepare: async (_bounty, { signal }) => { pendingPrepares++; return cancelledWait(signal); },
  });
  const ready = row(9, 'zeta.example');
  engine.proposals.set(key(ready), { bounty: ready, payout: ready.amount, context: context(ready) });
  engine.dns.set(ready.domain, { ok: true, expires: Date.now() + 60000 });
  engine.enqueue(['alpha', 'beta', 'gamma', 'delta', 'epsilon'].map((name, index) => row(index + 1, `${name}.example`)).concat(ready));
  engine.start(); await until(() => attempts.length === 1);
  assert.equal(pendingPrepares, 4, 'the fifth unprepared domain waits without blocking prepared work');
  assert.equal(attempts[0].context.domain, ready.domain);
  assert.equal(engine.scheduler.domainAfter, ready.domain);
});

test('two blocked DNS lookups cannot block a third unresolved domain ahead of a resolved domain', async t => {
  const resolutions = [];
  const { engine, attempts } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 1 },
    transformPool: pool => ({ ...pool, async resolve(domain, { signal }) { resolutions.push(domain); return cancelledWait(signal); } }),
  });
  const bounties = ['alpha', 'beta', 'gamma', 'zeta'].map((name, index) => row(index + 1, `${name}.example`));
  for (const bounty of bounties) engine.proposals.set(key(bounty), { bounty, payout: bounty.amount, context: context(bounty) });
  engine.dns.set('zeta.example', { ok: true, expires: Date.now() + 60000 });
  engine.enqueue(bounties); engine.start(); await until(() => attempts.length === 1);
  assert.deepEqual(resolutions, ['alpha.example', 'beta.example']);
  assert.equal(attempts[0].context.domain, 'zeta.example');
  assert.equal(engine.scheduler.domainAfter, 'zeta.example');
  assert.equal(engine.preferReward, true, 'only the single TCP assignment consumed a domain turn');
});

test('a late TCP-start acknowledgement after stop counts the attempt without reviving searching UI', async t => {
  let request, finish;
  const { engine } = fixture(t, {
    transformPool: pool => ({ ...pool, attempt(ctx, options) { request = { ctx, ...options }; return new Promise(resolve => { finish = resolve; }); } }),
  });
  const cancelled = { started: true, captured: false, validationPassed: null, cancelled: true, seconds: 0, proof: null, verified: false };
  try {
    engine.enqueue([row()]); engine.start(); await until(() => request);
    const stopping = engine.stop();
    assert.equal(request.signal.aborted, true);
    request.onStarted();
    assert.equal(engine.snapshot().attempts, 1);
    assert.equal(engine.enabled, false); assert.equal(engine.snapshot().status, 'off');
    finish(cancelled);
    await stopping;
    assert.equal(engine.snapshot().status, 'off'); assert.equal(engine.activeKeys().size, 0);
  } finally {
    finish?.(cancelled);
    await engine.stop();
  }
});

test('outpoint invalidation aborts an active retry submission, not only its original TLS request', async t => {
  let submits = 0, retrySignal;
  const { engine, attempts } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 1 }, retryDelayMs: 1,
    submit: async (_prepared, _proof, { signal }) => {
      if (++submits === 1) throw Object.assign(new Error('mock recoverable node rejection'), { code: -32020, data: { node_code: -26 } });
      retrySignal = signal; return cancelledWait(signal);
    },
  });
  const bounty = row(); engine.enqueue([bounty]); engine.start(); await until(() => attempts.length === 1);
  attempts[0].finish({ captured: true, validationPassed: true, proof: '020100', verified: true });
  await until(() => retrySignal);
  assert.equal(engine.hasActive(key(bounty)), true);
  engine.remove(bounty.txid, bounty.vout);
  assert.equal(retrySignal.aborted, true, 'a spent/reorganized outpoint cancels all its live stages');
  await until(() => !engine.hasActive(key(bounty)));
  assert.equal(engine.snapshot().completed, 0); assert.equal(attempts.length, 1);
});

test('a verified pending proof retains the only queue slot after resync even beyond the capture budget', async t => {
  const submitted = [];
  const { engine, attempts } = fixture(t, {
    maxQueue: 1, options: { connectionsPerSecond: 256, concurrency: 1 }, retryDelayMs: 300000,
    submit: async (prepared, proof) => {
      submitted.push({ prepared, proof });
      if (submitted.length === 1) throw Object.assign(new Error('mock recoverable node rejection'), { code: -32020, data: { node_code: -26 } });
      return prepared.context.txid;
    },
  });
  const bounty = row(), competing = { ...row(2, 'other.example'), amount: '1000000000000' };
  engine.enqueue([bounty]); engine.start();
  for (let i = 0; i < 3; i++) {
    await until(() => attempts.length === i + 1);
    attempts[i].finish({ captured: true, validationPassed: true, ...(i === 2 ? { proof: '020100', verified: true } : {}) });
  }
  await until(() => engine.pendingProofs.has(key(bounty)) && !engine.hasActive(key(bounty)));
  await engine.suspend();
  const factor = engine.factors.get(key(bounty)), prepared = engine.proposals.get(key(bounty));
  engine.clear({ preserveSelection: true });
  assert.equal(engine.enqueue([competing, bounty]), 1);
  engine.retainCatalog([bounty, competing]);
  assert.deepEqual([...engine.queue.keys()], [key(bounty)], 'a higher-paying new TLS candidate cannot expel a verified proof');
  assert.equal(engine.queue.get(key(bounty)).budgetExceeded, true);
  assert.equal(engine.factors.get(key(bounty)), factor);
  assert.strictEqual(engine.proposals.get(key(bounty)), prepared);
  engine.pendingProofs.get(key(bounty)).due = 0;
  engine.resume(); await until(() => engine.snapshot().completed === 1);
  assert.equal(attempts.length, 3); assert.equal(submitted.length, 2);
  assert.strictEqual(submitted[1].prepared, submitted[0].prepared);
  assert.equal(submitted[1].proof, submitted[0].proof);
});

test('a high-value candidate parked for preparation keeps its admission slot over a lower-value newcomer', async t => {
  let pendingPrepares = 0;
  const { engine, attempts } = fixture(t, {
    maxQueue: 5, options: { connectionsPerSecond: 256, concurrency: 1 },
    prepare: async (_bounty, { signal }) => { pendingPrepares++; return cancelledWait(signal); },
  });
  const bounties = ['alpha', 'beta', 'delta', 'epsilon', 'gamma'].map((domain, index) => row(index + 1, `${domain}.example`));
  engine.enqueue(bounties); engine.start();
  await until(() => pendingPrepares === 4 && engine.waitingPrepare.size === 1);
  const parked = [...engine.waitingPrepare][0], factor = parked.factor;
  assert.equal(engine.hasActive(key(parked.bounty)), false, 'the parked candidate has not consumed a preparation slot');
  const low = { ...row(99, 'low.example'), amount: '1000000' };
  assert.equal(engine.enqueue([low]), 0);
  assert.equal(engine.queue.size, 5);
  assert.strictEqual(engine.queue.get(key(parked.bounty)), parked);
  assert.equal(parked.factor, factor); assert.equal(engine.waitingPrepare.has(parked), true);
  assert.equal(engine.queue.has(key(low)), false); assert.equal(attempts.length, 0);
});

test('releasing a DNS slot skips a removed parked domain and wakes the next valid candidate', async t => {
  const lookups = new Map();
  const { engine, attempts } = fixture(t, {
    options: { connectionsPerSecond: 256, concurrency: 1 },
    transformPool: pool => ({ ...pool, resolve(domain, { signal }) {
      return new Promise((resolve, reject) => {
        const abort = () => reject(Object.assign(new Error('isolated cancellation'), { name: 'AbortError' }));
        signal.addEventListener('abort', abort, { once: true });
        lookups.set(domain, { resolve: () => { signal.removeEventListener('abort', abort); resolve(); },
          reject: error => { signal.removeEventListener('abort', abort); reject(error); } });
      });
    } }),
  });
  const bounties = ['alpha', 'beta', 'delta', 'gamma'].map((domain, index) => row(index + 1, `${domain}.example`));
  for (const bounty of bounties) engine.proposals.set(key(bounty), { bounty, payout: bounty.amount, context: context(bounty) });
  engine.enqueue(bounties); engine.start();
  await until(() => lookups.size === 2 && engine.waitingDns.size === 2);
  assert.deepEqual([...engine.waitingDns], ['delta.example', 'gamma.example']);
  const removed = bounties.find(bounty => bounty.domain === 'delta.example');
  engine.remove(removed.txid, removed.vout);
  lookups.get('alpha.example').reject(new Error('isolated DNS lookup failure'));
  await until(() => lookups.has('gamma.example'), 'valid parked DNS candidate after removal');
  assert.equal(lookups.has('delta.example'), false);
  assert.notEqual(engine.scheduler.domainGates.get('delta.example')?.ready, false, 'a removed candidate leaves no closed domain gate');
  assert.equal(attempts.length, 0, 'DNS-only decisions consume no TCP attempt');
  assert.equal(engine.scheduler.domainAfter, null);
  assert.equal(engine.preferReward, false);
});
