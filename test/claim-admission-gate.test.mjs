import test from 'node:test';
import assert from 'node:assert/strict';
import { ClaimsEngine } from '../src/core/claims-engine.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const tick = () => new Promise(resolve => setImmediate(resolve));
const bounty = { txid: 'a'.repeat(64), vout: 0, amount: '1000000000', domain: 'example.com', status: 'available',
  connection_work_target: 'f'.repeat(64), root_certificates_version: 1, signature_algorithms_mask: 7 };
const context = { domain: bounty.domain, txid: 'b'.repeat(64), input_index: 0,
  connection_work_target: bounty.connection_work_target, root_certificates_version: 1, signature_algorithms_mask: 7, validation_time: 1800000000 };

test('catalog pause propagates immediately to the existing native admission gate without cancelling started work', async t => {
  const gates = [], result = deferred(); let callbacks;
  const pool = { pacesStarts: true, setAdmissionAllowed: async allowed => { gates.push(allowed); },
    attempt: (_context, options) => { callbacks = options; return result.promise; }, async close() {} };
  const engine = new ClaimsEngine({ prepare: async () => ({ context }), submit: async () => {}, isUnlocked: () => true, randomIndex: () => 0 });
  engine.kick = () => {}; engine.enqueue([bounty]); engine.enabled = true; engine.pool = pool;
  const job = engine.queue.get(`${bounty.txid}:0`); job.prepared = { context }; engine.updatePriority(job);
  t.after(async () => { result.resolve({ started: true, captured: false, proof: null, verified: false, seconds: 0, cancelled: true, validationPassed: null }); await engine.stop(); });
  engine.dispatch([`${bounty.txid}:0`, job], engine.generation); await tick(); callbacks.onStarted();
  engine.setCatalogBlocked(true); assert.deepEqual(gates, [false]); assert.equal(callbacks.signal.aborted, false);
  assert.strictEqual(engine.pool, pool); assert.equal(engine.state.attempts, 1);
  engine.setCatalogBlocked(false); assert.deepEqual(gates, [false, true]);
});

test('catalog pause during helper startup is applied before any pending capture dispatch', async t => {
  const started = deferred(), gates = [];
  const pool = { start: () => started.promise, setAdmissionAllowed: async allowed => { gates.push(allowed); }, async close() {},
    attempt() { throw new Error('No capture should run while catalog is blocked'); } };
  const engine = new ClaimsEngine({ prepare: async () => ({ context }), submit: async () => {}, isUnlocked: () => true, poolFactory: () => pool });
  t.after(() => engine.stop());
  engine.enabled = true; const pump = engine.pump(engine.generation); engine.setCatalogBlocked(true);
  started.resolve(); await pump;
  assert.ok(gates.length > 0 && gates.every(allowed => allowed === false));
  assert.equal(engine.connections.size, 0); assert.equal(engine.catalogBlocked, true);
});

test('admission ACK failure stops only the pool and generation which requested it', async t => {
  for (const obsolete of [false, true]) {
    let reject; const gate = new Promise((_resolve, failed) => { reject = failed; });
    const pool = { setAdmissionAllowed: () => gate, async close() {} };
    const engine = new ClaimsEngine({ prepare: async () => ({}), submit: async () => {}, isUnlocked: () => true });
    engine.kick = () => {}; engine.enabled = true; engine.pool = pool;
    engine.setCatalogBlocked(true);
    if (obsolete) { engine.generation++; engine.pool = { async close() {} }; }
    reject(new Error('Gate acknowledgement failed')); await tick();
    assert.equal(engine.enabled, obsolete);
    await engine.stop();
  }
});
