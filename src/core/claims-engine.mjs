import { randomInt } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { validateClaimContext, isKnownClaimRejection } from './claims.mjs';
import { ConnectionPool, validateConnectionOptions, claimAborted } from './claim-pool.mjs';
import { ClaimScheduler } from './claim-scheduler.mjs';
import { ClaimConnectionPolicy, MAX_RECOVERY_POLICIES } from './claim-connection-policy.mjs';
import { diagnosticError } from './diagnostics.mjs';
import { claimPriority, selectionPriority, domainPriority, isWorthAttempting, compareClaimPriority, P2CDomainStats, validateAttemptStats, validateMinExpectedReturn, MIN_EXPECTED_RETURN,
  PRIORITY_FACTOR_SCALE, PRIORITY_FACTOR_MAX, isP2CClaimConnectionLimitExceeded, MAX_P2C_SUCCESSFUL_CONNECTIONS } from './claim-priority.mjs';

const keyOf = bounty => `${bounty.txid}:${bounty.vout}`;
const policyOf = job => `${job.bounty.domain}:${job.bounty.signature_algorithms_mask}`;
const report = (callback, event, details) => { try { Promise.resolve(callback(event, details)).catch(() => {}); } catch { /* Diagnostics never control claims. */ } };
const DIAGNOSTIC_INTERVAL_MS = 5000, DIAGNOSTIC_SAMPLES_PER_STAGE = 4;
// Pipeline preparation/IPC without preassigning a long queue at low rates.
// The helper still spaces actual socket starts; this is not a rate allowance.
const START_LOOKAHEAD_MS = 100;
// Bound IPC admissions awaiting a real TCP-start acknowledgement independently
// of the user's active connection limit. Each acknowledgement frees a slot.
const MAX_PENDING_STARTS = 128;
const CANCELLATIONS = Object.freeze({ stop: 'cancelledStop', locked: 'cancelledLocked', suspend: 'cancelledSuspend',
  clear: 'cancelledClear', unavailable: 'cancelledUnavailable', 'window-exit': 'cancelledWindowExit',
  'sibling-proof': 'cancelledSiblingProof', fatal: 'cancelledFatal', other: 'cancelledOther' });
const boundedAdd = (value, amount = 1) => Math.min(Number.MAX_SAFE_INTEGER, value + amount);
const validBounty = b => b && typeof b.txid === 'string' && b.txid.length === 64 && /^[0-9a-f]+$/.test(b.txid) &&
  Number.isInteger(b.vout) && b.vout >= 0 && b.vout <= 0xffffffff && b.status === 'available' &&
  typeof b.amount === 'string' && b.amount.length <= 19 && /^[0-9]+$/.test(b.amount) && BigInt(b.amount) <= 1000000000000000000n &&
  typeof b.domain === 'string' && b.domain.length <= 253 && !/[^a-z0-9.-]/.test(b.domain) && b.domain.includes('.') &&
  typeof b.connection_work_target === 'string' && b.connection_work_target.length === 64 && /^[0-9a-f]+$/.test(b.connection_work_target) &&
  Number.isInteger(b.signature_algorithms_mask) && b.signature_algorithms_mask >= 1 && b.signature_algorithms_mask <= 7 && b.root_certificates_version === 1;

// Injection for offline clients/tests. Production always uses ConnectionPool.
function injectedPool(generateProof) {
  return {
    async start() {}, async resolve() {}, async close() {},
    async attempt(context, { signal, onStarted, onCapture, onResult }) {
      if (signal.aborted) throw claimAborted();
      onStarted(); const started = performance.now();
      let proof;
      try {
        proof = await generateProof(context, { signal, options: { connectionsPerSecond: 1, concurrency: 1 }, onProgress() {} });
        if (signal.aborted) throw claimAborted();
      } catch (error) {
        if (error.name !== 'AbortError') {
          const result = { started: true, captured: false, seconds: (performance.now() - started) / 1000, cancelled: false, validationPassed: false };
          onCapture(result); onResult(result);
        }
        throw error;
      }
      const result = { started: true, captured: true, seconds: (performance.now() - started) / 1000, cancelled: false, proof, verified: true, validationPassed: true };
      onCapture(result); onResult(result); return result;
    },
  };
}

/** One persistent worker pool, with bounded Core-style connection assignments. */
export class ClaimsEngine {
  constructor({ prepare, submit, isUnlocked, poolFactory, generateProof, resourcesPath, onState = () => {}, onDiagnostic = () => {},
    options = {}, retryDelayMs = 30000, maxQueue = 20000, randomIndex = randomInt, getNetReward = bounty => BigInt(bounty.amount), getValidationTime, minExpectedReturn = MIN_EXPECTED_RETURN } = {}) {
    if (![prepare, submit, isUnlocked, onState, randomIndex, getNetReward].every(fn => typeof fn === 'function')) throw new Error('Claim callbacks are required');
    if (!Number.isInteger(maxQueue) || maxQueue < 1 || maxQueue > 20000 || !Number.isInteger(retryDelayMs) || retryDelayMs < 1 || retryDelayMs > 300000) throw new Error('Invalid claim queue limits');
    Object.assign(this, { prepare, submit, isUnlocked, onState, onDiagnostic, randomIndex, getNetReward, getValidationTime, maxQueue, retryDelayMs });
    this.minExpectedReturn = validateMinExpectedReturn(minExpectedReturn);
    this.poolFactory = poolFactory ?? (generateProof ? () => injectedPool(generateProof) : ({ onFailure }) => new ConnectionPool({ resourcesPath, onDiagnostic, onFailure }));
    this.options = validateConnectionOptions(options);
    this.queue = new Map(); this.completed = new Set(); this.factors = new Map(); this.successCounts = new Map();
    this.proposals = new Map(); this.pendingProofs = new Map(); this.submitting = new Set();
    this.domainStats = new Map(); this.dns = new Map(); this.live = new Map(); this.connections = new Map();
    this.connectionPolicy = new ClaimConnectionPolicy();
    this.recoveryJobs = new Map();
    this.pendingStarts = new Set(); this.pendingRecovery = new Map();
    this.tasks = new Set(); this.preparing = new Set(); this.resolving = new Set(); this.controllers = new Set();
    this.waitingPrepare = new Set(); this.waitingDns = new Set();
    this.scheduler = new ClaimScheduler({ connectionRate: job => this.connectionRate(job), isReady: job => this.ready(job), minExpectedReturn: this.minExpectedReturn });
    this.enabled = false; this.paused = false; this.dirty = true; this.nextDiagnosticId = 0; this.nextToken = 0; this.generation = 0;
    this.nextStart = 0; this.startIdle = true; this.timer = null; this.refreshTimer = null; this.coordinator = null; this.stopping = null;
    this.state = { enabled: false, status: 'off', queued: 0, completed: 0, attempts: 0, lastError: null, lastErrorCategory: null, lastErrorDiagnostic: false, lastErrorTransient: false };
    this.diagnosticRunId = 0; this.diagnosticRun = null;
    this.diagnosticOperations = new Set(); this.cancellationReasons = new WeakMap();
  }
  beginDiagnosticRun() {
    if (this.diagnosticRun) return false;
    const now = performance.now();
    this.diagnosticRun = { runId: ++this.diagnosticRunId, started: now, lastProgress: now, sampleWindow: now, samples: new Map(),
      counters: { operationsStarted: 0, operationsCompleted: 0, operationsFailed: 0, operationsCancelled: 0,
        attempts: 0, captures: 0, completed: 0, durationTotalMs: 0, durationMaxMs: 0, suppressedEvents: 0,
        ...Object.fromEntries(Object.values(CANCELLATIONS).map(key => [key, 0])) } };
    return true;
  }
  countDiagnostic(key, amount = 1) {
    const counters = this.diagnosticRun?.counters;
    if (counters) counters[key] = Math.min(key === 'durationTotalMs' ? Number.MAX_SAFE_INTEGER : 1000000000, boundedAdd(counters[key] ?? 0, amount));
  }
  beginOperation(stage, controller) {
    // Only active work is retained: at most 4 preparations, 2 DNS requests,
    // the configured active captures and 4 submissions. No history is retained.
    const operation = { stage, controller, started: performance.now() };
    this.diagnosticOperations.add(operation); this.countDiagnostic('operationsStarted');
    return operation;
  }
  finishOperation(operation, outcome) {
    if (!this.diagnosticOperations.delete(operation)) return;
    outcome ??= operation.controller.signal.aborted ? 'cancelled' : 'completed';
    const elapsed = Math.max(0, Math.round(performance.now() - operation.started));
    this.countDiagnostic({ completed: 'operationsCompleted', failed: 'operationsFailed', cancelled: 'operationsCancelled' }[outcome]);
    this.countDiagnostic('durationTotalMs', elapsed);
    const counters = this.diagnosticRun?.counters;
    if (counters) counters.durationMaxMs = Math.max(counters.durationMaxMs, elapsed);
    if (outcome === 'cancelled') this.countDiagnostic(CANCELLATIONS[this.cancellationReasons.get(operation.controller)] ?? CANCELLATIONS.other);
  }
  cancelOperation(controller, reason) {
    if (!controller || controller.signal.aborted) return;
    this.cancellationReasons.set(controller, reason); controller.abort();
  }
  diagnosticSnapshot() {
    const run = this.diagnosticRun, now = performance.now();
    const active = { prepareActive: 0, dnsActive: 0, captureActive: 0, submitActive: 0, activeMaxDurationMs: 0 };
    for (const operation of this.diagnosticOperations) {
      active[`${operation.stage}Active`]++;
      active.activeMaxDurationMs = Math.max(active.activeMaxDurationMs, Math.max(0, Math.round(now - operation.started)));
    }
    return { stage: 'lifecycle', enabled: this.enabled, paused: this.paused, queued: this.queue.size,
      ...(run ? { runId: run.runId, durationScope: 'run', durationMs: Math.min(86400000, Math.max(0, Math.round(now - run.started))), ...run.counters } : {}), ...active };
  }
  reportProgress() {
    const run = this.diagnosticRun, now = performance.now();
    if (!run || now - run.lastProgress < DIAGNOSTIC_INTERVAL_MS) return;
    run.lastProgress = now; report(this.onDiagnostic, 'claims.progress', this.diagnosticSnapshot());
  }
  sampleDiagnostic(event, details) {
    const run = this.diagnosticRun;
    if (run && !details.error?.unknownOutcome && !details.error?.helperFatal) {
      const now = performance.now();
      if (now - run.sampleWindow >= DIAGNOSTIC_INTERVAL_MS) { run.sampleWindow = now; run.samples.clear(); }
      const key = `${event}:${details.stage}`, count = run.samples.get(key) ?? 0;
      if (count >= DIAGNOSTIC_SAMPLES_PER_STAGE) { this.countDiagnostic('suppressedEvents'); return; }
      run.samples.set(key, count + 1);
    }
    report(this.onDiagnostic, event, { ...details, durationScope: 'stage', ...(run ? { runId: run.runId } : {}) });
  }
  get running() { return this.tasks.size || this.coordinator ? Promise.allSettled([...this.tasks, ...(this.coordinator ? [this.coordinator] : [])]) : null; }
  get activeKey() { return this.compatActiveKey ?? this.activeKeys().values().next().value ?? null; }
  set activeKey(value) { this.compatActiveKey = value; }
  get controller() { return this.compatController ?? this.controllers.values().next().value ?? null; }
  set controller(value) { this.compatController = value; }
  get preferReward() { return this.scheduler.preferReward; }
  activeKeys() { const keys = new Set(this.live.keys()); if (this.compatActiveKey) keys.add(this.compatActiveKey); return keys; }
  hasActive(key) { return this.live.has(key) || this.compatActiveKey === key; }
  snapshot() { return { ...this.state, enabled: this.enabled, queued: this.queue.size, active: this.connections.size, options: { ...this.options } }; }
  notify(patch = {}) {
    // Severity belongs to the warning, not the scheduler's current status.
    // A retry can become waiting/submitting without turning into a fatal alert.
    if (Object.hasOwn(patch, 'lastError')) patch = { lastErrorCategory: null, lastErrorDiagnostic: false, lastErrorTransient: false, ...patch };
    if (patch.lastError === null) patch = { ...patch, lastErrorCategory: null, lastErrorDiagnostic: false, lastErrorTransient: false };
    this.state = { ...this.state, ...patch };
    try { this.onState(this.snapshot()); } catch { /* Presentation cannot stop workers. */ }
  }
  track(job, promise) {
    const key = keyOf(job.bounty); this.live.set(key, (this.live.get(key) ?? 0) + 1);
    const tracked = Promise.resolve(promise).finally(() => {
      const count = this.live.get(key) - 1; if (count) this.live.set(key, count); else this.live.delete(key);
      this.tasks.delete(tracked);
      if (job.retired && !this.hasActive(key) && this.queue.get(key) === job) { this.queue.delete(key); this.scheduler.remove(key); }
      this.notify(); this.kick();
    });
    this.tasks.add(tracked); return tracked;
  }
  eligible(job) { return !job.unavailable && !job.retired && !job.winner && !job.budgetExceeded; }
  ready(job) { return this.eligible(job) && !job.preparing && !job.waitingPrepare &&
    !(job.recoveryProbe && this.pendingRecovery.has(policyOf(job))); }
  drawIndex(length) {
    const value = this.randomIndex(length);
    if (!Number.isSafeInteger(value) || value < 0 || value >= length) throw new Error('Invalid claim random index');
    return value;
  }
  updatePriority(job) {
    const net = job.prepared?.payout !== undefined ? BigInt(job.prepared.payout) : this.getNetReward(job.bounty);
    job.rawPriority = claimPriority(job.bounty.connection_work_target, net); job.priority = selectionPriority(job.rawPriority, job.factor);
    job.budgetExceeded = isP2CClaimConnectionLimitExceeded(job.bounty.connection_work_target, this.successCounts.get(keyOf(job.bounty)) ?? 0n);
  }
  connectionRate(job, cache) {
    const key = `${job.bounty.domain}:${job.bounty.signature_algorithms_mask}`;
    if (cache?.has(key)) return cache.get(key);
    const rate = this.domainStats.get(key)?.connectionRate() ?? 5; cache?.set(key, rate); return rate;
  }
  economicScore(job, rates) { return domainPriority(job.priority, this.connectionRate(job, rates), PRIORITY_FACTOR_SCALE); }
  recoveryCandidates(candidates, rates) {
    const healthy = new Set(), recovery = new Map();
    for (const candidate of candidates) {
      const { job } = candidate, policy = policyOf(job);
      if (!this.eligible(job)) continue;
      if (isWorthAttempting(job.rawPriority, this.connectionRate(job, rates), this.minExpectedReturn)) healthy.add(policy);
      else if (isWorthAttempting(job.rawPriority, 5, this.minExpectedReturn)) {
        const previous = recovery.get(policy);
        if (!previous || compareClaimPriority(job, previous.job) < 0) recovery.set(policy, candidate);
      }
    }
    return [...recovery].filter(([key]) => !healthy.has(key)).map(([, candidate]) => candidate)
      .sort((a, b) => compareClaimPriority(a.job, b.job)).slice(0, MAX_RECOVERY_POLICIES);
  }
  attemptable(job) { return isWorthAttempting(job.rawPriority, this.connectionRate(job), this.minExpectedReturn) || job.recoveryProbe === true; }
  jobDue(job) { return Math.max(job.due ?? 0, job.recoveryProbe ? job.probeDue ?? 0 : 0); }
  rebuild() {
    this.recoveryJobs.clear();
    for (const job of this.queue.values()) job.recoveryProbe = false;
    const candidates = [...this.queue].map(([key, job]) => ({ key, job }));
    for (const { job } of this.recoveryCandidates(candidates, new Map())) {
      const policy = policyOf(job);
      job.recoveryProbe = true; job.probeDue = this.connectionPolicy.probeDue(policy);
      this.recoveryJobs.set(policy, job);
    }
    this.scheduler.rebuild(this.queue);
    this.dirty = false;
  }
  nextReady(now = Date.now()) { if (this.dirty) this.rebuild(); return this.scheduler.next(now); }
  markAssigned(jobOrSelection) { this.scheduler.commit(jobOrSelection); }
  enqueue(bounties) {
    if (!Array.isArray(bounties)) throw new Error('Bounty list required');
    const candidates = [], protectedKeys = new Set(), seen = new Set(this.queue.keys()), rates = new Map();
    for (const [key, job] of this.queue) {
      this.updatePriority(job);
      if (this.hasActive(key) || this.pendingProofs.has(key) || job.due > Date.now()) protectedKeys.add(key);
      else if (this.eligible(job) && (isWorthAttempting(job.rawPriority, this.connectionRate(job, rates), this.minExpectedReturn) || isWorthAttempting(job.rawPriority, 5, this.minExpectedReturn))) candidates.push({ key, job });
    }
    let incoming = 0;
    for (const bounty of bounties) {
      if (!validBounty(bounty)) continue;
      const key = keyOf(bounty);
      if (seen.has(key) || this.completed.has(key) || this.hasActive(key)) continue;
      seen.add(key);
      let factor = this.factors.get(key);
      if (factor === undefined) {
        if (this.factors.size >= 100000) continue;
        factor = PRIORITY_FACTOR_SCALE + this.drawIndex(PRIORITY_FACTOR_MAX - PRIORITY_FACTOR_SCALE + 1); this.factors.set(key, factor);
      }
      const proof = this.pendingProofs.get(key);
      const job = { bounty, factor, due: proof?.due ?? 0, failures: proof?.failures ?? 0,
        winner: Boolean(proof), diagnosticId: ++this.nextDiagnosticId, prepared: this.proposals.get(key) };
      this.updatePriority(job);
      if (!proof && (job.budgetExceeded || (!isWorthAttempting(job.rawPriority, this.connectionRate(job, rates), this.minExpectedReturn) && !isWorthAttempting(job.rawPriority, 5, this.minExpectedReturn)))) continue;
      candidates.push({ key, job, fresh: true }); incoming++;
    }
    let count = 0;
    if (incoming) {
      for (const candidate of candidates) candidate.score = this.economicScore(candidate.job, rates);
      // An already-verified proof keeps its admission slot across a coherent
      // catalog rebuild, even when higher-paying new TLS candidates arrive.
      candidates.sort((a, b) => Number(this.pendingProofs.has(b.key)) - Number(this.pendingProofs.has(a.key)) || b.score - a.score || compareClaimPriority(a.job, b.job));
      const ordinary = candidates.filter(({ job }) => job.winner || isWorthAttempting(job.rawPriority, this.connectionRate(job, rates), this.minExpectedReturn));
      const recovery = this.recoveryCandidates([...candidates, ...[...protectedKeys].map(key => ({ key, job: this.queue.get(key) }))], rates)
        .filter(({ key }) => !protectedKeys.has(key));
      const slots = Math.max(0, this.maxQueue - protectedKeys.size);
      // Reserve a small bounded part of admission for formerly viable domains;
      // a full normal queue must not permanently prevent recovery observations.
      const proofSlots = ordinary.filter(({ key }) => this.pendingProofs.has(key)).length;
      const probeSlots = Math.min(recovery.length, MAX_RECOVERY_POLICIES, Math.max(1, Math.floor(this.maxQueue / 10)), Math.max(0, slots - Math.max(proofSlots, Number(ordinary.length > 0))));
      const selected = [...ordinary.slice(0, slots - probeSlots), ...recovery.slice(0, probeSlots)];
      const retained = new Set([...protectedKeys, ...selected.map(item => item.key)]);
      for (const [key, job] of this.queue) if (!retained.has(key)) { this.queue.delete(key); this.waitingPrepare.delete(job); }
      for (const { key, job, fresh } of selected) if (fresh) { job.bounty = structuredClone(job.bounty); this.queue.set(key, job); count++; }
    }
    this.dirty = true; if (count) this.notify(); this.kick(); return count;
  }
  retainCatalog(rows) {
    const keys = new Set(), masks = new Set(), domains = new Set();
    for (const row of rows) { keys.add(keyOf(row)); masks.add(`${row.domain}:${row.signature_algorithms_mask}`); domains.add(row.domain); }
    for (const key of this.activeKeys()) {
      keys.add(key); const job = this.queue.get(key) ?? [...this.connections.values()].find(item => keyOf(item.job.bounty) === key)?.job;
      if (job) { masks.add(`${job.bounty.domain}:${job.bounty.signature_algorithms_mask}`); domains.add(job.bounty.domain); }
    }
    for (const map of [this.factors, this.successCounts, this.proposals, this.pendingProofs]) for (const key of map.keys()) if (!keys.has(key)) map.delete(key);
    for (const key of this.domainStats.keys()) if (!masks.has(key)) this.domainStats.delete(key);
    for (const domain of this.dns.keys()) if (!domains.has(domain)) this.dns.delete(domain);
    for (const domain of this.waitingDns) if (!domains.has(domain)) this.waitingDns.delete(domain);
    this.connectionPolicy.retain(masks);
  }
  recordAttemptStats(job, snapshot, previousCompleted) {
    // Legacy tooling only. Production observes every protocol-4 validation result.
    // A truncated snapshot cannot reconstruct an EMA: never silently drop
    // missing observations as the former last-100 window permitted.
    validateAttemptStats(snapshot, Number.MAX_SAFE_INTEGER);
    if (!Number.isSafeInteger(previousCompleted) || previousCompleted < 0 ||
        snapshot.completed < previousCompleted || snapshot.completed - previousCompleted > snapshot.recent.length) {
      throw new Error('Invalid helper attempt sequence');
    }
    const key = `${job.bounty.domain}:${job.bounty.signature_algorithms_mask}`;
    const stats = this.domainStats.get(key) ?? new P2CDomainStats(); this.domainStats.set(key, stats);
    const first = snapshot.completed - snapshot.recent.length;
    for (let i = Math.max(0, previousCompleted - first); i < snapshot.recent.length; i++) stats.record(...snapshot.recent[i]);
    return snapshot.completed;
  }
  remove(txid, vout) {
    const key = `${txid}:${vout}`, job = this.queue.get(key); this.queue.delete(key); this.scheduler.remove(key);
    this.pendingProofs.delete(key);
    if (job) { job.unavailable = true; this.cancelOperation(job.prepareController, 'unavailable'); this.cancelOperation(job.submitController, 'unavailable'); this.waitingPrepare.delete(job); }
    let cancelled = false;
    for (const request of this.connections.values()) if (keyOf(request.job.bounty) === key) { request.job.unavailable = true; this.cancelOperation(request.controller, 'unavailable'); cancelled = true; }
    if (this.compatActiveKey === key && this.compatController && !this.compatController.signal.aborted) { this.compatController.abort(); cancelled = true; }
    if (job || cancelled) this.notify(); this.kick();
  }
  retire(txid, vout) {
    const key = `${txid}:${vout}`, job = this.queue.get(key);
    if (!job || job.retired) return;
    job.retired = true; this.scheduler.remove(key);
    if (!job.submitting) this.pendingProofs.delete(key);
    // Normal window exit does not cancel captures already on the wire.
    for (const request of this.connections.values()) if (request.job === job && !request.started) this.cancelOperation(request.controller, 'window-exit');
    if (!this.hasActive(key)) this.queue.delete(key);
    this.notify(); this.kick();
  }
  clear({ preserveSelection = false } = {}) {
    this.startIdle = true;
    for (const job of this.queue.values()) job.unavailable = true;
    this.queue.clear(); this.completed.clear();
    this.recoveryJobs.clear();
    this.waitingPrepare.clear(); this.waitingDns.clear();
    for (const controller of this.controllers) this.cancelOperation(controller, 'clear');
    this.scheduler.clear({ preserveSelection }); this.dirty = true;
    if (!preserveSelection) { this.factors.clear(); this.successCounts.clear(); this.proposals.clear(); this.pendingProofs.clear(); this.domainStats.clear(); this.connectionPolicy.clear(); }
    // A catalog resync keeps both activity totals. A full context reset must
    // clear both together so the UI never compares counters from different periods.
    this.notify(preserveSelection ? {} : { completed: 0, attempts: 0 });
  }
  setOptions(options) {
    if (this.enabled || this.running || this.stopping) throw new Error('Stop Automatic Claims before changing connection limits');
    this.options = validateConnectionOptions(options); this.notify();
  }
  start() {
    if (!this.isUnlocked()) throw new Error('Unlock the wallet before starting Automatic Claims');
    if (this.stopping) throw new Error('Wait for the previous claims worker to stop');
    this.enabled = true;
    const newRun = this.beginDiagnosticRun();
    this.refreshTimer ??= setInterval(() => { this.reportProgress(); if (this.enabled && !this.paused) { this.dirty = true; this.kick(); } }, DIAGNOSTIC_INTERVAL_MS);
    this.refreshTimer.unref?.();
    if (newRun) report(this.onDiagnostic, 'claims.started', this.diagnosticSnapshot());
    this.notify({ status: 'waiting', lastError: null }); this.kick();
  }
  stop(reason = 'stop') { this.enabled = false; this.paused = false; return this.halt('off', reason === 'locked' ? 'locked' : 'stop'); }
  suspend() {
    if (this.paused && !this.running && !this.pool) return this.stopping ?? Promise.resolve();
    this.paused = true; return this.halt(this.enabled ? 'waiting' : 'off', 'suspend');
  }
  halt(status, reason = 'stop') {
    clearTimeout(this.timer); this.timer = null;
    if (!this.enabled) { clearInterval(this.refreshTimer); this.refreshTimer = null; }
    if (this.haltReason !== 'fatal') this.haltReason = reason;
    if (this.stopping) return this.stopping;
    this.generation++;
    for (const controller of this.controllers) this.cancelOperation(controller, reason);
    const pool = this.pool; this.pool = null; this.poolReady = null;
    this.notify({ status, domain: null });
    const pending = (async () => {
      await pool?.close();
      while (this.tasks.size || this.coordinator) await Promise.allSettled([...this.tasks, ...(this.coordinator ? [this.coordinator] : [])]);
    })();
    this.stopping = pending.finally(() => {
      this.stopping = null; this.dns.clear(); this.scheduler.domainGates.clear();
      this.pendingStarts.clear(); this.pendingRecovery.clear(); this.nextStart = 0; this.startIdle = true;
      for (const job of this.waitingPrepare) job.waitingPrepare = false;
      this.waitingPrepare.clear(); this.waitingDns.clear(); this.dirty = true;
      const reason = this.haltReason; this.haltReason = null;
      if (this.diagnosticRun) {
        const event = this.enabled ? 'claims.suspended' : 'claims.stopped';
        const details = { ...this.diagnosticSnapshot(), reason };
        if (!this.enabled) this.diagnosticRun = null;
        report(this.onDiagnostic, event, details);
      }
    });
    return this.stopping;
  }
  resume() {
    const wasPaused = this.paused; this.paused = false; this.dirty = true;
    if (wasPaused && this.diagnosticRun) report(this.onDiagnostic, 'claims.resumed', this.diagnosticSnapshot());
    this.kick();
  }
  schedule(delay) {
    if (!this.enabled || this.paused || this.stopping || !Number.isFinite(delay)) return;
    clearTimeout(this.timer); this.timer = setTimeout(() => { this.timer = null; this.kick(); }, Math.max(1, delay)); this.timer.unref?.();
  }
  kick() {
    if (!this.enabled || this.paused || this.stopping) return;
    if (this.coordinator) { this.wakeRequested = true; return; }
    if (!this.isUnlocked()) { void this.stop('locked'); this.notify({ status: 'locked' }); return; }
    clearTimeout(this.timer); this.timer = null;
    const generation = this.generation;
    const operation = Promise.resolve().then(() => this.pump(generation)).catch(error => {
      if (generation === this.generation || error.unknownOutcome) this.fatal(error);
    });
    this.coordinator = operation.finally(() => {
      this.coordinator = null;
      if (this.wakeRequested) { this.wakeRequested = false; this.kick(); }
    });
  }
  async pump(generation) {
    if (!this.enabled || this.paused || generation !== this.generation) return;
    if (!this.pool) {
      let pool;
      const onFailure = error => queueMicrotask(() => {
        // A helper can die while idle, when no request promise will reject.
        // Old helpers must not stop a restarted/resumed engine generation.
        if (this.pool === pool && generation === this.generation && this.enabled && !this.paused) this.fatal(error);
      });
      pool = this.poolFactory({ onFailure }); this.pool = pool;
      this.poolReady = pool.start(this.options);
      await this.poolReady;
    } else await this.poolReady;
    if (!this.enabled || this.paused || generation !== this.generation) return;
    this.retrySubmissions(generation);
    for (let checked = 0; checked < this.maxQueue + 8; checked++) {
      // At least two pending starts let one slow admission be bypassed. The
      // lookahead is bounded independently of active captures: at 1/s, never
      // queue hundreds of requests behind the helper's 45-second IPC deadline.
      // Only the production/helper contract guarantees socket pacing. Legacy
      // adapters without that gate retain their single-start handshake: pacing
      // dispatch alone could let delayed starts bunch together above the limit.
      const pendingLimit = this.pool.pacesStarts ? Math.min(this.options.concurrency, MAX_PENDING_STARTS, Math.max(2,
        Math.ceil(this.options.connectionsPerSecond * START_LOOKAHEAD_MS / 1000))) : 1;
      if (this.pendingStarts.size >= pendingLimit || this.connections.size >= this.options.concurrency) {
        // Cancelled requests can still occupy capacity while their callbacks
        // drain. They cannot bridge an idle period into the next live run.
        if (!this.pool.pacesStarts && [...this.connections.values()].every(request => request.controller.signal.aborted)) this.startIdle = true;
        this.schedule(this.nextProofDue() - Date.now()); return;
      }
      const selection = this.nextReady();
      if (!selection) {
        // No runnable or live capture demand: idle time does not earn credit.
        // Capacity/ACK waits above retain the shared phase instead.
        if (![...this.connections.values()].some(request => !request.controller.signal.aborted)) this.startIdle = true;
        this.notify({ status: 'waiting' }); this.schedule(Math.min(this.scheduler.nextDue(), this.nextProofDue()) - Date.now()); return;
      }
      const [key, job] = selection;
      if (!this.ready(job)) { this.scheduler.remove(key); continue; }
      if (!job.prepared) {
        if (this.preparing.size >= 4) {
          job.waitingPrepare = true; this.waitingPrepare.add(job); this.scheduler.setReady(key, false); continue;
        }
        this.prepareJob(job, generation); continue;
      }
      const dns = this.dns.get(job.bounty.domain);
      if (!dns || dns.expires <= Date.now()) {
        if (this.resolving.size >= 2) {
          this.waitingDns.add(job.bounty.domain); this.scheduler.setDomainReady(job.bounty.domain, false); continue;
        }
        this.resolveJob(job, generation); continue;
      }
      if (!dns.ok) { this.scheduler.setDomainReady(job.bounty.domain, true, { due: dns.expires }); continue; }
      const delay = this.nextStart - performance.now();
      if (delay > 0) { this.schedule(delay); return; }
      this.dispatch(selection, generation);
    }
  }
  cachePrepared(key, prepared) {
    if (!this.proposals.has(key) && this.proposals.size >= 256) {
      const old = [...this.proposals.keys()].find(candidate => !this.hasActive(candidate) && !this.pendingProofs.has(candidate) && !this.queue.get(candidate)?.winner);
      if (!old) return false;
      this.proposals.delete(old); const idle = this.queue.get(old); if (idle) idle.prepared = undefined;
    }
    this.proposals.delete(key); this.proposals.set(key, prepared); return true;
  }
  prepareJob(job, generation) {
    const key = keyOf(job.bounty), controller = new AbortController();
    const operation = this.beginOperation('prepare', controller);
    const operationStarted = performance.now();
    job.preparing = true; job.prepareController = controller;
    this.preparing.add(job); this.controllers.add(controller); this.scheduler.setReady(key, false);
    const task = Promise.resolve().then(async () => {
      const prepared = await this.prepare(structuredClone(job.bounty), { signal: controller.signal, previous: this.proposals.get(key) });
      if (controller.signal.aborted || generation !== this.generation || !this.enabled || this.paused || this.queue.get(key) !== job || job.unavailable || job.retired) throw claimAborted();
      const context = validateClaimContext(prepared.context);
      if (prepared.bounty && keyOf(prepared.bounty) !== key) throw new Error('Prepared claim refers to a different bounty');
      const oldPriority = job.priority, oldDomain = job.bounty.domain, oldMask = job.bounty.signature_algorithms_mask;
      job.bounty = { ...job.bounty, domain: context.domain, connection_work_target: context.connection_work_target,
        signature_algorithms_mask: context.signature_algorithms_mask, root_certificates_version: context.root_certificates_version,
        ...(prepared.bounty?.amount === undefined ? {} : { amount: prepared.bounty.amount }) };
      if (!this.cachePrepared(key, prepared)) throw new Error('All prepared claim slots are active');
      job.prepared = prepared; this.updatePriority(job);
      if (oldPriority !== job.priority || oldDomain !== job.bounty.domain || oldMask !== job.bounty.signature_algorithms_mask) this.dirty = true;
    }).catch(error => {
      this.finishOperation(operation, error.name === 'AbortError' && !error.unknownOutcome ? 'cancelled' : 'failed');
      this.jobError(job, error, 'prepare', true, { durationMs: Math.round(performance.now() - operationStarted), attempts: 0 });
    }).finally(() => {
      this.finishOperation(operation);
      job.preparing = false; job.prepareController = null; this.preparing.delete(job); this.controllers.delete(controller);
      if (this.queue.get(key) === job && this.ready(job) && this.attemptable(job)) this.scheduler.setReady(key, true, { due: this.jobDue(job) });
      else this.scheduler.remove(key);
      this.releasePreparationSlot();
    });
    void this.track(job, task);
  }
  resolveJob(job, generation) {
    const domain = job.bounty.domain, controller = new AbortController();
    const operation = this.beginOperation('dns', controller);
    this.resolving.add(domain); this.controllers.add(controller); this.scheduler.setDomainReady(domain, false);
    const pool = this.pool;
    const task = Promise.resolve().then(() => pool.resolve(domain, { signal: controller.signal })).then(() => {
      if (controller.signal.aborted || generation !== this.generation) return;
      this.dns.set(domain, { ok: true, expires: Date.now() + 60000 }); this.scheduler.setDomainReady(domain, true);
    }).catch(error => {
      this.finishOperation(operation, error.name === 'AbortError' && !error.unknownOutcome ? 'cancelled' : 'failed');
      if (error.name !== 'AbortError') this.sampleDiagnostic('claim.failed', { stage: 'dns', claimId: job.diagnosticId, error,
        durationMs: Math.round(performance.now() - operation.started), attempts: 0 });
      if (error.helperFatal) this.fatal(error);
      if (controller.signal.aborted || generation !== this.generation) return;
      const expires = Date.now() + 2000; this.dns.set(domain, { ok: false, expires }); this.scheduler.setDomainReady(domain, true, { due: expires });
    }).finally(() => { this.finishOperation(operation); this.resolving.delete(domain); this.controllers.delete(controller); this.releaseDnsSlot(); });
    void this.track(job, task);
  }
  observe(request, observation) {
    if (request.observed) throw new Error('Duplicate connection observation');
    request.observed = true;
    const { job } = request, key = keyOf(job.bounty);
    if (observation.captured) {
      this.countDiagnostic('captures');
      const count = this.successCounts.get(key) ?? 0n;
      // The raw-capture budget is independent of the validated domain EMA. Replies
      // from parallel workers may arrive out of order, so never add it twice.
      const observed = observation.successfulConnections === undefined
        ? (count < MAX_P2C_SUCCESSFUL_CONNECTIONS ? count + 1n : count)
        : BigInt(observation.successfulConnections);
      this.successCounts.set(key, observed > count ? observed : count);
      job.budgetExceeded = isP2CClaimConnectionLimitExceeded(job.bounty.connection_work_target, this.successCounts.get(key));
      if (job.budgetExceeded) this.scheduler.remove(key); // Keep already-running attempts alive.
    }
  }
  observeResult(request, result) {
    if (request.resultObserved) throw new Error('Duplicate connection validation observation');
    request.resultObserved = true;
    if (![true, false, null].includes(result.validationPassed) ||
        typeof result.seconds !== 'number' || !Number.isFinite(result.seconds) || result.seconds < 0 || result.seconds > 3600 ||
        (result.validationPassed !== null && !result.started) ||
        (result.validationPassed === true && !result.captured) ||
        (result.validationPassed === null && result.started && !result.cancelled)) {
      throw new Error('Invalid connection validation observation');
    }
    // Null means no conclusive observation, e.g. cancellation before validation.
    // A target miss is still true: work probability already enters rawPriority.
    if (result.validationPassed === null) return;
    const { job } = request;
    const domainMask = `${job.bounty.domain}:${job.bounty.signature_algorithms_mask}`;
    const stats = this.domainStats.get(domainMask) ?? new P2CDomainStats(); this.domainStats.set(domainMask, stats);
    stats.record(result.validationPassed, result.seconds);
  }
  dispatch(selection, generation) {
    const [key, job] = selection;
    const recoveryProbe = !isWorthAttempting(job.rawPriority, this.connectionRate(job), this.minExpectedReturn);
    if (recoveryProbe) {
      if (!job.recoveryProbe || !isWorthAttempting(job.rawPriority, 5, this.minExpectedReturn)) { this.dirty = true; this.wakeRequested = true; return; }
      if (this.pendingRecovery.has(policyOf(job))) {
        this.scheduler.setReady(key, false); return;
      }
      // A delayed TCP-start acknowledgement may belong to a different bounty
      // than the current probe representative. Consult policy state, not the
      // representative's cached deadline, before spending another connection.
      job.probeDue = this.connectionPolicy.probeDue(policyOf(job));
      if (job.probeDue > Date.now()) {
        this.scheduler.setReady(key, this.ready(job), { due: this.jobDue(job) });
        this.wakeRequested = true; return;
      }
    }
    const controller = new AbortController(), token = ++this.nextToken;
    const context = validateClaimContext({ ...job.prepared.context, ...(this.getValidationTime ? { validation_time: this.getValidationTime() } : {}) });
    const request = { job, controller, token, generation, policy: policyOf(job), started: false, observed: false, recoveryProbe };
    const operation = this.beginOperation('capture', controller);
    this.connections.set(token, request); this.controllers.add(controller); this.pendingStarts.add(token);
    if (recoveryProbe) {
      this.pendingRecovery.set(request.policy, request); this.scheduler.setReady(key, false);
    }
    // Reserve turns in dispatch order, not callback arrival order. A failure
    // before TCP spends no attempt/EMA/probe cooldown, but cannot rewind turns
    // already reserved by other concurrent requests.
    this.scheduler.commit(selection);
    const pool = this.pool;
    let stage = 'proof', operationStarted = performance.now();
    const valid = () => generation === this.generation && this.enabled && !this.paused && this.isUnlocked() && !controller.signal.aborted && !job.unavailable && this.queue.get(key) === job;
    const task = Promise.resolve().then(() => pool.attempt(context, { bountyId: key, successfulConnections: this.successCounts.get(key) ?? 0n, signal: controller.signal,
      onStarted: () => {
        if (request.started) throw new Error('Duplicate connection start');
        this.countDiagnostic('attempts');
        request.started = true;
        if (request.recoveryProbe) {
          job.probeDue = this.connectionPolicy.probeStarted(request.policy);
        }
        this.releaseStart(request);
        // Never add a second JavaScript timer to the production helper's own
        // high-resolution socket gate. Only legacy/offline adapters need it.
        if (generation === this.generation) {
          if (pool.pacesStarts) this.nextStart = 0;
          else {
            const now = performance.now();
            if (this.startIdle) this.nextStart = Math.max(this.nextStart, now);
            this.nextStart = Math.max(this.nextStart + 1000 / this.options.connectionsPerSecond, now - 1000);
            // Count late real starts, but cancelled old work must not consume
            // the pending idle reset belonging to the next live admission.
            if (!controller.signal.aborted && !job.unavailable && this.queue.get(key) === job) this.startIdle = false;
          }
        }
        this.notify({ attempts: this.state.attempts + 1,
          ...(generation === this.generation && this.enabled && !this.paused
            ? { status: 'searching', domain: context.domain, lastError: null } : {}) }); this.kick();
      },
      onCapture: observation => this.observe(request, observation),
      onResult: result => this.observeResult(request, result),
    })).then(async result => {
      // Offline/custom adapters may return the terminal result without a callback.
      if (!request.resultObserved) this.observeResult(request, result);
      this.finishOperation(operation, !valid() || result.cancelled ? 'cancelled' : result.message ? 'failed' : 'completed');
      if (!valid()) return;
      if (result.blocked === 'budget') { job.budgetExceeded = true; this.scheduler.remove(key); return; }
      if (!result.started) { this.dns.delete(job.bounty.domain); return; }
      if (result.proof && result.verified === true && !job.winner) {
        job.winner = true; this.scheduler.remove(key);
        this.pendingProofs.set(key, { proof: result.proof, context, due: 0, failures: 0 });
        for (const sibling of this.connections.values()) if (sibling !== request && sibling.job === job) this.cancelOperation(sibling.controller, 'sibling-proof');
        stage = 'submit';
        if (!valid()) return;
        await this.submitVerified(job, controller, generation);
      } else {
        if (result.message && !result.cancelled) this.jobError(job, new Error(result.message), stage, false,
          { durationMs: Math.round(performance.now() - operationStarted), attempts: 1 });
        if (!result.captured && !result.cancelled) await this.pauseWorker(controller.signal);
      }
    }).catch(async error => {
      this.finishOperation(operation, error.name === 'AbortError' && !error.unknownOutcome ? 'cancelled' : 'failed');
      if (error.helperFatal || error.unknownOutcome) { this.fatal(error); return; }
      if (error.name !== 'AbortError') {
        const details = { durationMs: Math.round(performance.now() - operationStarted), attempts: request.started ? 1 : 0 };
        if (stage === 'proof') { this.jobError(job, error, stage, false, details); await this.pauseWorker(controller.signal); }
        else { this.jobError(job, error, stage, true, details); this.dirty = true; }
      }
    }).finally(() => {
      this.finishOperation(operation);
      this.releaseStart(request);
      this.connections.delete(token); this.controllers.delete(controller);
    });
    void this.track(job, task);
  }
  releaseStart(request) {
    this.pendingStarts.delete(request.token);
    const policy = request.policy;
    if (this.pendingRecovery.get(policy) !== request) return;
    this.pendingRecovery.delete(policy);
    const representative = this.recoveryJobs.get(policy);
    if (representative && request.generation === this.generation) {
      // A catalog refresh may replace the reserved bounty, not its policy.
      representative.probeDue = this.connectionPolicy.probeDue(policy);
      this.scheduler.setReady(keyOf(representative.bounty), this.ready(representative), { due: this.jobDue(representative) });
    }
  }
  nextProofDue() {
    if (this.submitting.size >= 4) return Infinity; // A completion will wake queued submissions.
    let due = Infinity;
    for (const [key, pending] of this.pendingProofs) {
      const job = this.queue.get(key);
      if (job && !job.retired && !job.unavailable && !job.submitting) due = Math.min(due, pending.due);
    }
    return due;
  }
  releasePreparationSlot() {
    for (const job of this.waitingPrepare) {
      this.waitingPrepare.delete(job); job.waitingPrepare = false;
      const key = keyOf(job.bounty);
      if (this.queue.get(key) !== job || !this.ready(job)) continue;
      if (this.scheduler.setReady(key, true, { due: this.jobDue(job) }) && this.jobDue(job) <= Date.now()) break;
    }
  }
  releaseDnsSlot() {
    for (const domain of this.waitingDns) {
      this.waitingDns.delete(domain);
      // Remove a remembered closed gate even if a rebuild excluded all of its
      // candidates. Otherwise a later eligible candidate would stay stuck.
      this.scheduler.domainGates.delete(domain);
      if (this.scheduler.setDomainReady(domain, true) && this.scheduler.groups.get(domain)?.ready.total) break;
    }
  }
  retrySubmissions(generation) {
    // At most 256 cached proposals. A proof retry never spends a TLS slot or
    // resets the successful-capture budget/challenge.
    for (const [key, pending] of this.pendingProofs) {
      if (this.submitting.size >= 4) return;
      const job = this.queue.get(key);
      if (!job || job.retired || job.unavailable || job.submitting || pending.due > Date.now()) continue;
      const controller = new AbortController(); this.controllers.add(controller);
      const task = this.submitVerified(job, controller, generation).finally(() => this.controllers.delete(controller));
      void this.track(job, task);
    }
  }
  async submitVerified(job, controller, generation) {
    const key = keyOf(job.bounty), pending = this.pendingProofs.get(key);
    // Fresh winners and retries share the same RPC budget. Keep excess verified
    // proofs queued; completing a submission wakes the coordinator to drain them.
    if (job.submitting || this.submitting.size >= 4 || !pending || generation !== this.generation || !this.enabled || this.paused || controller.signal.aborted ||
        job.unavailable || !this.isUnlocked() || this.queue.get(key) !== job) return;
    const started = performance.now(); job.submitting = true; job.submitController = controller; this.submitting.add(job);
    const operation = this.beginOperation('submit', controller);
    this.notify({ status: 'submitting' });
    try {
      const receipt = await this.submit(job.prepared, pending.proof, { signal: controller.signal });
      this.completed.add(key); if (this.completed.size > this.maxQueue) this.completed.delete(this.completed.values().next().value);
      this.queue.delete(key); this.proposals.delete(key); this.pendingProofs.delete(key);
      this.finishOperation(operation, 'completed'); this.countDiagnostic('completed');
      // durationMs measures this submit operation only, not preparation/capture
      // or queue time. Aggregated progress counts every success, even if sampled.
      this.sampleDiagnostic('claim.succeeded', { stage: 'submit', claimId: job.diagnosticId, completed: this.state.completed + 1,
        durationMs: Math.round(performance.now() - started), attempts: 1 });
      this.notify({ status: this.enabled ? 'claimed' : 'off', completed: this.state.completed + 1,
        ...(this.enabled && generation === this.generation ? { lastError: null } : {}),
        lastClaim: typeof receipt === 'string' ? receipt : receipt?.txid ?? pending.context.txid });
    } catch (error) {
      this.finishOperation(operation, error.name === 'AbortError' && !error.unknownOutcome ? 'cancelled' : 'failed');
      if (error.unknownOutcome || error.helperFatal) { this.fatal(error); return; }
      if (job.retired || job.unavailable) this.pendingProofs.delete(key);
      if (error.name !== 'AbortError') {
        this.jobError(job, error, 'submit', true, { durationMs: Math.round(performance.now() - started), attempts: 1 });
        pending.due = job.due; pending.failures = job.failures;
      }
    } finally { this.finishOperation(operation); job.submitting = false; job.submitController = null; this.submitting.delete(job); }
  }
  pauseWorker(signal) {
    if (signal.aborted) return Promise.resolve();
    return new Promise(resolve => {
      const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve(); };
      const timer = setTimeout(finish, 1000); signal.addEventListener('abort', finish, { once: true });
    });
  }
  jobError(job, error, stage, backoff = true, details = {}) {
    if (error.name === 'AbortError') return;
    if (backoff) { job.failures = Math.min(job.failures + 1, 8); job.due = Date.now() + Math.min(this.retryDelayMs * 2 ** (job.failures - 1), 300000); }
    this.sampleDiagnostic('claim.failed', { stage, claimId: job.diagnosticId, error, failures: job.failures,
      retryDelayMs: backoff ? Math.max(0, job.due - Date.now()) : 1000, ...details });
    // Other in-flight jobs can fail during teardown. Keep their diagnostics,
    // but do not replace the fatal/unknown-broadcast warning with a retry alert.
    if (this.haltReason === 'fatal') return;
    const diagnostic = stage === 'proof' ? diagnosticError(error) : null;
    const connectionTimeout = diagnostic?.category === 'tls-timeout';
    this.notify({ status: this.enabled ? 'retrying' : 'off',
      lastError: connectionTimeout ? diagnostic.message : String(error.message ?? error).slice(0, 500),
      lastErrorCategory: connectionTimeout ? 'tls-timeout' : null,
      lastErrorTransient: true, lastErrorDiagnostic: stage === 'submit' && isKnownClaimRejection(error) });
  }
  fatal(error) {
    // Cancellation can reveal that an in-flight broadcast has an unknown
    // outcome. That warning must supersede a helper failure, even during drain.
    if (!this.enabled && this.haltReason === 'fatal' && !error.unknownOutcome) return;
    if (error.name === 'AbortError' && !error.unknownOutcome && (!this.enabled || this.paused)) return;
    this.enabled = false; // Close the gate before diagnostics or any other callback.
    // Fatal/unknown-broadcast events bypass sampling. Their original safe error
    // classification remains available even when an error burst fills samples.
    if (this.diagnosticRun) {
      report(this.onDiagnostic, 'claims.failed', { ...this.diagnosticSnapshot(), reason: 'fatal', error });
    }
    this.notify({ status: 'off', lastError: String(error.message ?? error).slice(0, 500) });
    void this.halt('off', 'fatal');
  }
}
