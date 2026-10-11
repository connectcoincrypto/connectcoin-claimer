import { resolve } from 'node:path';
import { RpcClient } from './core/rpc.mjs';
import { validateTip } from './core/config.mjs';
import { ClaimsEngine } from './core/claims-engine.mjs';
import { ConnectionPool } from './core/claim-pool.mjs';
import { isKnownClaimRejection } from './core/claims.mjs';
import { discoverBounties, readBountyBlock, bountyKey } from './core/bounty-discovery.mjs';
import { prepareClaim, attachClaimProof, estimateClaimFee, transactionIdFromRaw } from './core/transaction.mjs';
import { BroadcastJournal, transactionDigest } from './broadcast-journal.mjs';
import { deferredBroadcast, validateSavedClaim, validateObservedClaim } from './broadcast-recovery.mjs';
import { diagnosticError } from './core/diagnostics.mjs';
import { ClaimMetrics } from './metrics.mjs';

const aborted = () => Object.assign(new Error('Claimer stopped or its RPC connection changed.'), { name: 'AbortError', code: 'ABORT_ERR', notSent: true });
const transient = error => [-32001, -32002, -32029, -32030].includes(error?.code) ||
  ['ECONNRESET', 'ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE'].includes(error?.code) ||
  /^(?:Cannot connect to RPC|RPC connection timed out\.|RPC request timed out\.|Connection to the RPC server was lost\.|RPC connection is closed\.|RPC connection closed before connecting\.)/.test(error?.message ?? '');

/** Address-only orchestration. No wallet, private key, or local Core RPC is involved. */
export class ClaimerService {
  constructor({ config, basePath = process.cwd(), statePath = resolve(basePath, 'claimer.conf.state.json'), emit = () => {},
    rpcFactory = options => new RpcClient(options), engineFactory = options => new ClaimsEngine(options), poolFactory,
    journal = new BroadcastJournal(statePath), discover = discoverBounties, readBlock = readBountyBlock,
    prepare = prepareClaim, attach = attachClaimProof, transactionId = transactionIdFromRaw,
    validateSaved = validateSavedClaim, validateObserved = validateObservedClaim,
    pollMs = 5000, retryMinMs = 1000, retryMaxMs = 30000, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
    Object.assign(this, { config, basePath, statePath, emit, journal, discover, readBlock, prepareTransaction: prepare,
      attachProof: attach, transactionId, validateSaved, validateObserved, pollMs, retryMinMs, retryMaxMs, setTimer, clearTimer });
    this.running = false; this.started = false; this.ready = false; this.epoch = 0; this.failures = 0;
    this.status = 'stopped'; this.lastError = null; this.fatalError = null; this.tip = null;
    this.blocks = new Map(); this.outpoints = new Map(); this.cursor = null; this.reserved = new Set();
    this.catalogGate = null;
    this.fundingCache = new Map(); this.fundingPending = new Map(); this.ioAbort = new AbortController();
    this.metrics = new ClaimMetrics();
    this.timer = null; this.cycling = null; this.suspending = null; this.stopping = null;
    this.inFlightBroadcasts = new Set(); this.recoveryDue = new Map(); this.recoveryBlocked = new Set();
    this.recoveryTimer = null; this.recovering = null;
    this.rpc = rpcFactory({ ...config.rpc, quota: 48, timeoutMs: 40000, onDiagnostic: (event, details) => {
      if (event !== 'rpc.failed') return;
      this.report('rpc-diagnostic', { event, method: details.method, stage: details.stage,
        error: diagnosticError(details.error), unknownOutcome: details.unknownOutcome === true,
        notSent: details.notSent === true, sent: details.sent === true, failureSource: details.failureSource });
    } });
    this.engine = engineFactory({
      prepare: (bounty, options) => this.prepare(bounty, options),
      submit: (prepared, proof, options) => this.submit(prepared, proof, options),
      isUnlocked: () => this.running && !this.fatalError,
      getNetReward: bounty => BigInt(bounty.amount) - BigInt(estimateClaimFee(config.feeRate)),
      getValidationTime: () => validateTip(this.tip, config.network).mediantime,
      minExpectedReturn: config.minExpectedReturn,
      options: { connectionsPerSecond: config.connectionsPerSecond, concurrency: config.concurrency },
      poolFactory: options => this.metrics.wrap(poolFactory ? poolFactory(options) : new ConnectionPool({ basePath, ...options })),
      stateNotifications: false,
      onState: state => { this.claimState = state; },
      onDiagnostic: (event, details) => {
        if (event === 'claims.failed') this.fail(details.error ?? new Error('The claims engine stopped unexpectedly.'));
      },
    });
    this.onDisconnected = () => this.disconnected();
    this.rpc.on('disconnected', this.onDisconnected);
  }

  report(event, details) { try { Promise.resolve(this.emit(event, details)).catch(() => {}); } catch { /* UI cannot affect claims. */ } }
  publish() { this.report('state', this.snapshot()); }
  snapshot() {
    // Only engines explicitly advertising pull mode use this path. Injected
    // engines that ignore the option retain the existing onState contract.
    const claims = this.engine.stateNotifications === false && typeof this.engine.snapshot === 'function'
      ? this.engine.snapshot() : this.claimState;
    return { status: this.status, running: this.running, ready: this.ready, height: this.tip?.height ?? null,
      available: [...this.outpoints.values()].filter(row => row.status === 'available' && !this.reserved.has(bountyKey(row))).length,
      reserved: this.reserved.size, lastError: this.lastError, reviewRequired: Boolean(this.fatalError?.unknownOutcome) || this.recoveryBlocked.size > 0,
      unresolvedBroadcasts: this.journal.loaded ? this.journal.unresolved().length : 0,
      claims: { ...(claims ?? {}) }, metrics: this.metrics.snapshot() };
  }

  async start() {
    if (this.started) throw new Error('This claimer service has already been started.');
    this.started = true;
    const epoch = this.epoch;
    try {
      const entries = await this.journal.load();
      this.reserved = new Set(entries.map(row => row.outpoint));
      for (const row of this.journal.unresolved()) {
        if (!row.transactionHex || row.receivingAddress !== this.config.receivingAddress) this.recoveryBlocked.add(row.outpoint);
      }
      if (epoch !== this.epoch || this.stopping) throw aborted();
    } catch (error) {
      if (error.name !== 'AbortError' || !this.stopping) this.fail(error);
      throw error;
    }
    this.running = true; this.status = 'connecting'; this.publish();
    await this.cycle();
    if (this.fatalError) throw this.fatalError;
    return this.snapshot();
  }

  check(epoch, signal) {
    if (!this.running || this.fatalError || epoch !== this.epoch || signal?.aborted) throw aborted();
  }

  schedule(milliseconds) {
    if (!this.running || this.fatalError) return;
    if (this.timer !== null) this.clearTimer(this.timer);
    this.timer = this.setTimer(() => { this.timer = null; void this.cycle(); }, milliseconds);
    this.timer?.unref?.();
  }

  suspend() {
    this.ready = false;
    // Do not overwrite the stronger disconnect barrier (durable writes +
    // drain + old-epoch cleanup) with just the worker drain.
    return Promise.resolve(this.engine.suspend());
  }

  resetCatalog(details = {}) {
    // A missing journal interval requires a new coherent catalog, not a new
    // TLS worker. Keep validated captures/proofs and their accounting alive;
    // preparation and broadcast wait below until the atomic publication.
    this.ready = false;
    this.catalogGate ??= Promise.withResolvers();
    if (this.engine.enabled) this.status = 'resyncing';
    const reason = ['initial', 'journal-reset', 'data-unavailable', 'cursor-invalid'].includes(details.reason) ? details.reason : 'journal-reset';
    this.report('discovery-reset', { reason, ...([-32004, -32011].includes(details.code) ? { code: details.code } : {}) });
    this.publish();
  }

  cancelCatalogWaiters() {
    // Call after invalidating/aborting the RPC epoch on stop/disconnect/failure.
    // Waiters always recheck that epoch, so waking cannot admit stale work.
    const gate = this.catalogGate; this.catalogGate = null; gate?.resolve();
  }

  async waitForCatalog(epoch, signal) {
    this.check(epoch, signal);
    const waitingSignal = signal ? AbortSignal.any([signal, this.ioAbort.signal]) : this.ioAbort.signal;
    while (this.catalogGate) {
      const gate = this.catalogGate;
      await new Promise((accept, reject) => {
        const finish = error => { waitingSignal.removeEventListener('abort', cancel); if (error) reject(error); else accept(); };
        const cancel = () => finish(aborted());
        gate.promise.then(() => finish());
        if (waitingSignal.aborted) cancel(); else waitingSignal.addEventListener('abort', cancel, { once: true });
      });
      this.check(epoch, signal);
    }
  }

  disconnected() {
    if (!this.running || this.fatalError) return;
    this.epoch++; this.ioAbort.abort(); this.cancelCatalogWaiters(); this.ioAbort = new AbortController();
    this.tip = null; this.fundingCache.clear(); this.fundingPending.clear();
    this.status = 'reconnecting';
    const epoch = this.epoch;
    const saved = this.persistPendingProofs(), previous = this.suspending;
    this.suspending = Promise.all([previous, saved, this.suspend()]).then(async () => {
      // A submission finishing during drain can return its proof to the queue.
      await this.persistPendingProofs();
      if (!this.running || this.fatalError || epoch !== this.epoch) return;
      // Verified winners were transferred to the durable journal above. Other
      // proposals belong to the former RPC epoch and must be re-prepared.
      this.engine.clear({ preserveSelection: true });
      this.engine.proposals.clear(); this.engine.pendingProofs.clear();
    });
    void this.suspending.catch(error => this.fail(error));
    this.publish();
    if (!this.cycling) this.schedule(this.retryMinMs);
  }

  cycle() {
    if (!this.running || this.fatalError) return Promise.resolve();
    if (this.cycling) return this.cycling;
    const operation = this.runCycle();
    this.cycling = operation;
    void operation.finally(() => { if (this.cycling === operation) this.cycling = null; });
    return operation;
  }

  async runCycle() {
    let delay = this.pollMs;
    const epoch = this.epoch, signal = this.ioAbort.signal;
    const check = () => this.check(epoch, signal);
    try {
      await this.suspending; check();
      // An explicit connect allows ordinary transport errors to be retried while
      // malformed network identity or discovery data always stops the service.
      await this.rpc.connect(); check();
      const scopedRpc = { request: (method, params, options) => this.rpc.request(method, params, { ...options, signal }) };
      const result = await this.discover({ rpc: scopedRpc, network: this.config.network,
        lookback: this.config.lookbackBlocks, previous: this.blocks, cursor: this.cursor, check,
        onReset: async details => { check(); this.resetCatalog(details); },
        onInvalidate: (row, reason) => {
          if (reason === 'window_exit') this.engine.retire(row.txid, row.vout);
          else {
            this.engine.remove(row.txid, row.vout);
            const key = bountyKey(row), current = this.outpoints.get(key);
            if (current) this.outpoints.set(key, { ...current, status: 'unavailable' });
          }
        },
        onWindow: snapshot => {
          validateTip(snapshot.tip, this.config.network);
          const canonical = new Map(snapshot.blocks.map(block => [block.height, block.hash]));
          const selected = new Set(snapshot.blocks.slice(0, this.config.lookbackBlocks).map(block => block.hash));
          for (const [key, row] of this.outpoints) {
            const hash = canonical.get(row.block_height);
            if (row.block_height > snapshot.tip.height || (hash && hash !== row.block_hash)) {
              this.engine.remove(row.txid, row.vout); this.outpoints.delete(key);
            } else if (!selected.has(row.block_hash)) this.engine.retire(row.txid, row.vout);
          }
        },
        readBlock: (hash, options) => this.readBlock({ rpc: scopedRpc, network: this.config.network, hash, ...options }),
      });
      check();
      const tip = validateTip(result.tip, this.config.network), outpoints = new Map(), available = [];
      for (const rows of result.blocks.values()) for (const row of rows) {
        const key = bountyKey(row), previous = this.outpoints.get(key);
        if (previous && ['domain', 'amount', 'connection_work_target', 'root_certificates_version', 'signature_algorithms_mask']
          .some(field => previous[field] !== row[field])) throw new Error('Bounty metadata changed for an existing outpoint.');
        outpoints.set(key, row);
        if (row.status === 'available' && row.root_certificates_version === 1 && !this.reserved.has(key)) available.push(row);
        else this.engine.remove(row.txid, row.vout);
      }
      // Already-started captures can finish after ordinary discovery aging.
      for (const [key, row] of this.outpoints) if (!outpoints.has(key)) {
        if (this.engine.queue.get(key)?.retired && (this.engine.hasActive(key) || this.engine.pendingProofs.has(key))) outpoints.set(key, row);
        else this.engine.remove(row.txid, row.vout);
      }
      this.blocks = result.blocks; this.outpoints = outpoints; this.cursor = result.cursor; this.tip = tip;
      this.engine.retainCatalog(outpoints.values()); this.engine.enqueue(available);
      this.ready = true; this.status = 'running'; this.lastError = null; this.failures = 0;
      this.cancelCatalogWaiters();
      if (!this.engine.enabled) this.engine.start();
      this.engine.resume();
      this.report('discovery', { height: tip.height, available: available.length, total: outpoints.size });
      this.publish();
      this.scheduleRecovery();
    } catch (error) {
      if (!this.running || this.fatalError) return;
      await this.suspend().catch(failure => this.fail(failure));
      if (error.name === 'AbortError') this.cancelCatalogWaiters();
      if (!this.running || this.fatalError) return;
      if (error.name !== 'AbortError' && !transient(error)) { this.fail(error); return; }
      this.status = 'reconnecting'; this.lastError = error.name === 'AbortError' ? 'RPC connection changed; catching up before resuming claims.' : error.message;
      delay = Math.min(this.retryMaxMs, this.retryMinMs * 2 ** Math.min(this.failures++, 10));
      if ([-32029, -32030].includes(error.code) && Number.isSafeInteger(error.data?.retry_after_ms) && error.data.retry_after_ms > 0) {
        delay = Math.max(delay, Math.min(300000, error.data.retry_after_ms));
      }
      this.report('error', { message: this.lastError, fatal: false, retryAfterMs: delay }); this.publish();
    } finally {
      if (this.running && !this.fatalError) this.schedule(delay);
    }
  }

  async funding(txid, { signal, epoch = this.epoch } = {}) {
    this.check(epoch, signal);
    if (this.fundingCache.has(txid)) return this.fundingCache.get(txid);
    let entry = this.fundingPending.get(txid);
    if (!entry || entry.epoch !== epoch) {
      if (this.fundingPending.size >= 256) throw new Error('Too many funding lookups are pending.');
      const scopedSignal = this.ioAbort.signal;
      entry = { epoch };
      entry.promise = (async () => {
        const result = await this.rpc.request('gettransaction', { txid }, { signal: scopedSignal });
        this.check(epoch, scopedSignal);
        let raw;
        try {
          validateTip(result?.tip, this.config.network); raw = result.transaction?.hex;
          if (this.transactionId(raw) !== txid) throw new Error('RPC funding bytes do not match their transaction ID.');
        } catch (error) { error.helperFatal = true; this.fail(error); throw error; }
        if (this.fundingCache.size >= 256) this.fundingCache.delete(this.fundingCache.keys().next().value);
        this.fundingCache.set(txid, raw); return raw;
      })().finally(() => { if (this.fundingPending.get(txid) === entry) this.fundingPending.delete(txid); });
      this.fundingPending.set(txid, entry);
    }
    if (!signal) return entry.promise;
    // Cancelling one bounty must not cancel another bounty's shared parent read.
    return new Promise((accept, reject) => {
      const cancel = () => { signal.removeEventListener('abort', cancel); reject(aborted()); };
      entry.promise.then(value => { signal.removeEventListener('abort', cancel); accept(value); },
        error => { signal.removeEventListener('abort', cancel); reject(error); });
      if (signal.aborted) cancel(); else signal.addEventListener('abort', cancel, { once: true });
    });
  }

  async prepare(bounty, { signal, previous } = {}) {
    const epoch = this.epoch;
    await this.waitForCatalog(epoch, signal);
    this.check(epoch, signal);
    const key = bountyKey(bounty), current = this.outpoints.get(key);
    if (!this.ready || current?.status !== 'available' || this.reserved.has(key)) throw aborted();
    const rawTransaction = await this.funding(current.txid, { signal, epoch });
    await this.waitForCatalog(epoch, signal);
    this.check(epoch, signal);
    const latest = this.outpoints.get(key);
    if (!this.ready || latest?.status !== 'available' || this.reserved.has(key)) throw aborted();
    const reusable = previous?.epoch === epoch && previous.rpc === this.rpc && bountyKey(previous.bounty) === key;
    const prepared = this.prepareTransaction({ bounty: latest, rawTransaction, rewardAddress: this.config.receivingAddress,
      fee: reusable ? previous.fee : estimateClaimFee(this.config.feeRate), network: this.config.network });
    return { ...prepared, epoch, rpc: this.rpc, context: {
      domain: prepared.bounty.domain, txid: prepared.txid, input_index: 0,
      connection_work_target: prepared.bounty.target, root_certificates_version: prepared.bounty.rootVersion,
      signature_algorithms_mask: prepared.bounty.mask, validation_time: validateTip(this.tip, this.config.network).mediantime,
    } };
  }

  async submit(prepared, proof, { signal } = {}) {
    const key = bountyKey(prepared.bounty);
    await this.waitForCatalog(prepared.epoch, signal);
    this.check(prepared.epoch, signal);
    if (!this.ready || prepared.rpc !== this.rpc || this.outpoints.get(key)?.status !== 'available' || this.reserved.has(key)) throw aborted();
    const signed = this.attachProof(prepared, proof);
    const record = { txid: signed.txid, receivingAddress: this.config.receivingAddress,
      transactionHex: signed.hex, transactionHash: transactionDigest(signed.hex) };
    this.reserved.add(key);
    this.inFlightBroadcasts.add(key);
    try {
      // Preserve the exact verified public witness BEFORE sending. A lost reply
      // never requires generating a competing transaction or discarding proof.
      await this.journal.update(key, { ...record, status: 'pending' });
    } catch (error) {
      this.inFlightBroadcasts.delete(key);
      error.helperFatal = true; this.fail(error); throw error;
    }
    let invoked = false;
    try {
      await this.waitForCatalog(prepared.epoch, signal);
      const beforeSend = () => {
        this.check(prepared.epoch, signal);
        if (!this.ready || this.catalogGate || this.outpoints.get(key)?.status !== 'available' || !this.reserved.has(key)) throw aborted();
      };
      beforeSend();
      invoked = true;
      const result = await this.rpc.request('sendrawtransaction', { transaction_hex: signed.hex },
        { signal: signal ? AbortSignal.any([signal, this.ioAbort.signal]) : this.ioAbort.signal, beforeSend });
      if (result?.txid !== signed.txid) throw new Error('RPC returned an unexpected claim transaction ID.');
      await this.journal.update(key, { ...record, status: 'accepted' });
      this.report('broadcast', { txid: signed.txid, outpoint: key, status: 'accepted' });
      return { txid: signed.txid };
    } catch (error) {
      // A definite first node rejection can be returned to the existing proof
      // retry policy. A later rejection during reconciliation cannot erase an
      // earlier uncertain write; that path never releases the reservation.
      if (invoked && isKnownClaimRejection(error) && !error.unknownOutcome &&
          this.running && !this.fatalError && prepared.epoch === this.epoch && !signal?.aborted) {
        try { await this.journal.update(key, null); this.reserved.delete(key); }
        catch (failure) { failure.helperFatal = true; this.fail(failure); throw failure; }
        throw error;
      }
      const notSent = !invoked || (error.notSent === true && !error.unknownOutcome) ||
        (!error.unknownOutcome && [-32001, -32029, -32030].includes(error.code));
      const status = notSent ? 'pending' : 'unknown';
      try { await this.journal.update(key, { ...record, status }); }
      catch (failure) { failure.helperFatal = true; this.fail(failure); throw failure; }
      this.report('broadcast', { txid: signed.txid, outpoint: key, status, reason: diagnosticError(error) });
      this.scheduleRecovery();
      throw deferredBroadcast(signed.txid, error);
    } finally { this.inFlightBroadcasts.delete(key); }
  }

  persistPendingProofs() {
    const writes = [];
    for (const [key, pending] of this.engine.pendingProofs) {
      const prepared = this.engine.queue.get(key)?.prepared;
      if (this.reserved.has(key) || !prepared || typeof pending.proof !== 'string') continue;
      this.reserved.add(key);
      const operation = (async () => {
        const signed = this.attachProof(prepared, pending.proof);
        await this.journal.update(key, { txid: signed.txid, receivingAddress: this.config.receivingAddress,
          status: 'pending', transactionHex: signed.hex, transactionHash: transactionDigest(signed.hex) });
      })();
      writes.push(operation);
    }
    return Promise.all(writes);
  }

  scheduleRecovery(delay = 5000) {
    if (!this.running || this.fatalError || this.recoveryTimer !== null || this.recovering || !this.journal.unresolved().length) return;
    this.recoveryTimer = this.setTimer(() => {
      this.recoveryTimer = null;
      void this.reconcileBroadcasts().catch(error => this.fail(error));
    }, delay);
    this.recoveryTimer?.unref?.();
  }

  reconcileBroadcasts() {
    if (this.recovering) return this.recovering;
    if (!this.running || this.fatalError) return Promise.resolve();
    if (!this.ready || this.catalogGate) { this.scheduleRecovery(); return Promise.resolve(); }
    // Old quarantined records must not starve newer recoverable claims. Choose
    // the least-recently scheduled eligible record, not insertion-order first.
    const now = Date.now(); let row, earliest = Infinity;
    for (const record of this.journal.unresolved()) {
      const due = this.recoveryDue.get(record.outpoint) ?? 0;
      if (!this.inFlightBroadcasts.has(record.outpoint) && due <= now && due < earliest) { row = record; earliest = due; }
    }
    if (!row) { this.scheduleRecovery(); return Promise.resolve(); }
    // Only one reconciliation at a time, sharing the normal bounded RPC quotas.
    const epoch = this.epoch, signal = this.ioAbort.signal;
    this.inFlightBroadcasts.add(row.outpoint);
    this.recoveryDue.set(row.outpoint, Date.now() + 30000);
    const operation = this.reconcileOne(row, epoch, signal).finally(() => {
      this.inFlightBroadcasts.delete(row.outpoint);
      if (this.recovering === operation) this.recovering = null;
      this.scheduleRecovery();
    });
    this.recovering = operation;
    return operation;
  }

  async reconcileOne(row, epoch, signal) {
    try {
      await this.waitForCatalog(epoch, signal);
      validateTip(this.tip, this.config.network);
      if (row.receivingAddress !== this.config.receivingAddress) {
        this.recoveryBlocked.add(row.outpoint);
        this.report('broadcast', { txid: row.txid, outpoint: row.outpoint, status: 'quarantined-address-mismatch' });
        return;
      }
      let found = false;
      try {
        const result = await this.rpc.request('gettransaction', { txid: row.txid }, { signal });
        this.check(epoch, signal); validateTip(result?.tip, this.config.network);
        this.validateObserved(row, result?.transaction?.hex, this.config);
        found = true;
      } catch (error) {
        // Absence is NOT proof of rejection; it only permits retrying IDENTICAL
        // saved bytes. Legacy records with no witness remain quarantined.
        if (error.code !== -32004) throw error;
      }
      if (!found) {
        if (!row.transactionHex) {
          this.recoveryBlocked.add(row.outpoint);
          this.report('broadcast', { txid: row.txid, outpoint: row.outpoint, status: 'quarantined-legacy-no-bytes' });
          return;
        }
        const raw = this.validateSaved(row, this.config);
        await this.waitForCatalog(epoch, signal);
        const beforeSend = () => {
          this.check(epoch, signal);
          if (!this.ready || this.catalogGate || !this.reserved.has(row.outpoint)) throw aborted();
        };
        beforeSend();
        // Persist potential uncertainty before the first byte of a retry, too.
        await this.journal.update(row.outpoint, { ...row, status: 'unknown' });
        const result = await this.rpc.request('sendrawtransaction', { transaction_hex: raw }, { signal, beforeSend });
        if (result?.txid !== row.txid) throw new Error('RPC returned an unexpected recovered transaction ID.');
      }
      await this.journal.update(row.outpoint, { txid: row.txid, receivingAddress: row.receivingAddress, status: 'accepted' });
      this.recoveryDue.delete(row.outpoint); this.recoveryBlocked.delete(row.outpoint);
      this.engine.completeRecoveredClaim?.(row.outpoint, row.txid);
      this.report('broadcast', { txid: row.txid, outpoint: row.outpoint, status: 'recovered-accepted' });
      this.publish();
    } catch (error) {
      // Uncertainty/rejections reserve only this outpoint and retain the exact
      // public transaction. Never release it on a later -25/-26/-27 or quota.
      if (error.unknownOutcome || error.notSent || transient(error) || error.code === -32011 ||
          error.code === -32020 || error.name === 'AbortError') {
        const retry = Number.isSafeInteger(error.data?.retry_after_ms) ? Math.min(300000, Math.max(30000, error.data.retry_after_ms)) : 30000;
        this.recoveryDue.set(row.outpoint, Date.now() + retry);
        this.report('broadcast', { txid: row.txid, outpoint: row.outpoint, status: 'reconciliation-pending', reason: diagnosticError(error) });
        return;
      }
      // Malformed identity, damaged saved bytes and storage failures are still
      // fail-closed, never a reason to send unvalidated or altered transactions.
      error.helperFatal = true; throw error;
    }
  }

  fail(error) {
    if (this.fatalError && (!error?.unknownOutcome || this.fatalError.unknownOutcome)) return;
    this.fatalError = error instanceof Error ? error : new Error('The claimer stopped unexpectedly.');
    this.running = false; this.ready = false; this.status = this.fatalError.unknownOutcome ? 'review-required' : 'failed';
    this.lastError = this.fatalError.message;
    this.epoch++; this.ioAbort.abort();
    this.cancelCatalogWaiters();
    if (this.recoveryTimer !== null) this.clearTimer(this.recoveryTimer); this.recoveryTimer = null;
    if (this.timer !== null) this.clearTimer(this.timer); this.timer = null;
    this.rpc.close();
    // Never await the engine from inside its own prepare/submit callback.
    const saved = this.persistPendingProofs();
    this.engineDrain = Promise.all([saved, this.engine.stop()]).then(() => this.persistPendingProofs()).catch(failure => {
      this.report('error', { message: failure.message, fatal: true, reviewRequired: true });
    });
    this.report('error', { message: this.lastError, fatal: true, reviewRequired: Boolean(this.fatalError.unknownOutcome) }); this.publish();
  }

  stop() {
    if (this.stopping) return this.stopping;
    this.running = false; this.ready = false; this.epoch++; this.ioAbort.abort();
    this.cancelCatalogWaiters();
    if (this.recoveryTimer !== null) this.clearTimer(this.recoveryTimer); this.recoveryTimer = null;
    if (this.timer !== null) this.clearTimer(this.timer); this.timer = null;
    if (!this.fatalError) this.status = 'stopping';
    this.rpc.close();
    const operation = (async () => {
      const saved = this.persistPendingProofs().catch(error => this.fail(error));
      await Promise.allSettled([saved, this.engine.stop(), this.engineDrain, this.cycling, this.suspending, this.recovering, ...[...this.fundingPending.values()].map(row => row.promise)].filter(Boolean));
      await this.persistPendingProofs();
      await this.journal.flush();
      this.rpc.off('disconnected', this.onDisconnected);
      if (!this.fatalError) this.status = 'stopped';
      this.publish();
    })();
    this.stopping = operation;
    return operation;
  }
}
