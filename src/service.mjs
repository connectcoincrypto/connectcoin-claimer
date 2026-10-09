import { resolve } from 'node:path';
import { RpcClient } from './core/rpc.mjs';
import { validateTip } from './core/config.mjs';
import { ClaimsEngine } from './core/claims-engine.mjs';
import { ConnectionPool } from './core/claim-pool.mjs';
import { isKnownClaimRejection } from './core/claims.mjs';
import { discoverBounties, readBountyBlock, bountyKey } from './core/bounty-discovery.mjs';
import { prepareClaim, attachClaimProof, estimateClaimFee, transactionIdFromRaw } from './core/transaction.mjs';
import { BroadcastJournal } from './broadcast-journal.mjs';
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
    pollMs = 5000, retryMinMs = 1000, retryMaxMs = 30000, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
    Object.assign(this, { config, basePath, statePath, emit, journal, discover, readBlock, prepareTransaction: prepare,
      attachProof: attach, transactionId, pollMs, retryMinMs, retryMaxMs, setTimer, clearTimer });
    this.running = false; this.started = false; this.ready = false; this.epoch = 0; this.failures = 0;
    this.status = 'stopped'; this.lastError = null; this.fatalError = null; this.tip = null;
    this.blocks = new Map(); this.outpoints = new Map(); this.cursor = null; this.reserved = new Set();
    this.fundingCache = new Map(); this.fundingPending = new Map(); this.ioAbort = new AbortController();
    this.metrics = new ClaimMetrics();
    this.timer = null; this.cycling = null; this.suspending = null; this.stopping = null;
    this.rpc = rpcFactory({ ...config.rpc, quota: 48, timeoutMs: 40000 });
    this.engine = engineFactory({
      prepare: (bounty, options) => this.prepare(bounty, options),
      submit: (prepared, proof, options) => this.submit(prepared, proof, options),
      isUnlocked: () => this.running && !this.fatalError,
      getNetReward: bounty => BigInt(bounty.amount) - BigInt(estimateClaimFee(config.feeRate)),
      getValidationTime: () => validateTip(this.tip, config.network).mediantime,
      minExpectedReturn: config.minExpectedReturn,
      options: { connectionsPerSecond: config.connectionsPerSecond, concurrency: config.concurrency },
      poolFactory: options => this.metrics.wrap(poolFactory ? poolFactory(options) : new ConnectionPool({ basePath, ...options })),
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
    return { status: this.status, running: this.running, ready: this.ready, height: this.tip?.height ?? null,
      available: [...this.outpoints.values()].filter(row => row.status === 'available' && !this.reserved.has(bountyKey(row))).length,
      reserved: this.reserved.size, lastError: this.lastError, reviewRequired: Boolean(this.fatalError?.unknownOutcome),
      claims: { ...(this.claimState ?? {}) }, metrics: this.metrics.snapshot() };
  }

  async start() {
    if (this.started) throw new Error('This claimer service has already been started.');
    this.started = true;
    const epoch = this.epoch;
    try {
      const entries = await this.journal.load();
      this.reserved = new Set(entries.map(row => row.outpoint));
      const uncertain = this.journal.unresolved();
      if (uncertain.length) throw Object.assign(new Error(`A previous claim broadcast needs review: ${uncertain[0].txid}. Check the transaction and the saved state at ${this.statePath} before restarting.`), { unknownOutcome: true });
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
    const pending = Promise.resolve(this.engine.suspend());
    this.suspending = pending;
    return pending;
  }

  disconnected() {
    if (!this.running || this.fatalError) return;
    this.epoch++; this.ioAbort.abort(); this.ioAbort = new AbortController();
    this.tip = null; this.fundingCache.clear(); this.fundingPending.clear();
    this.status = 'reconnecting';
    const epoch = this.epoch;
    this.suspending = this.suspend().then(() => {
      if (!this.running || this.fatalError || epoch !== this.epoch) return;
      // Cached proposals and verified proofs belong to the former RPC epoch.
      // Removing only live captures would leave old proposals in enqueue(), and
      // an old pending proof could repeatedly retry its now-aborted submission.
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
        onReset: async () => { await this.suspend(); check(); this.engine.clear({ preserveSelection: true }); },
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
          for (const key of this.engine.activeKeys()) {
            const row = this.outpoints.get(key), hash = row && canonical.get(row.block_height);
            if (row && (row.block_height > snapshot.tip.height || (hash && hash !== row.block_hash))) {
              this.engine.remove(row.txid, row.vout); this.outpoints.delete(key);
            }
          }
        },
        readBlock: (hash, options) => this.readBlock({ rpc: scopedRpc, network: this.config.network, hash, ...options }),
      });
      check();
      const tip = validateTip(result.tip, this.config.network), outpoints = new Map(), available = [];
      for (const rows of result.blocks.values()) for (const row of rows) {
        const key = bountyKey(row); outpoints.set(key, row);
        if (row.status === 'available' && row.root_certificates_version === 1 && !this.reserved.has(key)) available.push(row);
        else this.engine.remove(row.txid, row.vout);
      }
      // Already-started captures can finish after ordinary discovery aging.
      for (const [key, row] of this.outpoints) if (!outpoints.has(key) && this.engine.hasActive(key) && this.engine.queue.get(key)?.retired) outpoints.set(key, row);
      this.blocks = result.blocks; this.outpoints = outpoints; this.cursor = result.cursor; this.tip = tip;
      this.engine.retainCatalog(outpoints.values()); this.engine.enqueue(available);
      this.ready = true; this.status = 'running'; this.lastError = null; this.failures = 0;
      if (!this.engine.enabled) this.engine.start();
      this.engine.resume();
      this.report('discovery', { height: tip.height, available: available.length, total: outpoints.size });
      this.publish();
    } catch (error) {
      if (!this.running || this.fatalError) return;
      await this.suspend().catch(failure => this.fail(failure));
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
    this.check(epoch, signal);
    const key = bountyKey(bounty), current = this.outpoints.get(key);
    if (!this.ready || current?.status !== 'available' || this.reserved.has(key)) throw aborted();
    const rawTransaction = await this.funding(current.txid, { signal, epoch });
    this.check(epoch, signal);
    if (!this.ready || this.outpoints.get(key)?.status !== 'available' || this.reserved.has(key)) throw aborted();
    const reusable = previous?.epoch === epoch && previous.rpc === this.rpc && bountyKey(previous.bounty) === key;
    const prepared = this.prepareTransaction({ bounty: current, rawTransaction, rewardAddress: this.config.receivingAddress,
      fee: reusable ? previous.fee : estimateClaimFee(this.config.feeRate), network: this.config.network });
    return { ...prepared, epoch, rpc: this.rpc, context: {
      domain: prepared.bounty.domain, txid: prepared.txid, input_index: 0,
      connection_work_target: prepared.bounty.target, root_certificates_version: prepared.bounty.rootVersion,
      signature_algorithms_mask: prepared.bounty.mask, validation_time: validateTip(this.tip, this.config.network).mediantime,
    } };
  }

  async submit(prepared, proof, { signal } = {}) {
    const key = bountyKey(prepared.bounty);
    this.check(prepared.epoch, signal);
    if (!this.ready || prepared.rpc !== this.rpc || this.outpoints.get(key)?.status !== 'available' || this.reserved.has(key)) throw aborted();
    const signed = this.attachProof(prepared, proof);
    const record = { txid: signed.txid, receivingAddress: this.config.receivingAddress };
    this.reserved.add(key);
    try {
      // Any crash after this durable write requires explicit transaction review.
      // Neither transaction bytes nor proof witnesses are kept in the journal.
      await this.journal.update(key, { ...record, status: 'pending' });
    } catch (error) {
      error.helperFatal = true; this.fail(error); throw error;
    }
    let invoked = false;
    try {
      this.check(prepared.epoch, signal);
      if (!this.ready || this.outpoints.get(key)?.status !== 'available') throw aborted();
      invoked = true;
      const result = await this.rpc.request('sendrawtransaction', { transaction_hex: signed.hex },
        { signal: signal ? AbortSignal.any([signal, this.ioAbort.signal]) : this.ioAbort.signal });
      if (result?.txid !== signed.txid) throw new Error('RPC returned an unexpected claim transaction ID.');
      await this.journal.update(key, { ...record, status: 'accepted' });
      this.report('broadcast', { txid: signed.txid, outpoint: key, status: 'accepted' });
      return { txid: signed.txid };
    } catch (error) {
      const definitelyNotSent = !invoked || (error.name === 'AbortError' && error.notSent === true && !error.unknownOutcome) ||
        isKnownClaimRejection(error) || [-32001, -32029, -32030].includes(error.code);
      if (definitelyNotSent && !error.unknownOutcome) {
        try { await this.journal.update(key, null); this.reserved.delete(key); }
        catch (failure) { failure.helperFatal = true; this.fail(failure); throw failure; }
        throw error;
      }
      const uncertain = Object.assign(new Error(`Claim broadcast needs review: ${signed.txid}. Its outcome is unknown; no claims will restart automatically.`), { unknownOutcome: true });
      // Close the submission gate immediately, before any further asynchronous I/O.
      this.fail(uncertain);
      await this.journal.update(key, { ...record, status: 'unknown' }).catch(() => {});
      this.report('broadcast', { txid: signed.txid, outpoint: key, status: 'unknown' });
      throw uncertain;
    }
  }

  fail(error) {
    if (this.fatalError && (!error?.unknownOutcome || this.fatalError.unknownOutcome)) return;
    this.fatalError = error instanceof Error ? error : new Error('The claimer stopped unexpectedly.');
    this.running = false; this.ready = false; this.status = this.fatalError.unknownOutcome ? 'review-required' : 'failed';
    this.lastError = this.fatalError.message;
    this.epoch++; this.ioAbort.abort();
    if (this.timer !== null) this.clearTimer(this.timer); this.timer = null;
    this.rpc.close();
    // Never await the engine from inside its own prepare/submit callback.
    this.engineDrain = Promise.resolve(this.engine.stop()).catch(() => {});
    this.report('error', { message: this.lastError, fatal: true, reviewRequired: Boolean(this.fatalError.unknownOutcome) }); this.publish();
  }

  stop() {
    if (this.stopping) return this.stopping;
    this.running = false; this.ready = false; this.epoch++; this.ioAbort.abort();
    if (this.timer !== null) this.clearTimer(this.timer); this.timer = null;
    if (!this.fatalError) this.status = 'stopping';
    this.rpc.close();
    const operation = (async () => {
      await Promise.allSettled([this.engine.stop(), this.engineDrain, this.cycling, this.suspending, ...[...this.fundingPending.values()].map(row => row.promise)].filter(Boolean));
      await this.journal.flush();
      this.rpc.off('disconnected', this.onDisconnected);
      if (!this.fatalError) this.status = 'stopped';
      this.publish();
    })();
    this.stopping = operation;
    return operation;
  }
}
