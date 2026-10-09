import { spawn } from 'node:child_process';
import { getClaimsHelper, validateClaimContext } from './claims.mjs';
import { diagnosticProcessExit } from './diagnostics.mjs';
import { MAX_CONNECTION_LIMIT } from './connection-limits.mjs';

export const CONNECTION_DEFAULTS = Object.freeze({ connectionsPerSecond: 100, concurrency: 100 });
export function validateConnectionOptions(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !Object.hasOwn(CONNECTION_DEFAULTS, key))) throw new Error('Invalid connection options');
  const options = { ...CONNECTION_DEFAULTS, ...input };
  for (const value of Object.values(options)) if (!Number.isSafeInteger(value) || value < 1 || value > MAX_CONNECTION_LIMIT) throw new Error(`Connection limits must be integers between 1 and ${MAX_CONNECTION_LIMIT}`);
  return Object.freeze(options);
}
export function claimAborted() { return Object.assign(new Error('Automatic Claims stopped'), { name: 'AbortError' }); }
const MAX_COUNTER = (1n << 64n) - 1n;
const ATTEMPT_MESSAGES = new Set([
  'TLS capture cancelled', 'TLS connection timed out',
  'TLS capture or proof validation failed', 'Public DNS resolution is required',
]);
function counter(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > MAX_COUNTER) throw new Error('Invalid helper connection counter');
  return value;
}

/** One process for the entire run. Requests contain public claim contexts only. */
export class ConnectionPool {
  constructor({ helper, resourcesPath, basePath, spawnProcess = spawn, onDiagnostic = () => {}, onFailure = () => {} } = {}) {
    Object.assign(this, { helper, resourcesPath, basePath, spawnProcess, onDiagnostic, onFailure });
    this.pacesStarts = true; // Protocol 4 enforces one global clock at socket start.
    this.requests = new Map(); this.sequence = 0; this.pendingStarts = 0; this.closing = false;
  }
  async start(options) {
    if (this.closing) throw claimAborted();
    if (this.ready) return this.ready;
    this.options = validateConnectionOptions(options);
    const runtime = this.helper ?? getClaimsHelper({ basePath: this.basePath, resourcesPath: this.resourcesPath });
    if (!runtime) throw new Error('Automatic Claims helper is not installed. Run npm run build:claims.');
    this.ready = new Promise((resolve, reject) => { this.readyResolve = resolve; this.readyReject = reject; });
    this.closed = new Promise(resolve => { this.closedResolve = resolve; });
    this.startedAt = performance.now();
    const allowed = new Set(['path', 'systemroot', 'systemdrive', 'windir', 'temp', 'tmp', 'tmpdir', 'home', 'userprofile', 'localappdata', 'appdata', 'user', 'username', 'lang', 'lc_all', 'tz']);
    const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toLowerCase())));
    try {
      this.child = this.spawnProcess(runtime.command, [...runtime.args ?? [], '--service'], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { ...environment, PYTHONNOUSERSITE: '1', PYTHONUNBUFFERED: '1' } });
      this.buffer = ''; this.stderrBytes = 0;
      this.child.once('error', error => { this.fail(new Error('Claims helper could not start', { cause: error })); this.closedResolve(); });
      this.child.stdin.on('error', error => { if (!this.closing) this.fail(new Error(`Claims helper input failed: ${error.message}`)); });
      this.child.stdout.on('data', data => {
        if (this.failure || this.drainFailed || this.processClosed) return;
        try {
          this.buffer += data.toString('utf8');
          let end;
          while ((end = this.buffer.indexOf('\n')) !== -1) {
            if (end > 160 * 1024) throw new Error('Claims helper frame limit exceeded');
            const line = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end + 1);
            this.receive(JSON.parse(line));
          }
          if (this.buffer.length > 160 * 1024) throw new Error('Claims helper frame limit exceeded');
        } catch (error) { this.fail(error); }
      });
      this.child.stderr.on('data', data => {
        this.stderrBytes = Math.min(1073741824, this.stderrBytes + data.length);
        if (this.stderrBytes > 8192) this.fail(new Error('Claims helper diagnostic limit exceeded'));
      });
      this.child.once('close', (code, signal) => {
        this.processClosed = true;
        clearTimeout(this.startTimer); clearTimeout(this.killTimer);
        if (!this.closing) this.fail(new Error('Persistent claims helper closed unexpectedly'), diagnosticProcessExit(code, signal));
        else for (const request of [...this.requests.values()]) this.finish(request, claimAborted());
        this.readyReject(claimAborted()); this.closedResolve();
      });
      this.startTimer = setTimeout(() => this.fail(new Error('Claims helper startup timed out; update or rebuild the helper')), 15000);
      this.send({ type: 'start', protocol: 4, options: this.options });
    } catch (error) { this.fail(error); this.closedResolve(); }
    return this.ready;
  }
  send(message) {
    if (this.failure) throw this.failure;
    const line = JSON.stringify(message) + '\n';
    if (Buffer.byteLength(line) > 16384) throw new Error('Claims helper request limit exceeded');
    // There are at most concurrency+two DNS requests, not an unbounded pipe queue.
    if ((this.child?.stdin.writableLength ?? 0) > 1024 * 1024) throw new Error('Claims helper input backpressure exceeded');
    this.child.stdin.write(line);
  }
  armDeadline(request, delay, message = 'Claims helper request exceeded its deadline') {
    clearTimeout(request.timer);
    // Node timers use signed 32-bit milliseconds. Large real admission queues
    // must never wrap a legitimate pacing allowance into an immediate timeout.
    const maximumDelay = 2_147_483_647;
    request.timer = setTimeout(() => {
      if (delay > maximumDelay) this.armDeadline(request, delay - maximumDelay, message);
      else this.fail(new Error(message));
    }, Math.min(delay, maximumDelay));
  }
  request(kind, body, { signal, onStarted, onCapture, onResult } = {}) {
    if (this.failure) return Promise.reject(this.failure);
    if (!this.started || this.closing || signal?.aborted) return Promise.reject(claimAborted());
    // Bound retained requests by actual configured work plus DNS. Raising the
    // user's concurrency must not turn the former 512-request guard into a stop.
    if (this.requests.size >= Math.max(512, this.options.concurrency + 2) || this.sequence >= Number.MAX_SAFE_INTEGER) return Promise.reject(new Error('Claims helper request capacity exceeded'));
    return new Promise((resolve, reject) => {
      const id = ++this.sequence;
      const request = { id, kind, body, signal, onStarted, onCapture, onResult, resolve, reject, started: false, capture: null };
      request.abort = () => { try { this.send({ type: 'cancel', id }); } catch { /* A closing helper is already cancelled. */ } };
      // Socket pacing has its own generous watchdog, including every admission
      // ahead of this one. A stalled helper still fails without charging this
      // local queue wait to the capture/verification deadline.
      if (kind === 'resolve') this.armDeadline(request, 45000);
      else {
        this.pendingStarts++;
        this.armDeadline(request, 60000 + this.pendingStarts * 1000 / this.options.connectionsPerSecond,
          'Claims helper start acknowledgement exceeded its deadline');
      }
      signal?.addEventListener('abort', request.abort, { once: true });
      this.requests.set(id, request);
      try { this.send({ type: kind, id, ...body }); } catch (error) { this.fail(error); }
    });
  }
  resolve(domain, options = {}) { return this.request('resolve', { domain }, options); }
  attempt(context, { bountyId, successfulConnections = 0n, ...options } = {}) {
    if (typeof bountyId !== 'string' || !/^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$/.test(bountyId) || Number(bountyId.split(':')[1]) > 0xffffffff) return Promise.reject(new Error('Invalid bounty identity'));
    const publicContext = validateClaimContext(context);
    return this.request('attempt', { context: publicContext, bountyId, successfulConnections: counter(String(successfulConnections)) }, options);
  }
  receive(message) {
    if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Malformed claims helper response');
    if (message.type === 'ready') {
      if (this.started || message.protocol !== 4 || message.roots !== 1 || message.security?.rsaPublicExponentMaxBits !== 64) {
        throw new Error('Incompatible claims helper: validated observations require protocol 4 and a 64-bit RSA public-exponent limit. Update the app or run npm run build:claims.');
      }
      this.started = true; clearTimeout(this.startTimer);
      if (this.closing) this.readyReject(claimAborted()); else this.readyResolve();
      return;
    }
    if (message.type === 'error') throw new Error('Claims helper failed');
    // Only fixed descriptions may reach the claims engine/UI.
    if (Object.hasOwn(message, 'message')) message = { ...message,
      message: ATTEMPT_MESSAGES.has(message.message) ? message.message : 'TLS capture or proof validation failed' };
    if (!Number.isSafeInteger(message.id)) throw new Error('Invalid helper request identity');
    const request = this.requests.get(message.id);
    if (!request) throw new Error('Unexpected or duplicate helper response');
    if (message.type === 'resolved' && request.kind === 'resolve') {
      if (typeof message.ok !== 'boolean') throw new Error('Invalid DNS helper result');
      this.finish(request, request.signal?.aborted ? claimAborted() : message.ok ? null : new Error('Domain resolution failed'), message); return;
    }
    if (request.kind !== 'attempt') throw new Error('Mismatched helper response type');
    if (message.type === 'started') {
      if (request.started || request.capture) throw new Error('Duplicate helper start');
      this.pendingStarts--;
      this.armDeadline(request, 45000);
      request.started = true; request.onStarted?.(); return;
    }
    if (!['capture', 'attempt'].includes(message.type)) throw new Error('Unknown claims helper response');
    const context = validateClaimContext(message.context);
    if (Object.keys(context).some(key => context[key] !== request.body.context[key])) throw new Error('Proof does not match the prepared claim');
    if (typeof message.started !== 'boolean' || message.started !== request.started || typeof message.captured !== 'boolean' || typeof message.cancelled !== 'boolean' ||
        typeof message.seconds !== 'number' || !Number.isFinite(message.seconds) || message.seconds < 0 || message.seconds > 3600 ||
        (message.captured && !message.started)) throw new Error('Invalid helper capture status');
    counter(message.successfulConnections);
    const minimum = BigInt(request.body.successfulConnections) + (message.captured ? 1n : 0n);
    if (BigInt(message.successfulConnections) < (minimum > MAX_COUNTER ? MAX_COUNTER : minimum)) throw new Error('Helper connection counter moved backwards');
    if (message.type === 'capture') {
      if (Object.hasOwn(message, 'blocked') || Object.hasOwn(message, 'retryAfterMs')) throw new Error('Invalid blocked capture observation');
      if (!request.started || request.capture) throw new Error('Unexpected or duplicate capture');
      request.capture = message; request.onCapture?.(message); return;
    }
    if (request.started && !request.capture) throw new Error('Missing helper capture observation');
    if (Object.hasOwn(message, 'blocked')) {
      if (message.blocked !== 'budget' || message.started || message.captured || message.proof !== null ||
          message.verified !== false || message.validationPassed !== null || message.seconds !== 0) throw new Error('Invalid blocked helper result');
    }
    if (Object.hasOwn(message, 'retryAfterMs')) throw new Error('Unexpected endpoint retry delay');
    if (request.capture && (request.capture.captured !== message.captured || request.capture.seconds !== message.seconds ||
        request.capture.successfulConnections !== message.successfulConnections)) throw new Error('Conflicting helper capture observation');
    if (![true, false, null].includes(message.validationPassed) ||
        (message.validationPassed !== null && !message.started) ||
        (message.validationPassed === true && !message.captured) ||
        (message.validationPassed === null && message.started && !message.cancelled)) {
      throw new Error('Invalid helper validation observation');
    }
    if (message.proof !== null) {
      if (!message.captured || message.validationPassed !== true || message.verified !== true || message.cancelled || typeof message.proof !== 'string' || !/^02(?:[0-9a-f]{2})+$/.test(message.proof) || message.proof.length > 131072) throw new Error('Invalid verified proof result');
    } else if (message.verified !== false) throw new Error('Invalid proof verification status');
    // Preserve a completed validation observation even if cancellation arrived
    // before its acknowledgement. Never turn an unvalidated capture into success.
    request.onResult?.(this.closing ? { ...message, proof: null, verified: false, cancelled: true } : message);
    this.finish(request, request.signal?.aborted ? claimAborted() : null, message);
  }
  finish(request, error, result) {
    if (!this.requests.delete(request.id)) return;
    if (request.kind === 'attempt' && !request.started) this.pendingStarts--;
    clearTimeout(request.timer); request.signal?.removeEventListener('abort', request.abort);
    // Closing cancels every request, including callers without an AbortSignal.
    // Result callbacks above may retain validated observations, never a proof.
    if (this.closing) error = claimAborted();
    if (error) request.reject(error); else request.resolve(result);
  }
  fail(error, exit = {}) {
    if (this.failure || this.drainFailed) return;
    if (this.closing) {
      // Shutdown still parses bounded, validated result frames. A bad frame
      // ends draining immediately without turning requested shutdown into a crash.
      this.drainFailed = true; this.buffer = '';
      this.readyReject?.(claimAborted());
      for (const request of [...this.requests.values()]) this.finish(request, claimAborted());
      if (this.child && !this.processClosed && !this.child.killed) this.child.kill('SIGKILL');
      return;
    }
    this.failure = Object.assign(error, { helperFatal: true });
    clearTimeout(this.startTimer); this.readyReject?.(this.failure);
    for (const request of [...this.requests.values()]) this.finish(request, this.failure);
    if (this.child && !this.processClosed && !this.child.killed) this.child.kill('SIGKILL');
    try {
      Promise.resolve(this.onDiagnostic('helper.failed', { stage: 'proof', error: this.failure,
        helperReady: this.started === true, durationMs: Math.min(86400000, Math.max(0, performance.now() - this.startedAt)),
        stderrBytes: this.stderrBytes ?? 0, ...exit })).catch(() => {});
    } catch { /* No effect on cancellation. */ }
    // A ready helper may die while no request is in flight. Control flow must
    // not depend on a diagnostic consumer being installed or on another claim.
    try { Promise.resolve(this.onFailure(this.failure)).catch(() => {}); } catch { /* Cleanup still completes. */ }
  }
  async close() {
    if (this.closing) return this.closed;
    this.closing = true;
    clearTimeout(this.startTimer);
    this.readyReject?.(claimAborted());
    if (!this.child || this.processClosed) { this.closedResolve?.(); return; }
    try { this.send({ type: 'shutdown' }); this.child.stdin.end(); } catch { this.child.kill('SIGKILL'); }
    this.killTimer = setTimeout(() => { if (!this.child.killed) this.child.kill('SIGKILL'); }, 2000);
    await this.closed;
    clearTimeout(this.killTimer);
  }
}
