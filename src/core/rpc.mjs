import net from 'node:net';
import { EventEmitter } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { validateRpcEndpoint } from './config.mjs';

const PARAMS = Object.freeze({
  getchaintip: [], getrecentblockhashes: [], getblockbounties: ['block_hash'],
  getaddressbalance: ['address'], getaddresshistory: ['address', 'cursor'], getaddressutxos: ['address', 'cursor', 'include_pending_spent'],
  getaddresschanges: ['addresses', 'cursor'],
  gettransaction: ['txid'], gettransactions: ['txids'], sendrawtransaction: ['transaction_hex'], getbountychanges: ['cursor'],
  subscribebounties: [], subscribeaddress: ['address', 'changes_only'], subscribetip: [], unsubscribe: ['subscription_id'],
});
const MAX_FRAME = 2 * 1024 * 1024;
const PLAIN = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [null, Object.prototype].includes(Object.getPrototypeOf(value));

export class RpcError extends Error {
  constructor(message, code, data) { super(message); this.name = 'RpcError'; this.code = code; this.data = data; }
}

// Reject unexpected fields rather than accidentally transmitting a recovery
// phrase/password/private key attached to a caller's object. Copy primitives
// before any await so callers cannot mutate the queued request or quota key.
export function validateRpcParams(method, params) {
  if (!Object.hasOwn(PARAMS, method)) throw new Error('This RPC method is not allowed.');
  if (!PLAIN(params) || Reflect.ownKeys(params).some(key => typeof key !== 'string' || !PARAMS[method].includes(key))) throw new Error('Unexpected RPC parameters.');
  const clean = {};
  for (const key of PARAMS[method]) {
    if (!Object.hasOwn(params, key)) {
      if (key !== 'cursor' && key !== 'include_pending_spent' && key !== 'changes_only') throw new Error(`Missing RPC parameter: ${key}.`);
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(params, key);
    if (!Object.hasOwn(descriptor, 'value')) throw new Error('RPC parameters must be plain data.');
    const value = descriptor.value;
    if (key === 'include_pending_spent') {
      if (typeof value !== 'boolean') throw new Error('Invalid RPC pending-spend option.');
      clean[key] = value; continue;
    }
    if (key === 'changes_only') {
      if (typeof value !== 'boolean') throw new Error('Invalid RPC address change option.');
      clean[key] = value; continue;
    }
    if (key === 'addresses') {
      if (!Array.isArray(value) || value.length < 1 || value.length > 100) throw new Error('Invalid RPC address batch.');
      const addresses = [];
      for (let index = 0; index < value.length; index++) {
        const entry = Object.getOwnPropertyDescriptor(value, String(index));
        if (!entry || !Object.hasOwn(entry, 'value') || typeof entry.value !== 'string' || entry.value.length < 8 || entry.value.length > 90 || !/^[a-zA-Z0-9]+$/.test(entry.value)) throw new Error('Invalid RPC address batch.');
        addresses.push(entry.value);
      }
      if (new Set(addresses).size !== addresses.length) throw new Error('Duplicate RPC address.');
      clean[key] = addresses; continue;
    }
    if (key === 'txids') {
      if (!Array.isArray(value) || value.length < 1 || value.length > 32) throw new Error('Invalid RPC transaction batch.');
      const hashes = [];
      for (let index = 0; index < value.length; index++) {
        const entry = Object.getOwnPropertyDescriptor(value, String(index));
        if (!entry || !Object.hasOwn(entry, 'value') || typeof entry.value !== 'string' || !/^[0-9a-f]{64}$/i.test(entry.value)) throw new Error('Invalid RPC transaction batch.');
        hashes.push(entry.value.toLowerCase());
      }
      if (new Set(hashes).size !== hashes.length) throw new Error('Duplicate RPC transaction hash.');
      clean[key] = hashes; continue;
    }
    if (key === 'cursor' && value === null) { clean[key] = null; continue; }
    if (typeof value !== 'string') throw new Error(`Invalid RPC parameter: ${key}.`);
    if ((key === 'block_hash' || key === 'txid') && !/^[0-9a-f]{64}$/i.test(value)) throw new Error('Invalid RPC hash.');
    if (key === 'address' && (value.length < 8 || value.length > 90 || !/^[a-zA-Z0-9]+$/.test(value))) throw new Error('Invalid RPC address.');
    if (key === 'cursor' && (value.length < 1 || value.length > 1024 || !/^[A-Za-z0-9_.-]+$/.test(value))) throw new Error('Invalid RPC cursor.');
    if (key === 'subscription_id' && (value.length < 1 || value.length > 100 || /[\x00-\x1f\x7f]/.test(value))) throw new Error('Invalid RPC subscription ID.');
    if (key === 'transaction_hex' && (value.length < 20 || value.length > 800000 || value.length % 2 || !/^[0-9a-f]+$/i.test(value))) throw new Error('Invalid or oversized transaction bytes.');
    clean[key] = key === 'block_hash' || key === 'txid' ? value.toLowerCase() : value;
  }
  return clean;
}
function lossError(request, reason) {
  if (request.method === 'sendrawtransaction' && request.sent) {
    const error = new Error('Broadcast outcome is unknown. Check the transaction ID before retrying.');
    error.unknownOutcome = true;
    return error;
  }
  return reason;
}
function clearRequest(request) { clearTimeout(request.timer); clearTimeout(request.deadlineTimer); }
function closedError() {
  return Object.assign(new Error('RPC client closed.'), { name: 'AbortError', code: 'ABORT_ERR' });
}
function cancelledError() {
  return Object.assign(new Error('RPC request cancelled before transmission.'), { name: 'AbortError', code: 'ABORT_ERR' });
}
function isLocalCancellation(error) {
  return error instanceof Error && error.name === 'AbortError' && error.code === 'ABORT_ERR' && !error.unknownOutcome;
}
function waitForConnection(promise, signal) {
  // Connecting is shared. Only abandon this wait; destroying the socket would
  // also cancel unrelated requests (including broadcasts already in flight).
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(cancelledError()); };
    promise.then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      error => { signal.removeEventListener('abort', abort); reject(error); });
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  });
}

/** A bounded, plaintext, native TCP client. No wallet secrets cross this class. */
export class RpcClient extends EventEmitter {
  constructor({ host, port, timeoutMs = 40000, quota = 48, windowMs = 60000, onDiagnostic = () => {} } = {}) {
    super();
    Object.assign(this, validateRpcEndpoint({ host, port }));
    for (const [name, value, maximum] of [['timeoutMs', timeoutMs, 120000], ['quota', quota, 60], ['windowMs', windowMs, 60000]]) {
      if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error(`Invalid RPC ${name}.`);
    }
    Object.assign(this, { timeoutMs, quota, windowMs });
    this.onDiagnostic = onDiagnostic;
    this.connectionErrors = new WeakMap();
    this.pending = new Map(); this.streams = new Map(); this.history = new Map(); this.cooldowns = new Map();
    this.nextId = 0; this.socket = null; this.connecting = null; this.closed = false; this.queuedRequests = 0;
    this.capacityWaiters = []; this.capacityReservations = 0;
    this.abort = new AbortController();
  }
  diagnostic(event, details) {
    // Diagnostic sinks must never change transport, quota, or broadcast outcomes.
    try { Promise.resolve(this.onDiagnostic(event, details)).catch(() => {}); } catch {}
  }
  publishDisconnection(socket) {
    if (this.socket !== socket) return;
    this.socket = null; this.emit('disconnected');
  }
  async connect() {
    if (this.closed) throw closedError();
    if (this.socket?.destroyed) {
      // A timeout/protocol failure rejects requests before socket.close runs.
      // Publish that loss before an immediate retry replaces the socket, or
      // the late close would silently skip subscription/wallet invalidation.
      this.publishDisconnection(this.socket);
      if (this.closed) throw closedError();
    }
    if (this.socket && !this.socket.destroyed && !this.socket.connecting) return this.socket;
    if (this.connecting) return this.connecting;
    const connecting = new Promise((resolve, reject) => {
      const startedAt = performance.now();
      const socket = net.connect({ host: this.host, port: this.port });
      this.socket = socket;
      let buffer = Buffer.alloc(0), connected = false;
      let socketFailure = null, idleFailureReported = false;
      const idleFailure = (error, stage) => {
        if (idleFailureReported || (!connected && this.queuedRequests > 0)) return;
        if ([...this.pending.values(), ...this.streams.values()].some(request => request.socket === socket)) return;
        idleFailureReported = true;
        this.diagnostic('rpc.failed', { stage, durationMs: performance.now() - startedAt, error, unknownOutcome: false });
      };
      const connectTimer = setTimeout(() => socket.destroy(new Error('RPC connection timed out.')), Math.min(8000, this.timeoutMs));
      socket.setNoDelay(true); socket.setKeepAlive(true, 10000);
      socket.on('connect', () => {
        clearTimeout(connectTimer);
        if (this.closed || this.socket !== socket) { socket.destroy(); reject(this.closed ? closedError() : new Error('RPC connection is closed.')); return; }
        connected = true;
        this.diagnostic('rpc.connected', { stage: 'connect', durationMs: performance.now() - startedAt });
        this.emit('connected'); resolve(socket);
      });
      socket.on('data', chunk => {
        if (this.socket !== socket || socket.destroyed) return;
        try {
          if (buffer.length + chunk.length > 4 * 1024 * 1024) throw new Error('RPC input exceeds its safety limit.');
          buffer = Buffer.concat([buffer, chunk]);
          let end;
          while ((end = buffer.indexOf(10)) >= 0) {
            if (end === 0 || end > MAX_FRAME) throw new Error('RPC frame exceeds its safety limit.');
            const line = buffer.subarray(0, end); buffer = buffer.subarray(end + 1);
            const message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line));
            this.receive(message, socket, line.length);
          }
          if (buffer.length > MAX_FRAME) throw new Error('RPC frame exceeds its safety limit.');
        } catch {
          const error = new Error('RPC server returned an invalid or oversized response.');
          idleFailure(error, 'request');
          this.failAll(error, socket);
          socket.destroy();
        }
      });
      socket.on('error', error => {
        socketFailure = error;
        idleFailure(error, connected ? 'request' : 'connect');
        if (!connected) {
          const failure = new Error(`Cannot connect to RPC (${error.code ?? 'network error'}).`);
          this.connectionErrors.set(failure, error);
          reject(failure);
        }
      });
      socket.on('close', () => {
        clearTimeout(connectTimer);
        if (!connected) reject(this.closed && !socketFailure ? closedError() : new Error('RPC connection closed before connecting.'));
        // An old socket may close after a new connection has already begun.
        // Reject only requests owned by this socket; never kill the new one.
        const error = new Error('Connection to the RPC server was lost.');
        this.failAll(error, socket, socketFailure ?? error);
        this.diagnostic('rpc.disconnected', { stage: 'connect', durationMs: performance.now() - startedAt });
        this.publishDisconnection(socket);
      });
    });
    this.connecting = connecting;
    try { return await connecting; }
    finally { if (this.connecting === connecting) this.connecting = null; }
  }
  failAll(error, socket = null, diagnosticError = error) {
    const affected = request => !socket || request.socket === socket;
    const draining = [...this.streams.values()].find(stream => stream.abandoned && affected(stream));
    if (draining && !isLocalCancellation(error) &&
        ![...this.pending.values(), ...this.streams.values()].some(request => !request.abandoned && affected(request))) {
      // Its consumer already settled as cancellation, but malformed data or a
      // timeout during the bounded drain is still a real transport failure.
      this.diagnostic('rpc.failed', { method: draining.method, stage: 'stream',
        durationMs: performance.now() - draining.startedAt, error: diagnosticError, unknownOutcome: false });
    }
    for (const [id, request] of this.pending) if (!socket || request.socket === socket) {
      if (request.diagnostic) request.diagnostic.error ??= diagnosticError;
      clearRequest(request); this.pending.delete(id); request.reject(lossError(request, error));
    }
    for (const [id, stream] of this.streams) if (!socket || stream.socket === socket) {
      if (stream.diagnostic) stream.diagnostic.error ??= diagnosticError;
      clearRequest(stream); this.streams.delete(id); stream.reject(lossError(stream, error));
    }
    // Queued requests belong to the connection on which they requested a slot.
    // Never silently reconnect or transmit a queued broadcast after that loss.
    for (const waiter of [...this.capacityWaiters]) if (!socket || waiter.socket === socket) waiter.fail(error);
    this.drainCapacity();
  }
  receive(message, socket = this.socket, frameBytes = 0) {
    if (!PLAIN(message) || message.jsonrpc !== '2.0') throw new Error('Invalid RPC envelope.');
    if (Object.hasOwn(message, 'id')) {
      const pending = this.pending.get(message.id);
      if (!pending || pending.socket !== socket || Object.hasOwn(message, 'method')) throw new Error('Unexpected RPC response.');
      const result = Object.hasOwn(message, 'result'), error = Object.hasOwn(message, 'error');
      if (result === error) throw new Error('RPC response must contain either result or error.');
      // Validate every part BEFORE removing pending, so malformed stream IDs
      // cannot strand an untracked promise when the socket is torn down.
      if (error) {
        if (!PLAIN(message.error) || !Number.isSafeInteger(message.error.code) || typeof message.error.message !== 'string') throw new Error('Invalid RPC error.');
        if (message.error.code === -32029) {
          const retry = message.error.data?.retry_after_ms;
          const wait = Number.isSafeInteger(retry) && retry > 0 ? Math.min(60000, retry) : this.windowMs;
          this.cooldowns.set(pending.method, performance.now() + wait);
        } else if (message.error.code === -32001) this.cooldowns.set('*', performance.now() + 1000);
        this.pending.delete(message.id); clearRequest(pending);
        pending.reject(new RpcError('RPC request failed. ' + message.error.message.slice(0, 180), message.error.code, message.error.data));
      } else if (pending.streaming) {
        const streamId = message.result?.stream_id;
        if (!PLAIN(message.result) || typeof streamId !== 'string' || streamId.length < 1 || streamId.length > 128 || this.streams.has(streamId)) throw new Error('Invalid stream identifier.');
        if (pending.diagnostic) pending.diagnostic.stage = 'stream';
        const stream = { ...pending, next: 0, records: 0, bytes: 0, phase: 'snapshot' };
        this.pending.delete(message.id); clearRequest(pending);
        this.streams.set(streamId, stream); this.resetStreamTimer(streamId, stream);
        stream.deadlineTimer = setTimeout(() => { this.failAll(new Error('Bounty transfer exceeded its total time limit.'), socket); socket.destroy(); }, 180000);
      } else {
        this.pending.delete(message.id); clearRequest(pending); pending.resolve(message.result);
      }
      this.drainCapacity();
      return;
    }
    if (Object.hasOwn(message, 'result') || Object.hasOwn(message, 'error')) throw new Error('Invalid RPC notification.');
    const params = message.params;
    if (message.method === 'stream.chunk' || message.method === 'stream.end') {
      if (!PLAIN(params) || typeof params.stream_id !== 'string') throw new Error('Invalid RPC stream envelope.');
      const stream = this.streams.get(params.stream_id);
      if (!stream || stream.socket !== socket) throw new Error('Unexpected RPC stream.');
      if (message.method === 'stream.end') {
        if (params.complete !== true || params.chunks !== stream.next || stream.phase !== 'end') {
          const failure = new Error('Bounty stream was incomplete; nothing from this block was applied.');
          let diagnosticError = failure;
          // stream.end puts its server error inside params. Retain only numeric
          // classifications for diagnostics, never its message or arbitrary data.
          if (params.complete === false && PLAIN(params.error) && Number.isSafeInteger(params.error.code)) {
            const data = PLAIN(params.error.data) && Number.isSafeInteger(params.error.data.node_code)
              ? { node_code: params.error.data.node_code } : undefined;
            diagnosticError = new RpcError(failure.message, params.error.code, data);
            // Explicit, well-framed server invalidations are recoverable. Keep
            // malformed success markers/counts and all other failures generic.
            if (params.chunks === stream.next && typeof params.error.message === 'string' &&
                [-32011, -32001].includes(params.error.code)) failure.code = params.error.code;
          }
          this.failAll(failure, socket, diagnosticError);
          socket.destroy();
        } else {
          this.streams.delete(params.stream_id); clearRequest(stream);
          stream.resolve({ chunks: stream.next, records: stream.records });
          this.drainCapacity();
        }
      } else {
        if (!Number.isSafeInteger(params.sequence) || params.sequence !== stream.next || !PLAIN(params.items) || stream.next >= 2002) throw new Error('RPC stream sequence mismatch.');
        const kind = params.items.type;
        if (stream.phase === 'snapshot') {
          if (kind !== 'snapshot') throw new Error('Bounty stream is missing its snapshot.');
          stream.phase = 'bounties';
        } else if (stream.phase === 'bounties') {
          if (kind === 'state') stream.phase = 'end';
          else if (kind !== 'bounties' || !Array.isArray(params.items.items)) throw new Error('Invalid bounty stream payload.');
        } else throw new Error('Unexpected data after bounty stream state.');
        if (kind === 'bounties') stream.records += params.items.items.length;
        stream.bytes += frameBytes;
        if (stream.records > 100000 || stream.bytes > 64 * 1024 * 1024) throw new Error('Bounty block exceeds the wallet resource limit; it was not applied.');
        stream.next++;
        if (!stream.abandoned) {
          try {
            const callbackResult = stream.onChunk(params.items);
            if (callbackResult && typeof callbackResult.then === 'function') {
              // Unawaited callbacks could apply chunks after stream failure/lock.
              Promise.resolve(callbackResult).catch(() => {});
              throw new Error('RPC stream callbacks must be synchronous.');
            }
          } catch (error) {
            if (!isLocalCancellation(error)) throw error;
            // STOP/lock discards the consumer's partial snapshot, not the shared
            // connection. Keep validating/draining the stream under the same
            // sequence, size, capacity, idle and total-deadline bounds.
            stream.abandoned = true; stream.onChunk = null; stream.reject(error);
          }
        }
        this.resetStreamTimer(params.stream_id, stream);
      }
      return;
    }
    if (message.method === 'subscription' && PLAIN(params)) this.emit('notification', params);
    else throw new Error('Unknown RPC notification.');
  }
  resetStreamTimer(id, stream) {
    clearTimeout(stream.timer);
    stream.timer = setTimeout(() => { this.failAll(new Error('Bounty transfer timed out.'), stream.socket); stream.socket.destroy(); }, this.timeoutMs);
  }
  waitForCapacity(socket, signal) {
    // queuedRequests already bounds these waiters. Reserve synchronously when
    // granting a slot so simultaneous promise continuations cannot exceed 12.
    return new Promise((resolve, reject) => {
      const waiter = { socket, signal, fail: null, grant: null };
      const remove = () => {
        const index = this.capacityWaiters.indexOf(waiter);
        if (index !== -1) this.capacityWaiters.splice(index, 1);
        signal.removeEventListener('abort', abort);
      };
      const abort = () => { waiter.fail(cancelledError()); this.drainCapacity(); };
      waiter.fail = error => { remove(); reject(error); };
      waiter.grant = () => {
        remove(); this.capacityReservations++;
        let held = true;
        resolve(() => {
          if (!held) return;
          held = false; this.capacityReservations--; this.drainCapacity();
        });
      };
      this.capacityWaiters.push(waiter);
      signal.addEventListener('abort', abort, { once: true });
      this.drainCapacity();
    });
  }
  drainCapacity() {
    while (this.capacityWaiters.length) {
      const waiter = this.capacityWaiters[0];
      if (waiter.signal.aborted || this.closed) { waiter.fail(cancelledError()); continue; }
      if (waiter.socket.destroyed || this.socket !== waiter.socket) { waiter.fail(new Error('RPC connection is closed.')); continue; }
      if (this.pending.size + this.streams.size + this.capacityReservations >= 12) return;
      waiter.grant();
    }
  }
  quotaWait(method, params, { reserve = false } = {}) {
    const key = method === 'getblockbounties' ? `${method}:${params.block_hash}` : method;
    const limit = method === 'getblockbounties' || method === 'gettransactions' ? 8 : this.quota;
    const now = performance.now();
    const cooldown = Math.max(this.cooldowns.get(method) ?? 0, this.cooldowns.get('*') ?? 0);
    if (cooldown > now) return Math.ceil(cooldown - now);
    for (const [k, times] of this.history) if (!times.length || times.at(-1) <= now - this.windowMs) this.history.delete(k);
    const entries = this.history.get(key) ?? [];
    while (entries.length && entries[0] <= now - this.windowMs) entries.shift();
    if (entries.length >= limit) return Math.max(1, entries[0] + this.windowMs - now + 10);
    if (reserve) {
      if (!this.history.has(key) && this.history.size >= 4096) throw new Error('RPC quota tracking capacity reached; retry after one minute.');
      entries.push(now); this.history.set(key, entries);
    }
    return 0;
  }
  async pace(method, params, { signal, reserve = true } = {}) {
    const waitingSignal = signal ? AbortSignal.any([this.abort.signal, signal]) : this.abort.signal;
    for (;;) {
      if (this.closed) throw closedError();
      if (waitingSignal.aborted) throw cancelledError();
      const wait = this.quotaWait(method, params, { reserve });
      if (!wait) return;
      await delay(wait, undefined, { signal: waitingSignal });
    }
  }
  async request(method, params = {}, { onChunk, signal } = {}) {
    const startedAt = performance.now(), diagnostic = { stage: 'request', error: null };
    // Never copy caller params, arbitrary method names, or response bodies into diagnostics.
    const metadata = typeof method === 'string' && Object.hasOwn(PARAMS, method) ? { method } : {};
    let queued = false, sent = false, unknownOutcome = false, cancelled = false, releaseCapacity;
    try {
      const clean = validateRpcParams(method, params);
      if ((method === 'getblockbounties') !== (typeof onChunk === 'function')) throw new Error('Bounty requests require a stream callback; other requests must not use one.');
      const waitingSignal = signal ? AbortSignal.any([this.abort.signal, signal]) : this.abort.signal;
      if (waitingSignal.aborted) throw cancelledError();
      if (this.queuedRequests >= 32) throw new Error('Too many queued RPC requests; retry shortly.');
      this.queuedRequests++; queued = true;
      await this.pace(method, clean, { signal: waitingSignal, reserve: false });
      if (waitingSignal.aborted) throw cancelledError();
      diagnostic.stage = 'connect';
      const socket = await waitForConnection(this.connect(), waitingSignal);
      diagnostic.stage = 'request';
      for (;;) {
        releaseCapacity = await this.waitForCapacity(socket, waitingSignal);
        if (waitingSignal.aborted) throw cancelledError();
        if (this.closed) throw closedError();
        if (socket.destroyed || this.socket !== socket) throw new Error('RPC connection is closed.');
        // A slot wait may outlive a quota window or receive a new server
        // cooldown. Debit only immediately before transmission, and never
        // occupy a global slot while waiting on one method's rate limit.
        if (!this.quotaWait(method, clean, { reserve: true })) break;
        releaseCapacity(); releaseCapacity = undefined;
        await this.pace(method, clean, { signal: waitingSignal, reserve: false });
      }
      if (this.nextId >= Number.MAX_SAFE_INTEGER) throw new Error('RPC request identifier space exhausted. Reopen the wallet.');
      const id = ++this.nextId;
      const encoded = JSON.stringify({ jsonrpc: '2.0', id, method, params: clean }) + '\n';
      if (Buffer.byteLength(encoded) > 900000 || socket.writableLength + Buffer.byteLength(encoded) > 2 * 1024 * 1024) throw new Error('RPC request exceeds the wallet output buffer limit.');
      return await new Promise((resolve, reject) => {
        if (waitingSignal.aborted) { reject(cancelledError()); return; }
        const request = { resolve, reject, method, socket, streaming: typeof onChunk === 'function', onChunk, sent: false, diagnostic, startedAt };
        request.timer = setTimeout(() => { this.failAll(new Error('RPC request timed out.'), socket); socket.destroy(); }, this.timeoutMs);
        this.pending.set(id, request);
        // The pending request now owns the same slot until its reply or final
        // stream.end, even if the stream consumer cancels and starts draining.
        releaseCapacity();
        try {
          // There is no await between the final cancellation check and write.
          // After write starts, preserve the real reply or unknown outcome;
          // an individual abort must never cause a retry or lose that result.
          request.sent = sent = true;
          socket.write(encoded, error => {
            if (error) { this.failAll(error, socket); socket.destroy(); }
          });
        } catch (error) { this.failAll(error, socket); socket.destroy(); }
      });
    } catch (error) {
      unknownOutcome = Boolean(error?.unknownOutcome);
      cancelled = error?.name === 'AbortError' && !unknownOutcome;
      if (cancelled && !sent) error.notSent = true;
      const details = { ...metadata, stage: diagnostic.stage, durationMs: performance.now() - startedAt, unknownOutcome };
      if (cancelled) this.diagnostic('rpc.cancelled', details);
      else {
        const cause = diagnostic.error ?? this.connectionErrors.get(error) ?? error;
        // A submitted broadcast still has an unknown outcome when local close
        // interrupts its reply; do not label that case as harmless cancellation.
        this.diagnostic('rpc.failed', { ...details, error: unknownOutcome && cause?.name === 'AbortError' ? error : cause });
      }
      throw error;
    } finally {
      releaseCapacity?.();
      if (queued) this.queuedRequests--;
      const durationMs = performance.now() - startedAt;
      if (!cancelled && durationMs >= 1000) this.diagnostic('rpc.slow', { ...metadata, stage: diagnostic.stage, durationMs, unknownOutcome });
    }
  }
  close() {
    this.closed = true; this.abort.abort();
    this.failAll(closedError()); this.socket?.destroy(); this.socket = null;
  }
}
