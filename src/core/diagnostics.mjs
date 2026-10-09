import { randomUUID } from 'node:crypto';
import { mkdir, lstat, open, rename, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { MAX_CONNECTION_LIMIT } from './connection-limits.mjs';

const EVENTS = new Set([
  'wallet.unlock_started', 'wallet.unlocked', 'wallet.snapshot_ready', 'wallet.render_ready',
  'wallet.started', 'wallet.closed', 'wallet.refresh_failed', 'wallet.refresh_cancelled', 'wallet.discovery_failed', 'wallet.discovery_cancelled', 'wallet.subscription_failed',
  'payment.prepare_started', 'payment.prepared', 'payment.prepare_failed', 'payment.prepare_cancelled',
  'claims.started', 'claims.stopped', 'claims.suspended', 'claims.resumed', 'claims.progress', 'claims.failed',
  'claim.started', 'claim.succeeded', 'claim.failed',
  'claim.cancelled', 'rpc.connected', 'rpc.disconnected', 'rpc.failed', 'rpc.cancelled', 'rpc.slow', 'helper.failed',
]);
const STAGES = new Set(['prepare', 'network', 'outputs', 'funding', 'signing', 'dns', 'proof', 'submit', 'refresh', 'discovery', 'connect', 'request', 'stream', 'lifecycle']);
const REASONS = new Set(['stop', 'locked', 'suspend', 'clear', 'unavailable', 'window-exit', 'sibling-proof', 'fatal', 'other']);
const DURATION_SCOPES = new Set(['stage', 'run']);
const PROCESS_SIGNALS = new Set([
  'SIGHUP', 'SIGINT', 'SIGQUIT', 'SIGILL', 'SIGTRAP', 'SIGABRT', 'SIGIOT', 'SIGBUS', 'SIGFPE',
  'SIGKILL', 'SIGUSR1', 'SIGSEGV', 'SIGUSR2', 'SIGPIPE', 'SIGALRM', 'SIGTERM', 'SIGSTKFLT',
  'SIGCHLD', 'SIGCONT', 'SIGSTOP', 'SIGTSTP', 'SIGTTIN', 'SIGTTOU', 'SIGURG', 'SIGXCPU',
  'SIGXFSZ', 'SIGVTALRM', 'SIGPROF', 'SIGWINCH', 'SIGIO', 'SIGPOLL', 'SIGPWR', 'SIGSYS', 'SIGBREAK',
]);
const METHODS = new Set([
  'getchaintip', 'getrecentblockhashes', 'getblockbounties', 'getaddressbalance',
  'getaddresshistory', 'getaddressutxos', 'getaddresschanges', 'gettransaction', 'gettransactions', 'sendrawtransaction',
  'getbountychanges', 'subscribebounties', 'subscribeaddress', 'subscribetip', 'unsubscribe',
]);
const OS_CODES = new Set([
  'ABORT_ERR', 'ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL', 'ETIMEDOUT', 'ESOCKETTIMEDOUT',
  'ERR_SOCKET_CONNECTION_TIMEOUT', 'ECONNREFUSED', 'ECONNRESET', 'ECONNABORTED',
  'ENETUNREACH', 'EHOSTUNREACH', 'ENETDOWN', 'EPIPE', 'ERR_SOCKET_CLOSED',
  'EACCES', 'EPERM', 'ENOENT', 'ENOSPC', 'EIO', 'EROFS', 'EMFILE', 'ENFILE', 'ENOMEM', 'ENOBUFS',
]);
const MESSAGES = Object.freeze({
  unknown: 'An operation failed; no safe error description is available.',
  cancelled: 'The operation was cancelled.',
  'broadcast-unknown': 'The broadcast outcome is unknown; check its status before retrying.',
  dns: 'DNS resolution failed.',
  network: 'The network connection failed or was interrupted.',
  timeout: 'The operation exceeded its time limit.',
  'tls-timeout': 'One TCP/TLS connection attempt timed out before producing a usable TLS capture. No claim transaction was broadcast from this attempt.',
  quota: 'The RPC request or rate limit was reached.',
  'index-not-ready': 'The node index is not ready; retry later.',
  'snapshot-stale': 'The bounty snapshot must be refreshed.',
  'data-unavailable': 'The requested data is not in the current index or recent-block window.',
  'bounty-unavailable': 'The bounty is no longer available for this claim.',
  'node-rejected': 'The node rejected the transaction or claim.',
  'helper-missing': 'The Automatic Claims helper is not installed.',
  'helper-failed': 'The Automatic Claims helper failed.',
  'helper-response': 'The Automatic Claims helper returned an invalid response.',
  'proof-failed': 'A verified claim proof could not be generated.',
  'target-not-met': 'No proof met the target within the configured attempt limit.',
  'destination-blocked': 'The destination resolved to no permitted network addresses.',
  'invalid-response': 'The node returned an invalid or incomplete response.',
  'resource-limit': 'An operation exceeded a local resource limit.',
  'wallet-locked': 'The wallet is locked or its session changed.',
  storage: 'A local file operation failed.',
});

// Read only own data properties. Never call a getter, toString, or toJSON on
// helper/RPC errors or caller-supplied metadata. Proxy failures are contained.
function own(value, key) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return undefined;
  try { return Object.getOwnPropertyDescriptor(value, key)?.value; } catch { return undefined; }
}
function numericCode(value) { return Number.isInteger(value) && value >= -2147483648 && value <= 2147483647; }

/** OS process status only: Windows may expose NTSTATUS as an unsigned DWORD. */
export function diagnosticProcessExit(exitCode, signal) {
  return {
    ...(Number.isInteger(exitCode) && exitCode >= -2147483648 && exitCode <= 0xffffffff ? { exitCode } : {}),
    ...(PROCESS_SIGNALS.has(signal) ? { signal } : {}),
  };
}

/** Canonical descriptions only: arbitrary peer/helper exception text never leaves this function. */
export function diagnosticError(error) { return describeError(error, true); }
function describeError(error, includeCause) {
  const cause = includeCause ? own(error, 'cause') : undefined;
  const inputCode = own(error, 'code') ?? own(cause, 'code');
  const rawMessage = own(error, 'message');
  const message = typeof rawMessage === 'string' ? rawMessage.slice(0, 2048) : '';
  let code = numericCode(inputCode) || OS_CODES.has(inputCode) ? inputCode : undefined;
  // The transport wraps connection failures in this fixed local message.
  if (code === undefined) {
    const match = /^Cannot connect to RPC \(([A-Z_]+)\)\.$/.exec(message);
    if (match && OS_CODES.has(match[1])) code = match[1];
  }
  const nodeCode = own(own(error, 'data'), 'node_code') ?? own(own(cause, 'data'), 'node_code');
  let category = 'unknown';
  if (own(error, 'unknownOutcome') === true || /^(?:Broadcast outcome is unknown|Claim broadcast was not confirmed|Broadcast was not confirmed)/i.test(message)) category = 'broadcast-unknown';
  else if (own(error, 'name') === 'AbortError' || code === 'ABORT_ERR' || /^Automatic Claims stopped\.?$/i.test(message)) category = 'cancelled';
  else if (code === -32029) category = 'quota';
  else if (code === -32001) category = 'index-not-ready';
  else if (code === -32020) category = 'node-rejected';
  else if (code === -32004) category = 'data-unavailable';
  else if (code === -32011) category = 'snapshot-stale';
  else if (['ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL'].includes(code)) category = 'dns';
  // This exact message is emitted by the local capture helper and allowlisted
  // by claim-pool. Neither an arbitrary timeout at stage "proof" nor a helper
  // watchdog/RPC timeout establishes that one TCP/TLS attempt timed out.
  else if (message === 'TLS connection timed out' && own(error, 'helperFatal') !== true && own(cause, 'helperFatal') !== true) category = 'tls-timeout';
  else if (['ETIMEDOUT', 'ESOCKETTIMEDOUT', 'ERR_SOCKET_CONNECTION_TIMEOUT'].includes(code)) category = 'timeout';
  else if (['ECONNREFUSED', 'ECONNRESET', 'ECONNABORTED', 'ENETUNREACH', 'EHOSTUNREACH', 'ENETDOWN', 'EPIPE', 'ERR_SOCKET_CLOSED'].includes(code)) category = 'network';
  else if (['EMFILE', 'ENFILE', 'ENOMEM', 'ENOBUFS'].includes(code)) category = 'resource-limit';
  else if (['EACCES', 'EPERM', 'ENOENT', 'ENOSPC', 'EIO', 'EROFS'].includes(code)) category = 'storage';
  else if (/^DNS resolution failed for /i.test(message) || /^Domain resolution failed\.?$/i.test(message)) category = 'dns';
  else if (/^domain resolved to no permitted TCP addresses/i.test(message)) category = 'destination-blocked';
  else if (/^no proof met the target in \d+ attempts/i.test(message)) category = 'target-not-met';
  else if (/helper is not installed|Install the Automatic Claims helper first/i.test(message)) category = 'helper-missing';
  else if (/timed? ?out|timeout|exceeded (?:its deadline|its total time limit)/i.test(message)) category = 'timeout';
  else if (/rate.?limit|RPC quota|Too many (?:queued )?RPC requests/i.test(message)) category = 'quota';
  else if (/index.{0,40}not ready|RPC request failed\. Not ready/i.test(message)) category = 'index-not-ready';
  else if (/bounty.{0,60}(?:no longer|unavailable|availability changed)|Bounty availability changed/i.test(message)) category = 'bounty-unavailable';
  else if (/node rejected (?:this claim|the transaction)/i.test(message)) category = 'node-rejected';
  else if (/helper (?:could not start|input failed|closed unexpectedly|failed)|Incompatible claims helper/i.test(message)) category = 'helper-failed';
  else if (/Malformed claims helper|Unknown claims helper|Invalid helper progress|Unexpected output after claims proof/i.test(message)) category = 'helper-response';
  else if (/TLS proof|without a verified proof|Invalid proof encoding|Proof does not match|proof generation failed|^TLS capture or proof validation failed$/i.test(message)) category = 'proof-failed';
  else if (/resource limit|(?:output|frame|diagnostic|safety|buffer) limit|capacity reached/i.test(message)) category = 'resource-limit';
  else if (/Wallet locked or changed|Unlock the wallet/i.test(message)) category = 'wallet-locked';
  else if (/RPC connection (?:is closed|closed|changed)|RPC client (?:is closed|closed)|Connection to the RPC server was lost|Cannot connect to RPC/i.test(message)) category = 'network';
  else if (/snapshot.{0,40}(?:coherent|incomplete)|bounty window is changing|journal requested a new snapshot/i.test(message)) category = 'snapshot-stale';
  else if (/(?:Invalid|Incomplete|Unexpected|Duplicate).{0,45}(?:RPC|bounty|snapshot|stream|transaction)|RPC (?:server )?returned|Bounty stream was incomplete|complete recent-block window/i.test(message)) category = 'invalid-response';
  else if (own(error, 'helperFatal') === true) category = 'helper-failed';
  const result = category === 'unknown' && cause !== undefined ? describeError(cause, false) : { category, message: MESSAGES[category] };
  if (code !== undefined) result.code = code;
  if (numericCode(nodeCode)) result.nodeCode = nodeCode;
  return result;
}

const NUMBERS = Object.freeze({
  claimId: [0, Number.MAX_SAFE_INTEGER], attempts: [0, 1000000000], queued: [0, 1000000000],
  completed: [0, 1000000000], failures: [0, 1000000000], retryDelayMs: [0, 86400000],
  durationMs: [0, 86400000], height: [0, 0xffffffff], bytes: [0, 1073741824],
  inputCount: [0, 1738],
  stderrBytes: [0, 1073741824], exitCode: [-2147483648, 0xffffffff],
  runId: [0, Number.MAX_SAFE_INTEGER], operationsStarted: [0, 1000000000], operationsCompleted: [0, 1000000000],
  operationsFailed: [0, 1000000000], operationsCancelled: [0, 1000000000], captures: [0, 1000000000], suppressedEvents: [0, 1000000000],
  prepareActive: [0, 4], dnsActive: [0, 2], captureActive: [0, MAX_CONNECTION_LIMIT], submitActive: [0, 4],
  activeMaxDurationMs: [0, Number.MAX_SAFE_INTEGER], durationTotalMs: [0, Number.MAX_SAFE_INTEGER], durationMaxMs: [0, Number.MAX_SAFE_INTEGER],
  cancelledStop: [0, 1000000000], cancelledLocked: [0, 1000000000], cancelledSuspend: [0, 1000000000],
  cancelledClear: [0, 1000000000], cancelledUnavailable: [0, 1000000000], cancelledWindowExit: [0, 1000000000],
  cancelledSiblingProof: [0, 1000000000], cancelledFatal: [0, 1000000000], cancelledOther: [0, 1000000000],
});
function sanitize(details) {
  const clean = {};
  const stage = own(details, 'stage'), method = own(details, 'method');
  if (STAGES.has(stage)) clean.stage = stage;
  if (METHODS.has(method)) clean.method = method;
  const reason = own(details, 'reason'), durationScope = own(details, 'durationScope');
  if (REASONS.has(reason)) clean.reason = reason;
  if (DURATION_SCOPES.has(durationScope)) clean.durationScope = durationScope;
  const signal = own(details, 'signal');
  if (PROCESS_SIGNALS.has(signal)) clean.signal = signal;
  for (const [key, [minimum, maximum]] of Object.entries(NUMBERS)) {
    const value = own(details, key);
    if (Number.isFinite(value) && value >= minimum && value <= maximum && (key === 'durationMs' || Number.isSafeInteger(value))) clean[key] = value;
  }
  for (const key of ['enabled', 'paused', 'unknownOutcome', 'helperReady']) {
    const value = own(details, key);
    if (typeof value === 'boolean') clean[key] = value;
  }
  const error = own(details, 'error');
  if (error !== undefined) clean.error = Object.freeze(diagnosticError(error));
  return Object.freeze(clean);
}
function limit(value, fallback, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum ? value : fallback;
}

/** Best-effort, bounded local JSONL diagnostics. No network or synchronous disk I/O. */
export class DiagnosticLog {
  #directory;
  #file = '';
  #status = 'initializing';
  #session = randomUUID();
  #sequence = 0;
  #dropped = 0;
  #errors = 0;
  #recent = [];
  #queue = [];
  #worker = null;
  #initialized = false;
  #size = 0;
  #writing = false;
  #maxBytes;
  #backups;
  #maxPending;
  #historyLimit;

  constructor({ directory, maxBytes = 2 * 1024 * 1024, backups = 2, maxPending = 256, historyLimit = 50 } = {}) {
    this.#maxBytes = limit(maxBytes, 2 * 1024 * 1024, 256, 64 * 1024 * 1024);
    this.#backups = limit(backups, 2, 0, 5);
    this.#maxPending = limit(maxPending, 256, 1, 4096);
    this.#historyLimit = limit(historyLimit, 50, 0, 200);
    try {
      if (typeof directory !== 'string' || !directory || directory.includes('\0')) throw new Error();
      this.#directory = resolve(directory, 'logs');
      this.#file = resolve(this.#directory, 'diagnostics.jsonl');
      this.#schedule();
    } catch { this.#status = 'unavailable'; }
  }

  record(event, details = {}) {
    try {
      if (!EVENTS.has(event)) { this.#drop(); return; }
      const row = Object.freeze({ timestamp: new Date().toISOString(), session: this.#session, sequence: ++this.#sequence, event, details: sanitize(details) });
      const failure = !!row.details.error || event.endsWith('.failed') || event.endsWith('_failed');
      if (failure) {
        this.#errors = Math.min(Number.MAX_SAFE_INTEGER, this.#errors + 1);
        // Current-session failures remain visible through later successes.
        // Complete event history, including previous sessions, is on disk.
        if (this.#historyLimit) {
          this.#recent.push(row);
          if (this.#recent.length > this.#historyLimit) this.#recent.shift();
        }
      }
      if (this.#status === 'unavailable' || this.#queue.length + Number(this.#writing) >= this.#maxPending) { this.#drop(); return; }
      const line = `${JSON.stringify(row)}\n`;
      const bytes = Buffer.byteLength(line);
      if (bytes > this.#maxBytes) { this.#drop(); return; }
      this.#queue.push({ line, bytes });
      this.#schedule();
    } catch { this.#drop(); }
  }

  snapshot() {
    return {
      status: this.#status, file: this.#file, dropped: this.#dropped, errors: this.#errors,
      recent: this.#recent.map(row => ({ ...row, details: { ...row.details, ...(row.details.error ? { error: { ...row.details.error } } : {}) } })),
    };
  }

  async flush() {
    try { while (this.#worker) await this.#worker; } catch { /* Logging must never reject wallet shutdown. */ }
  }

  #drop(count = 1) { this.#dropped = Math.min(Number.MAX_SAFE_INTEGER, this.#dropped + count); }
  #backup(index) { return resolve(this.#directory, `diagnostics.${index}.jsonl`); }
  #schedule() {
    if (this.#worker || this.#status === 'unavailable') return;
    this.#worker = Promise.resolve().then(() => this.#drain()).catch(() => {
      this.#status = 'unavailable';
      this.#drop(this.#queue.length + Number(this.#writing));
      this.#writing = false;
      this.#queue = [];
    }).finally(() => {
      this.#worker = null;
      if (this.#queue.length) this.#schedule();
    });
  }
  async #initialize() {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    for (let index = 0; index <= 5; index++) {
      const file = index === 0 ? this.#file : this.#backup(index);
      const stat = await lstat(file).catch(error => { if (error.code !== 'ENOENT') throw error; return null; });
      if (!stat) continue;
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Diagnostic target is not a regular file');
      // Enforce bounds even when limits change between launches. Only managed
      // diagnostic files are touched; no directory traversal or wildcard removal.
      if (index > this.#backups || stat.size > this.#maxBytes) await rm(file);
      else if (index === 0) this.#size = stat.size;
    }
    this.#initialized = true;
  }
  async #rotate() {
    if (!this.#backups) await rm(this.#file, { force: true });
    else {
      await rm(this.#backup(this.#backups), { force: true });
      for (let index = this.#backups - 1; index >= 0; index--) {
        await rename(index === 0 ? this.#file : this.#backup(index), this.#backup(index + 1)).catch(error => { if (error.code !== 'ENOENT') throw error; });
      }
    }
    this.#size = 0;
  }
  async #drain() {
    if (!this.#initialized) await this.#initialize();
    let handle;
    try {
      handle = await open(this.#file, 'a', 0o600);
      this.#status = 'ready';
      while (this.#queue.length) {
        const entry = this.#queue.shift();
        this.#writing = true;
        if (this.#size + entry.bytes > this.#maxBytes) {
          await handle.sync();
          await handle.close();
          handle = null;
          await this.#rotate();
          handle = await open(this.#file, 'a', 0o600);
        }
        await handle.writeFile(entry.line, 'utf8');
        this.#size += entry.bytes;
        this.#writing = false;
      }
      await handle.sync();
    } finally { if (handle) await handle.close(); }
  }
}
