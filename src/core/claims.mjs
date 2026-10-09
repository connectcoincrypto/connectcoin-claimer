import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { validateAttemptStats } from './claim-priority.mjs';
import { MAX_CONNECTION_LIMIT } from './connection-limits.mjs';

const BASE = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const CONTEXT_KEYS = ['domain', 'txid', 'input_index', 'connection_work_target', 'root_certificates_version', 'signature_algorithms_mask', 'validation_time'];
const HASH = /^[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// Legacy one-shot development bridge only. The wallet's continuous scheduler
// uses CONNECTION_DEFAULTS in claim-pool.mjs: no batch timeout/attempt limit.
export const DEFAULT_CLAIM_OPTIONS = Object.freeze({ connectionsPerSecond: 100, concurrency: 100, overallTimeout: 180, maxAttempts: 1000 });

// Only explicit API-recognized rejections are recoverable. Already-known (-27),
// malformed replies and unknown broadcast outcomes must remain user-visible.
export function isKnownClaimRejection(error) {
  return error?.code === -32020 && [-22, -25, -26, -8].includes(error.data?.node_code) && !error.unknownOutcome;
}

function integer(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`Invalid ${name}`);
  return value;
}
export function validateClaimOptions(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) throw new Error('Invalid claim options');
  if (Object.keys(options).some((key) => !Object.hasOwn(DEFAULT_CLAIM_OPTIONS, key))) throw new Error('Unknown claim option');
  const result = { ...DEFAULT_CLAIM_OPTIONS, ...options };
  integer(result.connectionsPerSecond, 1, MAX_CONNECTION_LIMIT, 'connections per second');
  integer(result.concurrency, 1, MAX_CONNECTION_LIMIT, 'simultaneous connections');
  integer(result.overallTimeout, 1, 600, 'claim timeout');
  integer(result.maxAttempts, 1, 100000, 'claim attempts');
  return Object.freeze(result);
}
export function validateClaimContext(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== CONTEXT_KEYS.length || CONTEXT_KEYS.some((key) => !Object.hasOwn(input, key))) throw new Error('Invalid public claim context');
  const context = Object.fromEntries(CONTEXT_KEYS.map((key) => [key, input[key]]));
  if (typeof context.domain !== 'string' || !DOMAIN.test(context.domain) || /(?:^|\.)(?:localhost|local|internal)$/.test(context.domain)) throw new Error('A public DNS domain is required');
  if (typeof context.txid !== 'string' || !HASH.test(context.txid) || typeof context.connection_work_target !== 'string' || !HASH.test(context.connection_work_target)) throw new Error('Invalid claim hash');
  integer(context.input_index, 0, 0xffffffff, 'claim input index');
  if (context.root_certificates_version !== 1) throw new Error('Unsupported root certificate bundle');
  integer(context.signature_algorithms_mask, 1, 7, 'signature policy');
  integer(context.validation_time, 1, 253402300799, 'chain median time');
  return Object.freeze(context);
}

function aborted(message = 'Automatic Claims stopped') {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

function report(callback, event, details) {
  try { Promise.resolve(callback(event, details)).catch(() => {}); } catch { /* Diagnostics must never change claim behavior. */ }
}

/** Resources must be outside ASAR. An absent helper is explicit, never silently downloaded. */
export function getClaimsHelper({ basePath = BASE, resourcesPath } = {}) {
  const executable = process.platform === 'win32' ? 'connectwallet-claims.exe' : 'connectwallet-claims';
  const candidates = [resourcesPath && resolve(resourcesPath, 'claims-helper', executable), resolve(basePath, 'helpers/bin/connectwallet-claims', executable)].filter(Boolean);
  for (const command of candidates) if (existsSync(command)) return { command, args: [], packaged: true };
  const command = resolve(basePath, '.claims-venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  if (existsSync(command)) return { command, args: ['-I', resolve(basePath, 'helpers/claims_bridge.py')], packaged: false };
  return null;
}

/** Legacy one-shot tooling bridge, not used by the desktop claims engine. No keys cross it. */
export function createProofRunner({ helper, basePath = BASE, resourcesPath, spawnProcess = spawn, onDiagnostic = () => {} } = {}) {
  return async function generateProof(contextInput, { signal, options, onProgress = () => {} } = {}) {
    const context = validateClaimContext(contextInput);
    const limits = validateClaimOptions(options);
    if (signal?.aborted) throw aborted();
    const runtime = helper ?? getClaimsHelper({ basePath, resourcesPath });
    if (!runtime) throw new Error('Automatic Claims helper is not installed. Run npm run setup:claims or use a packaged desktop release.');
    return new Promise((accept, reject) => {
      const started = performance.now();
      let child;
      let timer;
      let output = '';
      let outputBytes = 0;
      let stderrBytes = 0;
      let result;
      let failure;
      let settled = false;
      let exitCode;
      let completedAttempts = 0;
      const stop = (error) => {
        failure ??= error;
        // Terminate the sole helper process, including its worker threads/sockets.
        // No shell and no descendant process tree is created by the helper.
        if (child && !child.killed) child.kill('SIGKILL');
      };
      const onAbort = () => stop(aborted());
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        if (error && error.name !== 'AbortError') report(onDiagnostic, 'helper.failed', {
          stage: 'proof', error, durationMs: Math.round(performance.now() - started),
          bytes: outputBytes, stderrBytes, ...(Number.isInteger(exitCode) ? { exitCode } : {}),
        });
        if (error) reject(error); else accept(result.proof);
      };
      const receive = (line) => {
        let message;
        try { message = JSON.parse(line); } catch { throw new Error('Malformed claims helper response'); }
        if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Malformed claims helper response');
        if (result) throw new Error('Unexpected output after claims proof');
        if (message.type === 'progress') {
          integer(message.attempts, 0, limits.maxAttempts, 'progress attempts');
          if (typeof message.elapsed !== 'number' || !Number.isFinite(message.elapsed) || message.elapsed < 0) throw new Error('Invalid helper progress');
          if (message.attemptStats === undefined) throw new Error('Claims helper lacks TLS statistics. Update the app or run npm run build:claims.');
          validateAttemptStats(message.attemptStats, limits.maxAttempts);
          if (message.attemptStats.completed < completedAttempts || message.attemptStats.completed !== message.attempts) throw new Error('Invalid helper attempt sequence');
          completedAttempts = message.attemptStats.completed;
          try { onProgress({ attempts: message.attempts, elapsed: message.elapsed, attemptStats: message.attemptStats }); } catch { /* UI callbacks cannot compromise cancellation. */ }
        } else if (message.type === 'result') {
          if (!completedAttempts) throw new Error('Claims helper lacks TLS statistics. Update the app or run npm run build:claims.');
          integer(message.attempts, 1, limits.maxAttempts, 'proof attempts');
          if (message.attempts !== completedAttempts) throw new Error('Invalid helper final attempt sequence');
          const returnedContext = validateClaimContext(message.context);
          if (CONTEXT_KEYS.some((key) => returnedContext[key] !== context[key]) || message.verified !== true) throw new Error('Proof does not match the prepared claim');
          if (typeof message.proof !== 'string' || !/^02(?:[0-9a-f]{2})+$/.test(message.proof) || message.proof.length > 131072) throw new Error('Invalid proof encoding');
          result = message;
        } else if (message.type === 'error') {
          if (message.message === 'unknown helper arguments') throw new Error('Incompatible claims helper: RSA public-exponent limit must be 64 bits. Update the app or run npm run build:claims.');
          throw new Error(typeof message.message === 'string' ? message.message.slice(0, 500) : 'TLS proof generation failed');
        } else throw new Error('Unknown claims helper response');
      };
      try {
        const environmentNames = new Set(['path', 'systemroot', 'systemdrive', 'windir', 'temp', 'tmp', 'tmpdir', 'home', 'userprofile', 'localappdata', 'appdata', 'user', 'username', 'lang', 'lc_all', 'tz']);
        const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => environmentNames.has(key.toLowerCase())));
        // Do not inherit RPC credentials, developer tokens, Python module overrides,
        // or any application-private environment into the network-facing helper.
        // Older helpers reject this unknown suffix before reading input or
        // opening sockets; never retry without the required RSA policy.
        child = spawnProcess(runtime.command, [...(runtime.args ?? []), '--require-rsa-exponent-64'], { shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], env: { ...environment, PYTHONNOUSERSITE: '1', PYTHONUNBUFFERED: '1' } });
        child.once('error', (error) => finish(new Error(`Claims helper could not start: ${error.message}`)));
        child.stdout.on('data', (chunk) => {
          if (failure || settled) return;
          outputBytes += chunk.length;
          // Throttled progress carries a bounded last-100 TLS sample window;
          // allow 600 seconds plus the final snapshot and a 64-KiB proof.
          if (outputBytes > 4 * 1024 * 1024) { stop(new Error('Claims helper output limit exceeded')); return; }
          output += chunk.toString('utf8');
          try {
            let end;
            while ((end = output.indexOf('\n')) !== -1) {
              if (end > 160 * 1024) throw new Error('Claims helper frame limit exceeded');
              const line = output.slice(0, end);
              output = output.slice(end + 1);
              receive(line);
            }
            if (output.length > 160 * 1024) throw new Error('Claims helper frame limit exceeded');
          } catch (error) { stop(error); }
        });
        child.stderr.on('data', (chunk) => {
          stderrBytes += chunk.length;
          if (stderrBytes > 8192) stop(new Error('Claims helper diagnostic limit exceeded'));
        });
        child.stdin.on('error', (error) => stop(new Error(`Claims helper input failed: ${error.message}`)));
        child.once('close', (code) => {
          exitCode = code;
          if (signal?.aborted) failure ??= aborted();
          if (failure) finish(failure);
          else if (code !== 0 || !result || output.trim()) finish(new Error('Claims helper ended without a verified proof'));
          else finish();
        });
        timer = setTimeout(() => stop(new Error('TLS proof generation exceeded its deadline')), (limits.overallTimeout + 15) * 1000);
        signal?.addEventListener('abort', onAbort, { once: true });
        if (signal?.aborted) onAbort();
        if (!failure) child.stdin.end(`${JSON.stringify({ context, options: limits })}\n`);
      } catch (error) { if (child) stop(error); else finish(error); }
    });
  };
}

export { ClaimsEngine } from './claims-engine.mjs';
