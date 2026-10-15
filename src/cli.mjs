#!/usr/bin/env node
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSea } from 'node:sea';
import { VERSION } from './version.mjs';
import { ensureConfig, readConfig } from './config.mjs';
import { getClaimsHelper } from './core/claims.mjs';
import { acquireLock } from './lock.mjs';
import { ClaimerService } from './service.mjs';
import { diagnosticError } from './core/diagnostics.mjs';

const HELP = `ConnectCoin Claimer ${VERSION}
Usage: claimer [--config PATH] [--check | --init]
       claimer --help | --version

With no configuration, creates claimer.conf and exits without connecting.
Set receiving_address, then run again to start Automatic Claims on mainnet.
--config PATH  Use a specific configuration file (relative to the working directory).
--init         Create a missing configuration without running or overwriting it.
--check        Validate configuration and helper availability offline; no claims.
Ctrl+C         Stop connections and exit cleanly.

Packaged default: claimer.conf beside claimer.exe (or claimer on Linux).
Source default: claimer.conf in the current working directory.
No seed, private key or wallet password is required or accepted.
`;

export function parseArguments(args, { packaged = isSea(), cwd = process.cwd(), executable = process.execPath } = {}) {
  let configPath, mode = 'run';
  const seen = new Set();
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (seen.has(arg)) throw new Error(`Duplicate argument: ${arg}`);
    seen.add(arg);
    if (arg === '--config') {
      const value = args[++index];
      if (!value || value.startsWith('--') || value.includes('\0')) throw new Error('--config requires a file path.');
      configPath = resolve(cwd, value);
    } else if (['--help', '--version', '--check', '--init'].includes(arg)) {
      if (mode !== 'run') throw new Error('Choose only one of --help, --version, --check or --init.');
      mode = arg.slice(2);
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  return { mode, configPath: configPath ?? resolve(packaged ? dirname(executable) : cwd, 'claimer.conf') };
}
const safeText = value => String(value ?? '').replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').slice(0, 1500);
const RPC_METHODS = new Set(['getchaintip', 'getrecentblockhashes', 'getblockbounties', 'getaddressbalance',
  'getaddresshistory', 'getaddressutxos', 'getaddresschanges', 'gettransaction', 'gettransactionstatus', 'gettransactions',
  'sendrawtransaction', 'getbountychanges', 'subscribebounties', 'subscribeaddress', 'subscribetip', 'unsubscribe']);
const RPC_STAGES = new Set(['connect', 'request', 'stream']);
const RPC_SOURCES = new Set(['pre-write', 'rpc-reply', 'request-timeout', 'stream-timeout', 'stream-deadline',
  'stream-incomplete', 'socket-close', 'socket-write', 'protocol', 'client-close']);
const ERROR_CATEGORIES = new Set(['unknown', 'cancelled', 'broadcast-unknown', 'dns', 'network', 'timeout',
  'tls-timeout', 'quota', 'index-not-ready', 'snapshot-stale', 'data-unavailable', 'bounty-unavailable',
  'node-rejected', 'helper-missing', 'helper-failed', 'helper-response', 'proof-failed', 'target-not-met',
  'destination-blocked', 'invalid-response', 'resource-limit', 'wallet-locked', 'storage']);
const BROADCAST_NOTES = Object.freeze({
  accepted: '',
  pending: 'saved for reconciliation; only this outpoint is reserved',
  unknown: 'reply uncertain; saved for reconciliation; only this outpoint is reserved',
  'recovered-accepted': 'accepted result recovered; exact transaction retained until block confirmation',
  confirmed: 'block confirmation validated; saved transaction bytes compacted',
  'reconciliation-pending': 'still reserved; identical saved transaction retained for another check',
  'quarantined-legacy-no-bytes': 'legacy record has no saved proof; this outpoint needs review; other claims continue',
  'quarantined-address-mismatch': 'saved receiving address differs; this outpoint needs review; other claims continue',
});
const booleanLabel = value => value === true ? 'yes' : value === false ? 'no' : 'unknown';
const numericLabel = value => Number.isSafeInteger(value) && value >= 0 ? value : '?';
function reasonLabel(reason) {
  // Never echo arbitrary messages, causes, response bodies, or proof bytes.
  const sanitized = diagnosticError(reason);
  const category = ERROR_CATEGORIES.has(reason?.category) ? reason.category : sanitized.category;
  const nodeCode = Number.isInteger(reason?.nodeCode) && reason.nodeCode >= -2147483648 && reason.nodeCode <= 2147483647
    ? reason.nodeCode : sanitized.nodeCode;
  return `category=${category}` + (sanitized.code === undefined ? '' : ` code=${sanitized.code}`) +
    (nodeCode === undefined ? '' : ` node_code=${nodeCode}`);
}

export function formatServiceEvent(event, details = {}) {
  if (event === 'discovery') return `Discovery: height ${numericLabel(details.height)}, ${numericLabel(details.available)} available bounties.`;
  if (event === 'discovery-reset') {
    const reason = ['initial', 'journal-reset', 'data-unavailable', 'cursor-invalid'].includes(details.reason) ? details.reason : 'journal-reset';
    const code = [-32004, -32011].includes(details.code) ? ` (RPC ${details.code})` : '';
    return `Discovery reset: ${reason}${code}; ` + (reason === 'initial' ? 'preparing a coherent catalog.'
      : 'no helper restart requested; new preparations and broadcasts wait for a coherent catalog.');
  }
  if (event === 'rpc-diagnostic') {
    return `RPC failure: method=${RPC_METHODS.has(details.method) ? details.method : 'unknown'} ` +
      `stage=${RPC_STAGES.has(details.stage) ? details.stage : 'unknown'} source=${RPC_SOURCES.has(details.failureSource) ? details.failureSource : 'unknown'} ` +
      `${reasonLabel(details.error)} sent=${booleanLabel(details.sent)} not_sent=${booleanLabel(details.notSent)} unknown_outcome=${booleanLabel(details.unknownOutcome)}.`;
  }
  if (event === 'broadcast') {
    const status = typeof details.status === 'string' && Object.hasOwn(BROADCAST_NOTES, details.status) ? details.status : 'update';
    const txid = typeof details.txid === 'string' && /^[0-9a-f]{64}$/.test(details.txid) ? details.txid : 'unavailable';
    const note = BROADCAST_NOTES[status];
    return `Claim ${status}: ${txid}` + (note ? ` | ${note}` : '') + (details.reason ? ` | ${reasonLabel(details.reason)}` : '');
  }
  return null;
}

export function formatMetricsLine(state) {
  const metrics = state.metrics ?? {};
  return `[${safeText(state.status ?? state.engine?.status ?? 'running')}] ` +
    `${Number(metrics.connectionsPerSecond ?? 0).toFixed(1)} connections/s (last 10s) | active ${metrics.activeConnections ?? 0} | ` +
    `started ${metrics.connectionsStarted ?? 0} | valid ${metrics.valid ?? 0} | failed ${metrics.invalid ?? 0} | ` +
    `target reached ${metrics.targetReached ?? 0} | submitted ${state.claims?.completed ?? 0}`;
}

export async function main(args = process.argv.slice(2), {
  serviceFactory = options => new ClaimerService(options), helperAvailable = getClaimsHelper,
} = {}) {
  const options = parseArguments(args);
  if (options.mode === 'help') { console.log(HELP); return 0; }
  if (options.mode === 'version') { console.log(VERSION); return 0; }
  const created = await ensureConfig(options.configPath);
  if (created || options.mode === 'init') {
    console.log(`${created ? 'Created' : 'Kept existing configuration:'} ${safeText(options.configPath)}`);
    if (created) console.log('Set receiving_address to your own mainnet address, then run again. No connections were made.');
    return options.mode === 'init' ? 0 : created ? 2 : 0;
  }
  const config = await readConfig(options.configPath);
  const basePath = isSea() ? dirname(process.execPath) : resolve(dirname(fileURLToPath(import.meta.url)), '..');
  if (!helperAvailable({ basePath })) throw new Error('Claims helper is missing. Keep the whole extracted package together, or run npm run build:claims.');
  if (options.mode === 'check') { console.log('Configuration valid.'); return 0; }
  const unlock = await acquireLock(`${options.configPath}.lock`);
  let service, timer, stopping, resolveDone, exitCode = 0;
  const done = new Promise(resolveDonePromise => { resolveDone = resolveDonePromise; });
  const stop = () => {
    if (stopping) return stopping;
    clearInterval(timer);
    stopping = (async () => {
      try {
        for (;;) {
          try { await service?.stop(); break; }
          catch (error) {
            exitCode = 1;
            if (!service?.heldProofs?.size) throw error;
            // Stopping has already revoked admission and drained the network.
            // A failed atomic write can still leave the only verified winner
            // in memory. Keep its owner AND the process lock alive, and retry
            // persistence only. Never unref this timer or restart claims.
            console.error(`Cannot finish shutdown: verified proofs remain only in memory. ` +
              `Restore writable storage; retrying in 5 seconds. Do not terminate this process. ${safeText(error.message)}`);
            await new Promise(resolveRetry => setTimeout(resolveRetry, 5000));
          }
        }
      }
      finally { resolveDone(); }
    })();
    return stopping;
  };
  const onSignal = () => { console.log('\nStopping claims...'); void stop().catch(error => { exitCode = 1; console.error(safeText(error.message)); }); };
  process.on('SIGINT', onSignal); process.on('SIGTERM', onSignal);
  if (process.platform === 'win32') process.on('SIGBREAK', onSignal);
  try {
    service = serviceFactory({ config, basePath, statePath: `${options.configPath}.state.json`, emit: (event, details = {}) => {
      if (event === 'error') {
        console.error(`${details.fatal ? 'Stopped' : 'Waiting/retrying'}: ${safeText(details.message)}`);
        if (details.fatal) { exitCode = 1; queueMicrotask(() => { void stop().catch(error => console.error(safeText(error.message))); }); }
      } else {
        const line = formatServiceEvent(event, details);
        if (line) console.log(line);
      }
    } });
    console.log(`ConnectCoin Claimer ${VERSION} | mainnet`);
    console.log(`Receiving address: ${config.receivingAddress}`);
    console.log(`Limits: ${config.connectionsPerSecond} starts/s, ${config.concurrency} simultaneous; minimum ${config.minExpectedReturn} connects/connection-second.`);
    console.log(`RPC: ${config.rpc.host}:${config.rpc.port}. Press Ctrl+C to stop.`);
    const display = () => console.log(formatMetricsLine(service.snapshot()));
    timer = setInterval(display, 5000);
    try { await service.start(); }
    catch (error) { if (!stopping || error.name !== 'AbortError') throw error; }
    if (!stopping) display();
    await done;
    await stopping;
    return exitCode;
  } finally {
    clearInterval(timer);
    try {
      // Startup failures must use the same preservation barrier as signals and
      // fatal events. Keep signal handlers installed during a storage retry.
      await stop();
      await unlock();
    } finally {
      process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal); process.removeListener('SIGBREAK', onSignal);
    }
  }
}

if (isSea() || (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))) {
  main().then(code => { process.exitCode = code; }).catch(error => { console.error(`Error: ${safeText(error.message)}`); process.exitCode = 1; });
}
