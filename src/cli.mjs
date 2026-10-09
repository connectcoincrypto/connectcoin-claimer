#!/usr/bin/env node
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSea } from 'node:sea';
import { VERSION } from './version.mjs';
import { ensureConfig, readConfig } from './config.mjs';
import { getClaimsHelper } from './core/claims.mjs';
import { acquireLock } from './lock.mjs';
import { ClaimerService } from './service.mjs';

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

export async function main(args = process.argv.slice(2)) {
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
  if (!getClaimsHelper({ basePath })) throw new Error('Claims helper is missing. Keep the whole extracted package together, or run npm run build:claims.');
  if (options.mode === 'check') { console.log('Configuration valid.'); return 0; }
  const unlock = await acquireLock(`${options.configPath}.lock`);
  let service, timer, stopping, resolveDone, exitCode = 0;
  const done = new Promise(resolveDonePromise => { resolveDone = resolveDonePromise; });
  const stop = () => {
    if (stopping) return stopping;
    clearInterval(timer);
    stopping = (async () => {
      try { await service?.stop(); }
      finally { resolveDone(); }
    })();
    return stopping;
  };
  const onSignal = () => { console.log('\nStopping claims...'); void stop().catch(error => { exitCode = 1; console.error(safeText(error.message)); }); };
  process.on('SIGINT', onSignal); process.on('SIGTERM', onSignal);
  if (process.platform === 'win32') process.on('SIGBREAK', onSignal);
  try {
    service = new ClaimerService({ config, basePath, statePath: `${options.configPath}.state.json`, emit: (event, details = {}) => {
      if (event === 'error') {
        console.error(`${details.fatal ? 'Stopped' : 'Waiting/retrying'}: ${safeText(details.message)}`);
        if (details.fatal) { exitCode = 1; queueMicrotask(() => { void stop().catch(error => console.error(safeText(error.message))); }); }
      } else if (event === 'broadcast') console.log(`Claim ${safeText(details.status)}: ${safeText(details.txid)}`);
      else if (event === 'discovery') console.log(`Discovery: height ${safeText(details.height)}, ${safeText(details.available)} available bounties.`);
    } });
    console.log(`ConnectCoin Claimer ${VERSION} | mainnet`);
    console.log(`Receiving address: ${config.receivingAddress}`);
    console.log(`Limits: ${config.connectionsPerSecond} starts/s, ${config.concurrency} simultaneous; minimum ${config.minExpectedReturn} connects/connection-second.`);
    console.log(`RPC: ${config.rpc.host}:${config.rpc.port}. Press Ctrl+C to stop.`);
    const display = () => {
      const state = service.snapshot(), metrics = state.metrics ?? {};
      console.log(`[${safeText(state.status ?? state.engine?.status ?? 'running')}] ` +
        `${Number(metrics.connectionsPerSecond ?? 0).toFixed(1)} connections/s (last 10s) | active ${metrics.activeConnections ?? 0} | ` +
        `started ${metrics.connectionsStarted ?? 0} | valid ${metrics.valid ?? 0} | failed ${metrics.invalid ?? 0} | ` +
        `target reached ${metrics.targetReached ?? 0} | submitted ${state.claims?.completed ?? 0}`);
    };
    timer = setInterval(display, 5000);
    try { await service.start(); }
    catch (error) { if (!stopping || error.name !== 'AbortError') throw error; }
    if (!stopping) display();
    await done;
    await stopping;
    return exitCode;
  } finally {
    clearInterval(timer);
    process.removeListener('SIGINT', onSignal); process.removeListener('SIGTERM', onSignal); process.removeListener('SIGBREAK', onSignal);
    await service?.stop();
    await unlock();
  }
}

if (isSea() || (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))) {
  main().then(code => { process.exitCode = code; }).catch(error => { console.error(`Error: ${safeText(error.message)}`); process.exitCode = 1; });
}
