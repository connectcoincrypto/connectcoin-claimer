import { open } from 'node:fs/promises';
import { decodeAddress } from './core/crypto.mjs';
import { validateRpcEndpoint } from './core/config.mjs';
import { MAX_CONNECTION_LIMIT } from './core/connection-limits.mjs';

export const CONFIG_TEMPLATE = `# ConnectCoin Claimer - mainnet. Public receiving address only.
receiving_address=
max_connections_per_second=100
max_simultaneous_connections=100
min_connects_per_connection_second=1000

# Optional: public JSON-RPC service, NOT the Core administrative RPC.
rpc_host=connectcoin4.com
rpc_port=48190
lookback_blocks=600
# Atomic connects per virtual byte (1 CONN = 10000000000 connects).
fee_rate=1500
`;
const DEFAULTS = Object.freeze({ receiving_address: '', max_connections_per_second: '100', max_simultaneous_connections: '100',
  min_connects_per_connection_second: '1000', rpc_host: 'connectcoin4.com', rpc_port: '48190', lookback_blocks: '600', fee_rate: '1500' });
const number = (values, key, minimum, maximum) => {
  const text = values[key];
  const value = Number(text);
  if (!/^(0|[1-9][0-9]*)$/.test(text) || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${key} must be an integer between ${minimum} and ${maximum}.`);
  }
  return value;
};
export function parseConfig(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 16384 || text.includes('\0')) throw new Error('Invalid or oversized configuration.');
  const values = { ...DEFAULTS }, seen = new Set();
  for (const [index, raw] of text.replace(/^\uFEFF/, '').split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const match = /^([a-z_]+)\s*=\s*([^\r\n]*)$/.exec(line);
    if (!match || !Object.hasOwn(DEFAULTS, match[1])) throw new Error(`Unknown or invalid setting on line ${index + 1}.`);
    const [, key, value] = match;
    if (seen.has(key)) throw new Error(`Duplicate setting: ${key}.`);
    seen.add(key); values[key] = value.trim();
  }
  if (!values.receiving_address) throw new Error('Set receiving_address to your mainnet ConnectCoin address in claimer.conf.');
  decodeAddress(values.receiving_address, 'main');
  return Object.freeze({ receivingAddress: values.receiving_address, network: 'main',
    connectionsPerSecond: number(values, 'max_connections_per_second', 1, MAX_CONNECTION_LIMIT),
    concurrency: number(values, 'max_simultaneous_connections', 1, MAX_CONNECTION_LIMIT),
    minExpectedReturn: number(values, 'min_connects_per_connection_second', 0, Number.MAX_SAFE_INTEGER),
    rpc: Object.freeze(validateRpcEndpoint({ host: values.rpc_host, port: number(values, 'rpc_port', 1, 65535) })),
    lookbackBlocks: number(values, 'lookback_blocks', 1, 600), feeRate: number(values, 'fee_rate', 1201, 100000),
  });
}
export async function ensureConfig(path) {
  let file;
  try {
    file = await open(path, 'wx', 0o600);
    await file.writeFile(CONFIG_TEMPLATE); await file.sync(); return true;
  } catch (error) { if (error.code === 'EEXIST') return false; throw error; }
  finally { await file?.close(); }
}
export async function readConfig(path) {
  const file = await open(path, 'r');
  try {
    if (!(await file.stat()).isFile()) throw new Error('Configuration must be a regular file.');
    const buffer = Buffer.alloc(16385);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    if (bytesRead > 16384) throw new Error('Configuration is too large.');
    return parseConfig(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytesRead)));
  } finally { await file.close(); }
}
