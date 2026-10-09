import { isIP } from 'node:net';

export const GENESIS = Object.freeze({
  main: '30a3a7543f593b6343873a16aeb61005dce0fe3f4169ab34039316b2a9bb373e',
});
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export function validateRpcEndpoint(input) {
  if (!plain(input)) throw new Error('Invalid RPC endpoint.');
  const { host, port } = input;
  if (typeof host !== 'string' || !host.length || host.length > 253 || host.includes('%') ||
      (!isIP(host) && (/^(?:[0-9]+\.){3}[0-9]+$/.test(host) || !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(host)))) {
    throw new Error('RPC host must be a hostname or IP address without a URL, path or credentials.');
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('RPC port must be between 1 and 65535.');
  return { host: host.toLowerCase(), port };
}
export function validateTip(tip, network = 'main') {
  if (!Object.hasOwn(GENESIS, network) || !plain(tip) || tip.chain !== network || tip.genesis_hash !== GENESIS[network] ||
      !Number.isSafeInteger(tip.height) || tip.height < 0 || !/^[0-9a-f]{64}$/.test(tip.hash) ||
      !Number.isSafeInteger(tip.mediantime) || tip.mediantime < 0 || (tip.height === 0 && tip.hash !== GENESIS[network])) {
    throw new Error('The RPC server returned an unexpected network or invalid chain tip.');
  }
  return tip;
}
