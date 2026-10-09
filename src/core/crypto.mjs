// Public address decoding and hashes only. No wallet, key generation or signing.
// Adapted from ConnectWallet v1.1.5; see PROVENANCE.md.
import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bech32m } from '@scure/base';

export const NETWORKS = Object.freeze({ main: Object.freeze({ hrp: 'cc' }), testnet4: Object.freeze({ hrp: 'tcc' }), regtest: Object.freeze({ hrp: 'ccrt' }) });
export function networkParameters(network = 'main') {
  const parameters = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : undefined;
  if (!parameters) throw new Error('Unsupported ConnectCoin network');
  return parameters;
}

export function sha256(value) { return createHash('sha256').update(value).digest(); }
export function hash256(value) { return sha256(sha256(value)); }
export function taggedHash(tag, value) {
  const prefix = sha256(Buffer.from(tag, 'utf8'));
  return sha256(Buffer.concat([prefix, prefix, Buffer.from(value)]));
}

export function validatePublicKey(publicKey) {
  const key = typeof publicKey === 'string' && /^[a-fA-F0-9]{64}$/.test(publicKey) ? Buffer.from(publicKey, 'hex') : publicKey;
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('Expected a 32-byte x-only public key');
  // An x coordinate must actually lift to a secp256k1 curve point.
  secp256k1.Point.fromBytes(Buffer.concat([Buffer.from([2]), key]));
  return Buffer.from(key);
}
export function encodeAddress(publicKey, network = 'main') {
  const key = validatePublicKey(publicKey);
  return bech32m.encode(networkParameters(network).hrp, [1, ...bech32m.toWords(key)]);
}
export function decodeAddress(address, network = 'main') {
  if (typeof address !== 'string' || address.length > 90) throw new Error('Invalid ConnectCoin address');
  const decoded = bech32m.decode(address, 90);
  if (decoded.prefix !== networkParameters(network).hrp || decoded.words[0] !== 1) throw new Error('Address belongs to a different network or is not native P2PK');
  return validatePublicKey(bech32m.fromWords(decoded.words.slice(1)));
}
