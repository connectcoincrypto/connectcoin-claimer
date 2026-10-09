// Public ConnectCoin claim transactions: typed outputs and 10 decimal places.
// Adapted from ConnectWallet v1.1.5. Claims require a TLS proof, no signing key.
import { domainToASCII } from 'node:url';
import { decodeAddress, hash256, taggedHash, validatePublicKey } from './crypto.mjs';

export const COIN = 10_000_000_000n;
export const MAX_MONEY = 100_000_000n * COIN;
export const DEFAULT_FEE_RATE = 1500; // integer connects/vbyte, NOT CONN or sat/vbyte
export const MAX_PROOF_SIZE = 65536;
const MAX_TX_BYTES = 4_000_000;
const MAX_INPUTS = 10000;
const MAX_OUTPUTS = 10000;

export function amountInConnects(value) {
  if (typeof value !== 'bigint' && (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value))) throw new Error('Amounts must be exact integer strings in connects');
  const amount = BigInt(value);
  if (amount < 0n || amount > MAX_MONEY) throw new Error('Amount is outside the ConnectCoin money range');
  return amount;
}
export function parseCoinAmount(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,8})(\.[0-9]{1,10})?$/.test(value)) throw new Error('Enter a CONN amount with at most 10 decimal places');
  const [whole, decimal = ''] = value.split('.');
  return amountInConnects(BigInt(whole) * COIN + BigInt(decimal.padEnd(10, '0')));
}
export function formatCoinAmount(value) {
  const amount = amountInConnects(value);
  const decimal = (amount % COIN).toString().padStart(10, '0').replace(/0+$/, '');
  return `${amount / COIN}${decimal ? `.${decimal}` : ''}`;
}
function hexBytes(value, size, label = 'hexadecimal data') {
  if (typeof value !== 'string' || value.length % 2 || !/^[0-9a-f]*$/i.test(value) || (size !== undefined && value.length !== size * 2)) throw new Error(`Invalid ${label}`);
  return Buffer.from(value, 'hex');
}
function u32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('Invalid unsigned 32-bit integer');
  const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value); return bytes;
}
function i64(value) { const bytes = Buffer.alloc(8); bytes.writeBigInt64LE(amountInConnects(value)); return bytes; }
export function compactSize(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_TX_BYTES) throw new Error('CompactSize is outside local safety bounds');
  if (value < 253) return Buffer.from([value]);
  if (value <= 65535) { const bytes = Buffer.alloc(3); bytes[0] = 253; bytes.writeUInt16LE(value, 1); return bytes; }
  return Buffer.concat([Buffer.from([254]), u32(value)]);
}
function variable(bytes) { return Buffer.concat([compactSize(bytes.length), bytes]); }
export function normalizeDomain(value) {
  if (typeof value !== 'string' || value.length > 1024 || /[\s/:@?#\\]/.test(value)) throw new Error('Use a domain name, not a URL');
  const domain = domainToASCII(value.trim().toLowerCase());
  if (!isCanonicalDomain(domain)) throw new Error('Invalid domain name');
  return domain;
}
function isCanonicalDomain(domain) {
  return typeof domain === 'string' && domain.length >= 1 && domain.length <= 253 && /^[a-z0-9.-]+$/.test(domain) && domain.split('.').every(label => label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}
export function workTargetForExpectedConnections(expected) {
  if ((typeof expected !== 'string' || !/^[1-9][0-9]{0,76}$/.test(expected)) && typeof expected !== 'bigint') throw new Error('Expected connections must be a positive integer string');
  const count = BigInt(expected);
  if (count < 1n || count > (1n << 256n)) throw new Error('Expected connections is out of range');
  return (((1n << 256n) / count) - 1n).toString(16).padStart(64, '0');
}
function transactionPublicKey(value, publicKeys) {
  // A successful curve lift is immutable for these exact 32 bytes. Reuse it
  // only within this bounded transaction operation; malformed or changed keys
  // still pass through the complete validator before they can be cached.
  const key = typeof value === 'string' && value.length === 64 ? value.toLowerCase()
    : value instanceof Uint8Array && value.length === 32 ? Buffer.from(value).toString('hex') : null;
  if (key !== null && publicKeys?.has(key)) return publicKeys.get(key);
  const validated = validatePublicKey(value);
  if (publicKeys && publicKeys.size < MAX_OUTPUTS) publicKeys.set(validated.toString('hex'), validated);
  return validated;
}
function outputPayloadWithKeys(output, publicKeys) {
  if (output.type === 1) return Buffer.concat([Buffer.from([1]), transactionPublicKey(output.publicKey, publicKeys)]);
  if (output.type === 2) {
    if (!isCanonicalDomain(output.domain)) throw new Error('Noncanonical P2C domain');
    if (!Number.isInteger(output.rootVersion) || output.rootVersion < 1 || output.rootVersion > 0xffffffff) throw new Error('Invalid P2C root bundle version');
    if (!Number.isInteger(output.mask) || output.mask < 1 || output.mask > 7) throw new Error('Invalid P2C signature mask');
    return Buffer.concat([Buffer.from([2, output.domain.length]), Buffer.from(output.domain, 'ascii'), hexBytes(output.target, 32, 'P2C work target').reverse(), u32(output.rootVersion), Buffer.from([output.mask])]);
  }
  throw new Error('Unknown or invalid ConnectCoin output type');
}
export function outputPayload(output) { return outputPayloadWithKeys(output); }
function serializeOutputWithKeys(output, publicKeys) { return Buffer.concat([i64(output.amount), outputPayloadWithKeys(output, publicKeys)]); }
export function serializeOutput(output) { return serializeOutputWithKeys(output); }
function outpoint(input) { return Buffer.concat([hexBytes(input.txid, 32, 'transaction ID').reverse(), u32(input.vout)]); }
function validateShape(tx) {
  u32(tx.version); u32(tx.locktime);
  if (!Array.isArray(tx.inputs) || tx.inputs.length < 1 || tx.inputs.length > MAX_INPUTS || !Array.isArray(tx.outputs) || tx.outputs.length < 1 || tx.outputs.length > MAX_OUTPUTS) throw new Error('Invalid transaction input/output count');
  let total = 0n;
  for (const output of tx.outputs) { total += amountInConnects(output.amount); if (total > MAX_MONEY) throw new Error('Total transaction outputs exceed money range'); }
  const seen = new Set();
  for (const input of tx.inputs) {
    const key = outpoint(input).toString('hex');
    if (seen.has(key)) throw new Error('Duplicate transaction input');
    seen.add(key);
    if (hexBytes(input.scriptSig ?? '').length > 10000 || !Array.isArray(input.witness ?? []) || (input.witness ?? []).length > 100) throw new Error('Oversized input script or witness stack');
  }
}
function serializeTransactionWithKeys(tx, { witness = true } = {}, publicKeys) {
  validateShape(tx);
  const hasWitness = witness && tx.inputs.some(input => (input.witness ?? []).length > 0);
  const parts = [u32(tx.version), ...(hasWitness ? [Buffer.from([0, 1])] : []), compactSize(tx.inputs.length)];
  for (const input of tx.inputs) parts.push(outpoint(input), variable(hexBytes(input.scriptSig ?? '')), u32(input.sequence));
  parts.push(compactSize(tx.outputs.length), ...tx.outputs.map(output => serializeOutputWithKeys(output, publicKeys)));
  if (hasWitness) for (const input of tx.inputs) {
    parts.push(compactSize((input.witness ?? []).length));
    for (const item of input.witness ?? []) {
      const data = hexBytes(item);
      if (data.length > MAX_PROOF_SIZE) throw new Error('Oversized witness element');
      parts.push(variable(data));
    }
  }
  parts.push(u32(tx.locktime));
  const result = Buffer.concat(parts);
  if (result.length > MAX_TX_BYTES) throw new Error('Transaction exceeds local size limit');
  return result;
}
export function serializeTransaction(tx, options) { return serializeTransactionWithKeys(tx, options, new Map()); }
export function transactionId(tx) { return hash256(serializeTransaction(tx, { witness: false })).reverse().toString('hex'); }
export function transactionVsize(tx) {
  const base = serializeTransaction(tx, { witness: false }).length;
  return Math.ceil((base * 3 + serializeTransaction(tx).length) / 4);
}
class Reader {
  constructor(data) { this.data = data; this.offset = 0; }
  take(size) { if (!Number.isSafeInteger(size) || size < 0 || size > this.data.length - this.offset) throw new Error('Truncated transaction'); const result = this.data.subarray(this.offset, this.offset + size); this.offset += size; return result; }
  byte() { return this.take(1)[0]; }
  uint() { return this.take(4).readUInt32LE(); }
  count(max = MAX_TX_BYTES) {
    const marker = this.byte();
    const result = marker < 253 ? marker : marker === 253 ? this.take(2).readUInt16LE() : marker === 254 ? this.uint() : this.take(8).readBigUInt64LE();
    if ((marker === 253 && result < 253) || (marker === 254 && result <= 65535) || marker === 255 || result > max) throw new Error('Noncanonical or oversized CompactSize');
    return result;
  }
  blob(max) { return this.take(this.count(max)); }
}
/**
 * Check bounded, canonical wire framing and hash the witness-stripped bytes.
 * This is an identity check for cached funding, NOT a semantic/ownership check:
 * unlike parseTransaction(), it deliberately does not lift public keys onto the
 * curve. Claim preparation must still verifyFunding() on the full original bytes.
 */
export function transactionIdFromRaw(raw) {
  if (typeof raw !== 'string' || raw.length > MAX_TX_BYTES * 2) throw new Error('Transaction exceeds local size limit');
  const reader = new Reader(hexBytes(raw));
  const version = reader.take(4);
  let inputStart = reader.offset;
  let count = reader.count(MAX_INPUTS), witnessed = false;
  if (count === 0) {
    if (reader.byte() !== 1) throw new Error('Unknown transaction witness flag');
    witnessed = true; inputStart = reader.offset; count = reader.count(MAX_INPUTS);
  }
  if (count < 1 || count > (reader.data.length - reader.offset) / 41) throw new Error('Invalid transaction input count');
  const seen = new Set();
  for (let index = 0; index < count; index++) {
    const outpoint = reader.take(36).toString('hex');
    if (seen.has(outpoint)) throw new Error('Duplicate transaction input');
    seen.add(outpoint);
    reader.blob(10000); reader.take(4);
  }
  const outputCount = reader.count(MAX_OUTPUTS);
  if (outputCount < 1 || outputCount > (reader.data.length - reader.offset) / 9) throw new Error('Invalid transaction output count');
  let total = 0n;
  for (let index = 0; index < outputCount; index++) {
    total += amountInConnects(reader.take(8).readBigInt64LE());
    if (total > MAX_MONEY) throw new Error('Total transaction outputs exceed money range');
    const type = reader.byte();
    if (type === 1) reader.take(32);
    else if (type === 2) {
      const domain = reader.take(reader.byte());
      if (domain.some(byte => byte > 127)) throw new Error('Non-ASCII P2C domain');
      if (!isCanonicalDomain(domain.toString('ascii'))) throw new Error('Noncanonical P2C domain');
      reader.take(32);
      if (reader.uint() < 1) throw new Error('Invalid P2C root bundle version');
      const mask = reader.byte();
      if (mask < 1 || mask > 7) throw new Error('Invalid P2C signature mask');
    } else throw new Error('Unknown or invalid ConnectCoin output type');
  }
  const outputsEnd = reader.offset;
  let hasWitness = false;
  if (witnessed) for (let index = 0; index < count; index++) {
    const items = reader.count(100);
    hasWitness ||= items > 0;
    for (let item = 0; item < items; item++) reader.blob(MAX_PROOF_SIZE);
  }
  if (witnessed && !hasWitness) throw new Error('Superfluous witness record');
  const locktime = reader.take(4);
  if (reader.offset !== reader.data.length) throw new Error('Trailing transaction data');
  const stripped = witnessed ? Buffer.concat([version, reader.data.subarray(inputStart, outputsEnd), locktime]) : reader.data;
  return hash256(stripped).reverse().toString('hex');
}
function parseTransactionWithKeys(raw, publicKeys) {
  if (typeof raw !== 'string' || raw.length > MAX_TX_BYTES * 2) throw new Error('Transaction exceeds local size limit');
  const reader = new Reader(hexBytes(raw));
  const version = reader.uint();
  let count = reader.count(MAX_INPUTS);
  let witnessed = false;
  if (count === 0) { if (reader.byte() !== 1) throw new Error('Unknown transaction witness flag'); witnessed = true; count = reader.count(MAX_INPUTS); }
  if (count < 1 || count > (reader.data.length - reader.offset) / 41) throw new Error('Invalid transaction input count');
  const inputs = [];
  for (let index = 0; index < count; index++) inputs.push({ txid: Buffer.from(reader.take(32)).reverse().toString('hex'), vout: reader.uint(), scriptSig: reader.blob(10000).toString('hex'), sequence: reader.uint(), witness: [] });
  const outputCount = reader.count(MAX_OUTPUTS);
  if (outputCount < 1 || outputCount > (reader.data.length - reader.offset) / 9) throw new Error('Invalid transaction output count');
  const outputs = [];
  for (let index = 0; index < outputCount; index++) {
    const amount = amountInConnects(reader.take(8).readBigInt64LE()).toString();
    const type = reader.byte();
    if (type === 1) outputs.push({ type, amount, publicKey: transactionPublicKey(reader.take(32), publicKeys).toString('hex') });
    else if (type === 2) {
      const domainBytes = reader.take(reader.byte());
      if (domainBytes.some(byte => byte > 127)) throw new Error('Non-ASCII P2C domain');
      const domain = domainBytes.toString('ascii');
      const target = Buffer.from(reader.take(32)).reverse().toString('hex');
      const output = { type, amount, domain, target, rootVersion: reader.uint(), mask: reader.byte() };
      outputPayload(output); outputs.push(output);
    } else throw new Error('Unknown or invalid ConnectCoin output type');
  }
  if (witnessed) for (const input of inputs) {
    const items = reader.count(100);
    for (let index = 0; index < items; index++) input.witness.push(reader.blob(MAX_PROOF_SIZE).toString('hex'));
  }
  if (witnessed && !inputs.some(input => input.witness.length)) throw new Error('Superfluous witness record');
  const tx = { version, inputs, outputs, locktime: reader.uint() };
  if (reader.offset !== reader.data.length) throw new Error('Trailing transaction data');
  if (!serializeTransactionWithKeys(tx, undefined, publicKeys).equals(reader.data)) throw new Error('Noncanonical transaction encoding');
  return tx;
}
export function parseTransaction(raw) { return parseTransactionWithKeys(raw, new Map()); }
function checkFundingOutput(utxo, expectedPublicKey, funding, fundingId) {
  if (!utxo || typeof utxo !== 'object') throw new Error('Missing funding output');
  hexBytes(utxo.txid, 32, 'funding transaction ID');
  if (fundingId !== utxo.txid.toLowerCase()) throw new Error('Funding transaction ID does not match its bytes');
  if (!Number.isInteger(utxo.vout) || utxo.vout < 0 || utxo.vout >= funding.outputs.length) throw new Error('Funding output does not exist');
  const output = funding.outputs[utxo.vout];
  if (amountInConnects(output.amount) !== amountInConnects(utxo.amount)) throw new Error('RPC funding amount does not match the original transaction');
  if (expectedPublicKey !== undefined && (output.type !== 1 || output.publicKey !== validatePublicKey(expectedPublicKey).toString('hex'))) throw new Error('Funding output is not owned by this expected public key');
  return output;
}
export function verifyFunding(utxo, expectedPublicKey) {
  if (!utxo || typeof utxo !== 'object') throw new Error('Missing funding output');
  hexBytes(utxo.txid, 32, 'funding transaction ID');
  const funding = parseTransaction(utxo.rawTransaction);
  return checkFundingOutput(utxo, expectedPublicKey, funding, transactionId(funding));
}

export function dustThreshold(output) {
  const spend = output.type === 2 ? 41 + Math.ceil((1 + 5 + MAX_PROOF_SIZE) / 4) : 58;
  return BigInt((serializeOutput(output).length + spend) * 3);
}

function checkedFeeRate(value) {
  if (!Number.isSafeInteger(value) || value < 1201 || value > 1_000_000) throw new Error('Fee rate must be 1,201–1,000,000 connects per vbyte');
  return BigInt(value);
}

export function claimChallenge(tx, index = 0) {
  if (!Number.isInteger(index) || index < 0 || index >= tx.inputs.length) throw new Error('Claim input index is out of range');
  return taggedHash('ConnectCoin/P2C/claim/v1', Buffer.concat([hexBytes(transactionId(tx), 32).reverse(), u32(index)])).toString('hex');
}
export function estimateClaimFee(feeRate = DEFAULT_FEE_RATE, proofSize = MAX_PROOF_SIZE) {
  checkedFeeRate(feeRate);
  if (!Number.isInteger(proofSize) || proofSize < 1 || proofSize > MAX_PROOF_SIZE) throw new Error('Invalid claim proof size');
  // Fixed one-input/one-output P2PK claim: 92 stripped bytes.
  return (BigInt(Math.ceil((92 * 4 + 2 + 1 + compactSize(proofSize).length + proofSize) / 4)) * BigInt(feeRate)).toString();
}
export function prepareClaim({ bounty, rawTransaction, rewardAddress, fee = estimateClaimFee(), network = 'main', maxFee = COIN.toString() }) {
  const output = verifyFunding({ ...bounty, rawTransaction });
  if (output.type !== 2 || output.rootVersion !== 1) throw new Error('Not a supported P2C bounty');
  for (const [remote, local] of [['domain', 'domain'], ['connection_work_target', 'target'], ['root_certificates_version', 'rootVersion'], ['signature_algorithms_mask', 'mask']]) {
    if (bounty[remote] !== undefined && bounty[remote] !== output[local]) throw new Error(`Bounty ${remote} differs from the funding transaction`);
  }
  const feeAmount = amountInConnects(fee);
  if (feeAmount > amountInConnects(maxFee) || feeAmount >= BigInt(output.amount)) throw new Error('Claim fee exceeds the claim limit or bounty value');
  const reward = { type: 1, amount: (BigInt(output.amount) - feeAmount).toString(), publicKey: decodeAddress(rewardAddress, network).toString('hex') };
  if (BigInt(reward.amount) < dustThreshold(reward)) throw new Error('Claim reward is below the dust threshold');
  const transaction = { version: 2, inputs: [{ txid: bounty.txid, vout: bounty.vout, scriptSig: '', sequence: 0xffffffff, witness: [] }], outputs: [reward], locktime: 0 };
  const challenge = claimChallenge(transaction);
  return { transaction, hex: serializeTransaction(transaction).toString('hex'), txid: transactionId(transaction), challenge, clienthello_random: challenge, bounty: { ...bounty, ...output }, fee: feeAmount.toString(), payout: reward.amount };
}
export function attachClaimProof(prepared, proofHex) {
  const proof = hexBytes(proofHex);
  if (proof.length < 1 || proof.length > MAX_PROOF_SIZE || proof[0] !== 2) throw new Error('Invalid P2C version-2 proof');
  // Framing and work checks are defense-in-depth, NOT certificate validation.
  // The local TLS helper verifies the chain, signature, domain and profile;
  // consensus validation is still performed by ConnectCoin nodes.
  let offset = 1;
  const messages = [];
  for (const [type, maximum] of [[1, 4096], [2, 2048], [8, 4096], [11, 49152], [15, 8192]]) {
    if (offset + 4 > proof.length || proof[offset] !== type) throw new Error('Invalid P2C handshake sequence');
    const size = proof.readUIntBE(offset + 1, 3) + 4;
    if (size > maximum || offset + size > proof.length) throw new Error('Invalid P2C handshake length');
    messages.push(proof.subarray(offset, offset + size)); offset += size;
  }
  if (offset !== proof.length || messages[0].length < 38 || messages[0].subarray(6, 38).toString('hex') !== prepared.challenge) throw new Error('Proof is not bound to this claim');
  const tx = parseTransaction(prepared.hex);
  if (transactionId(tx) !== prepared.txid || claimChallenge(tx) !== prepared.challenge || tx.inputs.length !== 1 || tx.outputs.length !== 1 || tx.inputs[0].witness.length) throw new Error('Claim proposal was changed after preparing its challenge');
  const work = taggedHash('ConnectCoin/P2C/work/v2', Buffer.concat(messages.slice(0, 4)));
  if (BigInt(`0x${Buffer.from(work).reverse().toString('hex')}`) > BigInt(`0x${prepared.bounty.target}`)) throw new Error('P2C proof does not meet the bounty work target');
  tx.inputs[0].witness = [proofHex];
  return { hex: serializeTransaction(tx).toString('hex'), txid: transactionId(tx), fee: prepared.fee, payout: prepared.payout, transaction: tx };
}
