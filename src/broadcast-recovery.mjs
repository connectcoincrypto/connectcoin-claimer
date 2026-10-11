import { decodeAddress } from './core/crypto.mjs';
import { parseTransaction, transactionIdFromRaw, claimChallenge, MAX_PROOF_SIZE } from './core/transaction.mjs';
import { MAX_REPLAY_HEX, transactionDigest } from './broadcast-journal.mjs';

/** Integrity/binding of bytes ALREADY verified before the original durable write.
 * This is retransmission, never proof generation or a replacement transaction.
 * The receiving node still applies its full current validation and fee policy.
 */
export function validateSavedClaim(record, { network, receivingAddress }) {
  if (record.receivingAddress !== receivingAddress) throw new Error('Saved claim belongs to another configured receiving address.');
  const raw = record.transactionHex;
  if (typeof raw !== 'string' || raw.length > MAX_REPLAY_HEX || !/^(?:[0-9a-f]{2})+$/.test(raw) ||
      transactionDigest(raw) !== record.transactionHash || transactionIdFromRaw(raw) !== record.txid) {
    throw new Error('Saved claim bytes do not match their durable identity.');
  }
  validateObservedClaim(record, raw, { network, receivingAddress });
  return raw;
}

export function validateObservedClaim(record, raw, { network, receivingAddress }) {
  if (record.receivingAddress !== receivingAddress || typeof raw !== 'string' || raw.length > MAX_REPLAY_HEX ||
      transactionIdFromRaw(raw) !== record.txid) throw new Error('Observed claim does not match its saved transaction identity.');
  const tx = parseTransaction(raw), input = tx.inputs[0], output = tx.outputs[0];
  if (tx.version !== 2 || tx.locktime !== 0 || tx.inputs.length !== 1 || tx.outputs.length !== 1 ||
      `${input.txid}:${input.vout}` !== record.outpoint || input.scriptSig !== '' || input.sequence !== 0xffffffff ||
      input.witness.length !== 1 || output.type !== 1 ||
      output.publicKey !== decodeAddress(record.receivingAddress, network).toString('hex')) {
    throw new Error('Saved claim input or receiving output was changed.');
  }
  const proof = Buffer.from(input.witness[0], 'hex');
  if (proof.length > MAX_PROOF_SIZE || proof[0] !== 2) throw new Error('Invalid saved claim proof.');
  let offset = 1;
  for (const [index, [type, maximum]] of [[1,4096], [2,2048], [8,4096], [11,49152], [15,8192]].entries()) {
    if (offset + 4 > proof.length || proof[offset] !== type) throw new Error('Invalid saved claim handshake sequence.');
    const size = proof.readUIntBE(offset + 1, 3) + 4;
    if (size > maximum || offset + size > proof.length) throw new Error('Invalid saved claim handshake length.');
    if (index === 0 && (size < 38 || proof.subarray(offset + 6, offset + 38).toString('hex') !== claimChallenge(tx))) {
      throw new Error('Saved proof is not bound to the claim transaction.');
    }
    offset += size;
  }
  if (offset !== proof.length) throw new Error('Trailing saved claim proof bytes.');
  return raw;
}

export function deferredBroadcast(txid, cause) {
  return Object.assign(new Error('Claim saved for reconciliation; only its outpoint is reserved.', { cause }),
    { broadcastDeferred: true, txid });
}
