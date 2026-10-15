import { decodeAddress, taggedHash } from './core/crypto.mjs';
import { parseTransaction, transactionIdFromRaw, claimChallenge, MAX_PROOF_SIZE } from './core/transaction.mjs';
import { MAX_REPLAY_HEX, transactionDigest } from './broadcast-journal.mjs';
import { validateTip } from './core/config.mjs';

/** Missing metadata never means confirmed. A plain sendrawtransaction ACK is
 * deliberately insufficient for dropping the only saved witness. */
export function validateConfirmation(result, { network }, window) {
  const tip = validateTip(result?.tip, network);
  const confirmations = result.transaction?.confirmations, transactionBlock = result.transaction?.blockhash;
  if ((confirmations !== undefined && (!Number.isSafeInteger(confirmations) || confirmations < 0)) ||
      (transactionBlock !== undefined && (typeof transactionBlock !== 'string' || !/^[0-9a-f]{64}$/.test(transactionBlock)))) {
    throw new Error('Invalid claim transaction location.');
  }
  if (result.status === undefined || result.status === 'pending') {
    if (result.block_hash !== undefined || result.block_height !== undefined) throw new Error('Unconfirmed claim has block metadata.');
    // The backend may have mined the transaction before the index advances.
    // Do not acknowledge the inconsistent receipt, but do not stop other work:
    // the unchanged owner is retried through the bounded reconciliation lane.
    if (transactionBlock !== undefined || confirmations > 0) {
      throw Object.assign(new Error('Claim receipt index and backend location disagree.'), { code: -32011 });
    }
    return null;
  }
  if (result.status !== 'confirmed' || !Number.isSafeInteger(result.block_height) || result.block_height < 0 ||
      result.block_height > tip.height || typeof result.block_hash !== 'string' || !/^[0-9a-f]{64}$/.test(result.block_hash)) {
    throw new Error('Invalid claim confirmation metadata.');
  }
  const known = window?.blocks?.find(block => block.height === result.block_height);
  if ((result.block_height === 0 && result.block_hash !== tip.genesis_hash) ||
      (result.block_height === tip.height && result.block_hash !== tip.hash)) {
    throw new Error('Claim confirmation conflicts with the validated chain.');
  }
  if (confirmations === 0 || (transactionBlock !== undefined && transactionBlock !== result.block_hash)) {
    throw Object.assign(new Error('Claim receipt index and backend location disagree.'), { code: -32011 });
  }
  // Discovery and this read can straddle a reorganization. A different local
  // canonical block is a reason to resynchronize, not to discard the witness
  // or permanently stop an otherwise healthy claimer.
  if (known && known.hash !== result.block_hash) {
    throw Object.assign(new Error('Claim confirmation needs a fresh chain snapshot.'), { code: -32011 });
  }
  return { blockHash: result.block_hash, blockHeight: result.block_height };
}

/** An indexed receipt contains no witness. Its identity must bind to the saved
 * transaction, whose bytes are independently checked before this read. */
export function validateClaimStatus(result, record, config, window) {
  const tip = validateTip(result?.tip, config.network);
  if (typeof result?.txid !== 'string' || !/^[0-9a-f]{64}$/.test(result.txid) || result.txid !== record.txid) {
    throw new Error('Claim receipt reports a conflicting transaction identity.');
  }
  if (!['pending', 'confirmed'].includes(result.status) || !Number.isSafeInteger(result.confirmations) || result.confirmations < 0) {
    throw new Error('Invalid claim confirmation metadata.');
  }
  const confirmation = validateConfirmation({ ...result, transaction: {
    confirmations: result.confirmations, ...(result.status === 'confirmed' ? { blockhash: result.block_hash } : {}),
  } }, config, window);
  if (confirmation && result.confirmations !== tip.height - confirmation.blockHeight + 1) {
    throw Object.assign(new Error('Claim confirmation count disagrees with its indexed tip.'), { code: -32011 });
  }
  return confirmation;
}

/** Integrity/binding of bytes ALREADY verified before the original durable write.
 * This is retransmission, never proof generation or a replacement transaction.
 * The receiving node still applies its full current validation and fee policy.
 */
export function validateSavedClaim(record, { network, receivingAddress }, { target } = {}) {
  if (record.receivingAddress !== receivingAddress) throw new Error('Saved claim belongs to another configured receiving address.');
  const raw = record.transactionHex;
  if (typeof raw !== 'string' || raw.length > MAX_REPLAY_HEX || !/^(?:[0-9a-f]{2})+$/.test(raw) ||
      transactionDigest(raw) !== record.transactionHash || transactionIdFromRaw(raw) !== record.txid) {
    throw new Error('Saved claim bytes do not match their durable identity.');
  }
  validateObservedClaim(record, raw, { network, receivingAddress }, { target });
  return raw;
}

export function validateObservedClaim(record, raw, { network, receivingAddress }, { target } = {}) {
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
  const messages = [];
  for (const [index, [type, maximum]] of [[1,4096], [2,2048], [8,4096], [11,49152], [15,8192]].entries()) {
    if (offset + 4 > proof.length || proof[offset] !== type) throw new Error('Invalid saved claim handshake sequence.');
    const size = proof.readUIntBE(offset + 1, 3) + 4;
    if (size > maximum || offset + size > proof.length) throw new Error('Invalid saved claim handshake length.');
    if (index === 0 && (size < 38 || proof.subarray(offset + 6, offset + 38).toString('hex') !== claimChallenge(tx))) {
      throw new Error('Saved proof is not bound to the claim transaction.');
    }
    messages.push(proof.subarray(offset, offset + size)); offset += size;
  }
  if (offset !== proof.length) throw new Error('Trailing saved claim proof bytes.');
  // The journal need not retain discovery metadata forever. When the bounty is
  // still known, also authenticate work against its current validated target.
  // For aged/legacy records, the full node remains the consensus verifier.
  if (target !== undefined) {
    if (typeof target !== 'string' || !/^[0-9a-f]{64}$/.test(target)) throw new Error('Invalid observed claim work target.');
    const work = taggedHash('ConnectCoin/P2C/work/v2', Buffer.concat(messages.slice(0, 4)));
    if (BigInt(`0x${Buffer.from(work).reverse().toString('hex')}`) > BigInt(`0x${target}`)) {
      throw new Error('Observed proof does not meet the bounty work target.');
    }
  }
  return raw;
}

export function deferredBroadcast(txid, cause) {
  return Object.assign(new Error('Claim saved for reconciliation; only its outpoint is reserved.', { cause }),
    { broadcastDeferred: true, txid });
}
