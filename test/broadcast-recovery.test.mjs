import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BroadcastJournal, MAX_REPLAY_HEX, transactionDigest } from '../src/broadcast-journal.mjs';
import { validateSavedClaim, validateObservedClaim, deferredBroadcast } from '../src/broadcast-recovery.mjs';
import { prepareClaim, attachClaimProof, parseTransaction, serializeTransaction, transactionIdFromRaw } from '../src/core/transaction.mjs';
import { encodeAddress } from '../src/core/crypto.mjs';

// Public fixtures only. Framing is deliberately synthetic: these tests exercise
// durable replay integrity, not the helper's certificate/CertificateVerify checks.
const publicKey = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const receivingAddress = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
const config = { network: 'main', receivingAddress };
const fundingHex = '02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff0100e40b5402000000020b6578616d706c652e636f6dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000700000000';
const bounty = { txid: 'b34ed54b791ccc26f559081380d0b8590335d1617930810ec72b3c5ac19f8c54', vout: 0,
  amount: '10000000000', domain: 'example.com', connection_work_target: 'ff'.repeat(32),
  root_certificates_version: 1, signature_algorithms_mask: 7 };
function proofFor(prepared, extra = Buffer.alloc(0)) {
  const message = (type, body) => {
    const header = Buffer.alloc(4); header[0] = type; header.writeUIntBE(body.length, 1, 3);
    return Buffer.concat([header, body]);
  };
  return Buffer.concat([Buffer.from([2]), message(1, Buffer.concat([Buffer.from([3, 3]), Buffer.from(prepared.challenge, 'hex')])),
    ...[2, 8, 11].map(type => message(type, Buffer.alloc(0))), message(15, extra)]).toString('hex');
}
function fixture(extra) {
  const prepared = prepareClaim({ bounty, rawTransaction: fundingHex, rewardAddress: receivingAddress });
  const signed = attachClaimProof(prepared, proofFor(prepared, extra));
  const record = { outpoint: `${bounty.txid}:0`, txid: signed.txid, receivingAddress, status: 'pending',
    transactionHex: signed.hex, transactionHash: transactionDigest(signed.hex), updatedAt: 1 };
  return { prepared, signed, record };
}
async function journalFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-recovery-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'state.json'), journal = new BroadcastJournal(path);
  await journal.load();
  return { path, journal };
}

test('saved replay validates actual transaction identity, receiving address, network and challenge', () => {
  const { signed, record } = fixture();
  assert.equal(validateSavedClaim(record, config), signed.hex);
  assert.equal(validateObservedClaim(record, signed.hex, config), signed.hex);
  assert.throws(() => validateSavedClaim({ ...record, txid: '00'.repeat(32) }, config), /identity/);
  assert.throws(() => validateSavedClaim({ ...record, transactionHash: '00'.repeat(32) }, config), /identity/);
  assert.throws(() => validateSavedClaim({ ...record, outpoint: `${bounty.txid}:1` }, config), /input or receiving/);
  assert.throws(() => validateSavedClaim(record, { ...config, receivingAddress: encodeAddress(publicKey, 'testnet4') }), /another configured/);
  assert.throws(() => validateSavedClaim(record, { ...config, network: 'testnet4' }), /network/);
  for (const raw of ['', signed.hex.toUpperCase(), signed.hex + '0', signed.hex + '00', signed.hex.slice(0, -2), 'ab'.repeat(MAX_REPLAY_HEX / 2 + 1)]) {
    assert.throws(() => validateSavedClaim({ ...record, transactionHex: raw, transactionHash: transactionDigest(raw) }, config));
  }
});

test('digest binds the exact witness independently of txid; observed acceptance may have another bound witness', () => {
  const first = fixture(), second = fixture(Buffer.from([1]));
  assert.equal(first.signed.txid, second.signed.txid, 'transaction IDs exclude the witness');
  assert.notEqual(first.record.transactionHash, second.record.transactionHash);
  assert.throws(() => validateSavedClaim({ ...first.record, transactionHex: second.signed.hex }, config), /durable identity/);
  assert.equal(validateObservedClaim(first.record, second.signed.hex, config), second.signed.hex,
    'a node-observed transaction with the same input/payout identity proves acceptance without replacing our durable bytes');
});

test('saved and observed validators reject malformed witness framing and wrong challenge even when digest and txid match', () => {
  const { signed, record } = fixture(), original = parseTransaction(signed.hex);
  const proof = Buffer.from(original.inputs[0].witness[0], 'hex');
  const wrongChallenge = Buffer.from(proof); wrongChallenge[7] ^= 1;
  const wrongType = Buffer.from(proof); wrongType[39] = 3;
  const wrongLength = Buffer.from(proof); wrongLength.writeUIntBE(4096, 2, 3);
  for (const changed of [Buffer.alloc(0), Buffer.from([1]), proof.subarray(0, -1), Buffer.concat([proof, Buffer.from([0])]), wrongChallenge, wrongType, wrongLength]) {
    const tx = structuredClone(original); tx.inputs[0].witness = [changed.toString('hex')];
    const raw = serializeTransaction(tx).toString('hex');
    assert.equal(transactionIdFromRaw(raw), record.txid);
    const modified = { ...record, transactionHex: raw, transactionHash: transactionDigest(raw) };
    assert.throws(() => validateSavedClaim(modified, config));
    assert.throws(() => validateObservedClaim(record, raw, config));
  }
});

test('replay enforces the one-input one-payout claim shape even with a recomputed identity', () => {
  const { signed, record } = fixture(), original = parseTransaction(signed.hex);
  const variants = [tx => { tx.version = 3; }, tx => { tx.locktime = 1; }, tx => { tx.inputs[0].sequence--; },
    tx => { tx.inputs[0].scriptSig = '00'; }, tx => { tx.inputs[0].witness = []; },
    tx => { tx.inputs[0].witness.push('00'); }, tx => { tx.outputs.push(structuredClone(tx.outputs[0])); },
    tx => { tx.inputs.push({ ...structuredClone(tx.inputs[0]), vout: 1 }); },
    tx => { tx.outputs[0].amount = '1'; }];
  for (const change of variants) {
    const tx = structuredClone(original); change(tx);
    const raw = serializeTransaction(tx).toString('hex');
    const modified = { ...record, txid: transactionIdFromRaw(raw), transactionHex: raw, transactionHash: transactionDigest(raw) };
    assert.throws(() => validateSavedClaim(modified, config));
    assert.throws(() => validateObservedClaim(modified, raw, config));
  }
});

test('journal v2 round-trips immutable replay bytes and compacts only an accepted receipt', async t => {
  const { path, journal } = await journalFixture(t), { record } = fixture();
  await journal.update(record.outpoint, record);
  const disk = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(disk.version, 2); assert.equal(disk.records[0].transactionHex, record.transactionHex);
  const loaded = new BroadcastJournal(path); await loaded.load();
  assert.equal(validateSavedClaim(loaded.unresolved()[0], config), record.transactionHex);
  await loaded.update(record.outpoint, { txid: record.txid, receivingAddress, status: 'unknown' });
  assert.equal(loaded.unresolved()[0].transactionHex, record.transactionHex);
  const other = fixture(Buffer.from([1])).record;
  await assert.rejects(loaded.update(record.outpoint, other), /witness cannot be replaced/);
  await assert.rejects(loaded.update(record.outpoint, { ...record, txid: '11'.repeat(32) }), /cannot be replaced/);
  await assert.rejects(loaded.update(record.outpoint, { ...record, receivingAddress: encodeAddress(publicKey, 'testnet4') }), /cannot be replaced/);
  await loaded.update(record.outpoint, { txid: record.txid, receivingAddress, status: 'accepted' });
  assert.equal(loaded.unresolved().length, 0);
  assert.equal(loaded.entries()[0].transactionHex, undefined); assert.equal(loaded.entries()[0].transactionHash, undefined);
  await assert.rejects(loaded.update(record.outpoint, record), /cannot become pending/);
  const accepted = new BroadcastJournal(path); await accepted.load();
  assert.equal(accepted.entries()[0].status, 'accepted'); assert.equal(accepted.unresolved().length, 0);
});

test('legacy journal records load without fabricated replay bytes and migrate without losing reservations', async t => {
  const { path } = await journalFixture(t), { record } = fixture();
  const { transactionHex, transactionHash, ...legacy } = record;
  await writeFile(path, JSON.stringify({ version: 1, records: [legacy] }));
  const journal = new BroadcastJournal(path); await journal.load();
  assert.equal(journal.unresolved()[0].transactionHex, undefined);
  await journal.update(record.outpoint, { txid: record.txid, receivingAddress, status: 'unknown' });
  const disk = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(disk.version, 2); assert.equal(disk.records[0].outpoint, record.outpoint);
  assert.equal(disk.records[0].transactionHex, undefined);
  assert.throws(() => validateSavedClaim(journal.unresolved()[0], config));
  assert.equal(validateObservedClaim(legacy, transactionHex, config), transactionHex);
});

test('journal fails closed on damaged replay pairs, accepted raw data and duplicate outpoints', async t => {
  const { path, journal } = await journalFixture(t), { record } = fixture();
  for (const change of [
    { transactionHash: undefined }, { transactionHex: undefined }, { transactionHash: '00'.repeat(32) },
    { transactionHex: 'ab'.repeat(MAX_REPLAY_HEX / 2 + 1) }, { transactionHex: record.transactionHex.toUpperCase() },
    { status: 'accepted' }, { txid: 'bad' }, { outpoint: `${bounty.txid}:4294967296` }, { unrecognized: true },
  ]) {
    await writeFile(path, JSON.stringify({ version: 2, records: [{ ...record, ...change }] }));
    await assert.rejects(new BroadcastJournal(path).load());
  }
  await writeFile(path, JSON.stringify({ version: 2, records: [record, record] }));
  await assert.rejects(new BroadcastJournal(path).load(), /Invalid claim broadcast record/);
  await writeFile(path, JSON.stringify({ version: 1, records: [record] }));
  await assert.rejects(new BroadcastJournal(path).load(), /Invalid claim broadcast record/);
  await assert.rejects(journal.update(record.outpoint, { ...record, transactionHash: '00'.repeat(32) }), /Invalid saved/);
  assert.equal(journal.entries().length, 0);
});

test('deferred ownership marker retains the exact transaction identity and original cause', () => {
  const cause = Object.assign(new Error('Reply lost after submission.'), { unknownOutcome: true });
  const txid = fixture().record.txid, error = deferredBroadcast(txid, cause);
  assert.equal(error.broadcastDeferred, true); assert.equal(error.txid, txid); assert.strictEqual(error.cause, cause);
  assert.equal(error.helperFatal, undefined);
});
