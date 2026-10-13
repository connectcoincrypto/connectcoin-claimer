import assert from 'node:assert/strict';
import test from 'node:test';
import { bech32m } from '@scure/base';
import * as publicCrypto from '../src/core/crypto.mjs';
import * as transactions from '../src/core/transaction.mjs';

const { decodeAddress, encodeAddress, validatePublicKey } = publicCrypto;
const { attachClaimProof, estimateClaimFee, parseTransaction, prepareClaim, serializeTransaction,
  transactionId, transactionIdFromRaw, verifyFunding, FundingTransactionCache } = transactions;
// Public secp256k1 generator point. No secret keys are used in these fixtures.
const publicKey = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const receivingAddress = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
// Golden public fixture generated independently by unchanged ConnectWallet v1.1.5.
const fundingHex = '02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020101ffffffff0100e40b5402000000020b6578616d706c652e636f6dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff010000000700000000';
const bounty = {
  txid: 'b34ed54b791ccc26f559081380d0b8590335d1617930810ec72b3c5ac19f8c54',
  vout: 0, amount: '10000000000', domain: 'example.com',
  connection_work_target: 'ff'.repeat(32), root_certificates_version: 1, signature_algorithms_mask: 7,
};
const expectedClaimHex = '0200000001548c9fc15a3c2bc70e81307961d1350359b8d080130859f526cc1c794bd54eb30000000000ffffffff0138bd9252020000000179be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000';
const proposal = overrides => prepareClaim({ bounty, rawTransaction: fundingHex, rewardAddress: receivingAddress, ...overrides });

test('public API exposes no account generation, seed derivation or payment signing', () => {
  for (const name of ['generateMnemonic', 'deriveAccount', 'createPublicAccountDeriver', 'publicKeyFromPrivate', 'signSchnorr']) {
    assert.equal(Object.hasOwn(publicCrypto, name), false);
  }
  assert.equal(Object.hasOwn(transactions, 'buildPayment'), false);
  assert.equal(Object.hasOwn(transactions, 'signatureHash'), false);
});

test('receiving address uses validated native P2PK bech32m and selected network', () => {
  assert.equal(encodeAddress(publicKey), receivingAddress);
  assert.equal(decodeAddress(receivingAddress).toString('hex'), publicKey);
  assert.equal(decodeAddress(receivingAddress.toUpperCase()).toString('hex'), publicKey);
  for (const network of ['main', 'testnet4', 'regtest']) {
    const address = encodeAddress(publicKey, network);
    assert.equal(decodeAddress(address, network).toString('hex'), publicKey);
  }
  assert.throws(() => decodeAddress(receivingAddress, 'testnet4'), /network/);
  assert.throws(() => decodeAddress(receivingAddress.slice(0, -1) + 'q'));
  assert.throws(() => decodeAddress('cc1p' + 'q'.repeat(100)));
  assert.throws(() => decodeAddress(bech32m.encode('cc', [0, ...bech32m.toWords(Buffer.from(publicKey, 'hex'))])), /P2PK/);
  assert.throws(() => decodeAddress(bech32m.encode('cc', [1, ...bech32m.toWords(Buffer.alloc(31))])), /32-byte/);
  assert.throws(() => validatePublicKey('ff'.repeat(32)));
});

test('claim construction matches desktop v1.1.5 bytes, identity, fee and challenge', () => {
  const claim = proposal();
  assert.equal(claim.hex, expectedClaimHex);
  assert.equal(claim.txid, '61e4fd7f266e840d74bdb2dd3862bace048ab7f03409f6282fb16d9c179a737c');
  assert.equal(claim.challenge, '15edfccc1c6e819c92dc4af7fe16ec2365df01e454da61452a6d9204acab1032');
  assert.equal(claim.clienthello_random, claim.challenge);
  assert.equal(claim.fee, '24717000');
  assert.equal(claim.fee, estimateClaimFee());
  assert.equal(claim.payout, '9975283000');
  assert.equal(claim.transaction.outputs[0].publicKey, publicKey);
  assert.deepEqual(claim.transaction.inputs[0].witness, []);
  assert.equal(BigInt(claim.fee) + BigInt(claim.payout), BigInt(bounty.amount));
});

test('raw funding parser authenticates amount, metadata and transaction identity', () => {
  const funding = parseTransaction(fundingHex);
  assert.equal(serializeTransaction(funding).toString('hex'), fundingHex);
  assert.equal(transactionId(funding), bounty.txid);
  assert.equal(transactionIdFromRaw(fundingHex), bounty.txid);
  assert.equal(verifyFunding({ ...bounty, rawTransaction: fundingHex }).type, 2);
  for (const override of [
    { txid: '11'.repeat(32) }, { vout: 1 }, { amount: '1' }, { domain: 'other.example' },
    { connection_work_target: '00'.repeat(32) }, { root_certificates_version: 2 }, { signature_algorithms_mask: 1 },
  ]) assert.throws(() => proposal({ bounty: { ...bounty, ...override } }));
  const unsupported = structuredClone(funding); unsupported.outputs[0].rootVersion = 2;
  const raw = serializeTransaction(unsupported).toString('hex');
  assert.throws(() => proposal({ rawTransaction: raw, bounty: { ...bounty, txid: transactionId(unsupported) } }), /supported P2C/);
});

test('malformed or noncanonical funding cannot be prepared', () => {
  for (const raw of [fundingHex + '00', fundingHex.slice(0, -2), '02000000fd0100' + fundingHex.slice(10), '020000000002' + fundingHex.slice(8)]) {
    assert.throws(() => parseTransaction(raw));
    assert.throws(() => transactionIdFromRaw(raw));
  }
  const duplicate = parseTransaction(fundingHex);
  duplicate.inputs.push(structuredClone(duplicate.inputs[0]));
  assert.throws(() => serializeTransaction(duplicate), /Duplicate/);
  const nonAscii = Buffer.from(fundingHex, 'hex'); nonAscii[nonAscii.indexOf(Buffer.from('example.com'))] |= 0x80;
  assert.throws(() => parseTransaction(nonAscii.toString('hex')), /Non-ASCII/);
});

test('claim fee and payout enforce exact amounts, bounds and minimum reward', () => {
  for (const fee of ['0.1', '01', '-1', 1500, '10000000000']) assert.throws(() => proposal({ fee }));
  assert.throws(() => proposal({ fee: '2', maxFee: '1' }), /limit/);
  assert.throws(() => proposal({ fee: '9999999999' }), /dust/);
  for (const rate of [1200, 1000001, 1.5, Infinity]) assert.throws(() => estimateClaimFee(rate), /Fee rate/);
  assert.throws(() => estimateClaimFee(1500, 65537), /proof size/);
  assert.throws(() => proposal({ rewardAddress: encodeAddress(publicKey, 'testnet4') }), /network/);
});

test('funding cache parses the exact parent once while repeating every claim-specific check', t => {
  const cache = new FundingTransactionCache();
  let parentDecodes = 0;
  const from = Buffer.from;
  t.mock.method(Buffer, 'from', function (value, ...args) {
    if (value === fundingHex && args[0] === 'hex') parentDecodes++;
    return from(value, ...args);
  });
  const prepare = overrides => cache.prepareClaim({ bounty, rawTransaction: fundingHex, rewardAddress: receivingAddress, ...overrides });
  assert.equal(cache.transactionId(fundingHex), bounty.txid);
  for (let index = 0; index < 20; index++) assert.equal(prepare().hex, expectedClaimHex);
  assert.equal(parentDecodes, 1, 'Canonical parsing, parent serialization and hashing are reused.');
  for (const override of [
    { txid: '11'.repeat(32) }, { vout: -1 }, { vout: 1 }, { vout: 0.5 }, { amount: '1' }, { domain: 'other.example' },
    { connection_work_target: '00'.repeat(32) }, { root_certificates_version: 2 }, { signature_algorithms_mask: 1 },
  ]) assert.throws(() => prepare({ bounty: { ...bounty, ...override } }));
  for (const fee of ['0.1', '01', '-1', 1500, '10000000000']) assert.throws(() => prepare({ fee }));
  assert.throws(() => prepare({ fee: '2', maxFee: '1' }), /limit/);
  assert.throws(() => prepare({ fee: '9999999999' }), /dust/);
  assert.throws(() => prepare({ network: 'testnet4' }), /network/);
  assert.throws(() => prepare({ rewardAddress: receivingAddress.slice(0, -1) + 'q' }));
  assert.throws(() => cache.verifyFunding({ ...bounty, rawTransaction: fundingHex }, publicKey), /owned/);
  assert.equal(parentDecodes, 1);

  const returned = cache.verifyFunding({ ...bounty, rawTransaction: fundingHex });
  returned.amount = '1'; returned.domain = 'forged.example';
  const prepared = prepare(); prepared.bounty.target = '00'.repeat(32);
  assert.equal(prepare().hex, expectedClaimHex);
  assert.equal(prepare().bounty.target, bounty.connection_work_target);
  assert.throws(() => prepare({ rawTransaction: '00', funding: { outputs: [returned] }, fundingId: bounty.txid }));
  cache.clear();
  assert.equal(cache.size, 0); assert.equal(cache.retainedBytes, 0);
  assert.equal(prepare().hex, expectedClaimHex);
  assert.equal(parentDecodes, 2, 'Epoch clearing requires full validation again.');
});

test('funding cache authenticates each selected output and rejects malformed siblings', () => {
  const cache = new FundingTransactionCache(), funding = parseTransaction(fundingHex);
  funding.outputs.push({ type: 1, amount: '100', publicKey }, { ...funding.outputs[0], amount: '20000000000', domain: 'other.example' });
  const raw = serializeTransaction(funding).toString('hex'), txid = transactionId(funding);
  const selected = { txid, vout: 2, amount: '20000000000', domain: 'other.example' };
  assert.equal(cache.prepareClaim({ bounty: selected, rawTransaction: raw, rewardAddress: receivingAddress }).bounty.domain, 'other.example');
  assert.throws(() => cache.prepareClaim({ bounty: { ...selected, vout: 0 }, rawTransaction: raw, rewardAddress: receivingAddress }), /amount/);
  assert.equal(cache.verifyFunding({ txid, vout: 1, amount: '100', rawTransaction: raw }, publicKey).publicKey, publicKey);
  assert.throws(() => cache.prepareClaim({ bounty: { txid, vout: 1, amount: '100' }, rawTransaction: raw, rewardAddress: receivingAddress }), /supported/);
  const malformed = raw.replace(publicKey, 'ff'.repeat(32));
  const malformedId = transactionIdFromRaw(malformed);
  assert.throws(() => cache.prepareClaim({ bounty: { ...selected, txid: malformedId }, rawTransaction: malformed, rewardAddress: receivingAddress }), /key|point|field/i);
  assert.equal(cache.size, 1, 'Rejected transactions never enter the trusted cache.');
});

test('funding validation cache keys exact witness bytes, not only the stripped txid', () => {
  const cache = new FundingTransactionCache(), funding = parseTransaction(fundingHex);
  funding.inputs[0].witness = ['02'];
  const first = serializeTransaction(funding).toString('hex');
  funding.inputs[0].witness = ['03'];
  const second = serializeTransaction(funding).toString('hex');
  assert.equal(cache.transactionId(first), bounty.txid);
  assert.equal(cache.transactionId(second), bounty.txid);
  assert.equal(cache.size, 2);
  const superfluousWitness = first.slice(0, -14) + '0000000000';
  assert.throws(() => cache.transactionId(superfluousWitness), /Superfluous/);
  for (const malformed of [first + '00', first.slice(0, -2), '02000000fd0100' + fundingHex.slice(10)]) assert.throws(() => cache.transactionId(malformed));
  assert.equal(cache.size, 2);
});

test('funding cache bounds entries and decoded bytes, evicts least recently used parents and declines oversized entries', t => {
  const funding = parseTransaction(fundingHex);
  const raws = [0, 1, 2].map(locktime => serializeTransaction({ ...funding, locktime }).toString('hex'));
  const decodes = new Map(), from = Buffer.from;
  t.mock.method(Buffer, 'from', function (value, ...args) {
    if (raws.includes(value) && args[0] === 'hex') decodes.set(value, (decodes.get(value) ?? 0) + 1);
    return from(value, ...args);
  });
  const bounded = new FundingTransactionCache({ maxEntries: 2 });
  bounded.transactionId(raws[0]); bounded.transactionId(raws[1]); bounded.transactionId(raws[0]); bounded.transactionId(raws[2]);
  assert.equal(bounded.size, 2);
  bounded.transactionId(raws[0]); assert.equal(decodes.get(raws[0]), 1);
  bounded.transactionId(raws[1]); assert.equal(decodes.get(raws[1]), 2);
  const one = new FundingTransactionCache(); one.transactionId(raws[0]);
  const byteBound = one.retainedBytes;
  const limited = new FundingTransactionCache({ maxBytes: byteBound });
  for (const raw of raws) { limited.transactionId(raw); assert.equal(limited.size, 1); assert.ok(limited.retainedBytes <= byteBound); }
  const tooSmall = new FundingTransactionCache({ maxBytes: byteBound - 1 });
  assert.equal(tooSmall.transactionId(raws[0]), bounty.txid);
  assert.equal(tooSmall.size, 0); assert.equal(tooSmall.retainedBytes, 0);
  for (const options of [{ maxEntries: 0 }, { maxEntries: 257 }, { maxBytes: 0 }, { maxBytes: Infinity }]) assert.throws(() => new FundingTransactionCache(options), /bounds/);
});

function framingFixture(claim) {
  const record = (type, body) => {
    const header = Buffer.alloc(4); header[0] = type; header.writeUIntBE(body.length, 1, 3);
    return Buffer.concat([header, body]);
  };
  // Deliberately only wire framing; certificate verification belongs to the TLS helper.
  const hello = Buffer.concat([Buffer.from([3, 3]), Buffer.from(claim.challenge, 'hex')]);
  return Buffer.concat([Buffer.from([2]), record(1, hello), ...[2, 8, 11, 15].map(type => record(type, Buffer.alloc(0)))]);
}

test('proof binds witness to prepared payout without changing the transaction ID', () => {
  const claim = proposal(), fixture = framingFixture(claim), proof = fixture.toString('hex');
  const completed = attachClaimProof(claim, proof);
  assert.equal(completed.txid, claim.txid);
  assert.equal(transactionIdFromRaw(completed.hex), claim.txid);
  assert.deepEqual(parseTransaction(completed.hex).inputs[0].witness, [proof]);
  assert.equal(completed.payout, claim.payout);
  assert.deepEqual(claim.transaction.inputs[0].witness, []);
  const changed = Buffer.from(fixture); changed[8] ^= 1;
  assert.throws(() => attachClaimProof(claim, changed.toString('hex')), /bound/);
  assert.throws(() => attachClaimProof({ ...claim, txid: '11'.repeat(32) }, proof), /changed/);
  const changedTx = structuredClone(claim.transaction); changedTx.outputs[0].amount = '1';
  assert.throws(() => attachClaimProof({ ...claim, hex: serializeTransaction(changedTx).toString('hex') }, proof), /changed/);
  assert.throws(() => attachClaimProof({ ...claim, bounty: { ...claim.bounty, target: '00'.repeat(32) } }, proof), /work target/);
  for (const malformed of ['00', '02', proof + '00', proof.slice(0, -2)]) assert.throws(() => attachClaimProof(claim, malformed));
});
