import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRpcParams } from '../src/core/rpc.mjs';

const hash = 'ab'.repeat(32), known_tip = { height: 700, hash }, cursor = 'opaque-cursor';

test('compact versions 2 and 3 are explicit numeric opt-ins, without getters or mixed legacy modes', () => {
  const base = { include_bounties: true, compact: true };
  assert.deepEqual(validateRpcParams('getbountychanges', { ...base, compact_version: 2 }), { ...base, compact_version: 2 });
  assert.deepEqual(validateRpcParams('getbountychanges', { ...base, compact_version: 3 }), { ...base, compact_version: 3 });
  for (const value of [undefined, null, 0, 1, 4, 2.5, '2', '3', true, [], {}]) {
    assert.throws(() => validateRpcParams('getbountychanges', { ...base, compact_version: value }), /Invalid RPC compact version/);
  }
  for (const params of [{ compact_version: 2 }, { include_bounties: true, compact: false, compact_version: 2 }]) {
    assert.throws(() => validateRpcParams('getbountychanges', params), /Invalid RPC/);
  }
  assert.throws(() => validateRpcParams('getbountychanges', { ...base, get compact_version() { assert.fail('Getter executed'); } }), /plain data/);
});
test('compact/count/raw opt-ins require booleans and never invoke getters or leak extras', () => {
  for (const [method, key, base] of [['getbountychanges', 'compact', { include_bounties: true }],
    ['getrecentblockhashes', 'include_bounty_counts', {}], ['gettransaction', 'raw_only', { txid: hash }]]) {
    for (const value of [true, false]) assert.deepEqual(validateRpcParams(method, { ...base, [key]: value }), { ...base, [key]: value });
    for (const value of [undefined, null, 0, 1, 'true', [], {}]) assert.throws(() => validateRpcParams(method, { ...base, [key]: value }), /Invalid RPC/);
    assert.throws(() => validateRpcParams(method, Object.defineProperty({ ...base }, key, { get() { assert.fail('Getter executed'); } })), /plain data/);
    assert.throws(() => validateRpcParams(method, { ...base, [key]: true, password: 'secret' }), /Unexpected/);
  }
  assert.deepEqual(validateRpcParams('getbountychanges', { compact: false }), { compact: false });
  assert.throws(() => validateRpcParams('getbountychanges', { compact: true }), /Invalid RPC compact/);
  assert.throws(() => validateRpcParams('getbountychanges', { include_bounties: false, compact: true }), /Invalid RPC compact/);
});

test('known_state is an exact normalized digest requiring compact, known_tip and a valid string cursor', () => {
  const base = { cursor, include_bounties: true, known_tip, compact: true };
  assert.deepEqual(validateRpcParams('getbountychanges', { ...base, known_state: hash.toUpperCase() }), { ...base, known_state: hash });
  for (const value of [undefined, null, '', 'a'.repeat(63), 'a'.repeat(65), 'z'.repeat(64), [], {}]) {
    assert.throws(() => validateRpcParams('getbountychanges', { ...base, known_state: value }), /Invalid RPC known state/);
  }
  for (const key of ['cursor', 'compact', 'known_tip', 'include_bounties']) {
    const params = { ...base, known_state: hash }; delete params[key];
    assert.throws(() => validateRpcParams('getbountychanges', params), /Invalid RPC/);
  }
  assert.throws(() => validateRpcParams('getbountychanges', { ...base, cursor: null, known_state: hash }), /Invalid RPC known state/);
  assert.throws(() => validateRpcParams('getbountychanges', { ...base, get known_state() { assert.fail('Getter executed'); } }), /plain data/);
});
