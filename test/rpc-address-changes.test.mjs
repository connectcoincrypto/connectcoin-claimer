import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRpcParams } from '../src/core/rpc.mjs';

test('address changes sends only bounded copied public addresses and optional cursor', () => {
  const addresses = ['syntheticaddress1', 'syntheticaddress2'];
  const params = validateRpcParams('getaddresschanges', { addresses, cursor: 'opaque-cursor_1' });
  addresses[0] = 'mutatedaddress';
  assert.deepEqual(params, { addresses: ['syntheticaddress1', 'syntheticaddress2'], cursor: 'opaque-cursor_1' });
  assert.deepEqual(validateRpcParams('getaddresschanges', { addresses: ['syntheticaddress'], cursor: null }), { addresses: ['syntheticaddress'], cursor: null });
  for (const value of [[], ['short'], ['syntheticaddress', 'syntheticaddress'], ['bad address'], Array(101).fill('syntheticaddress'), [null]]) {
    assert.throws(() => validateRpcParams('getaddresschanges', { addresses: value }));
  }
  let getterCalls = 0;
  const evil = []; Object.defineProperty(evil, '0', { get() { getterCalls++; return 'syntheticaddress'; } });
  assert.throws(() => validateRpcParams('getaddresschanges', { addresses: evil })); assert.equal(getterCalls, 0);
  assert.throws(() => validateRpcParams('getaddresschanges', { addresses: ['syntheticaddress'], mnemonic: 'must-not-leak' }));
});

test('pending-spent inclusion is optional and must be a boolean on UTXO reads only', () => {
  assert.deepEqual(validateRpcParams('getaddressutxos', { address: 'syntheticaddress', include_pending_spent: true }), { address: 'syntheticaddress', include_pending_spent: true });
  assert.deepEqual(validateRpcParams('getaddressutxos', { address: 'syntheticaddress' }), { address: 'syntheticaddress' });
  for (const value of [null, 1, 'true', {}]) assert.throws(() => validateRpcParams('getaddressutxos', { address: 'syntheticaddress', include_pending_spent: value }));
  assert.throws(() => validateRpcParams('getaddresshistory', { address: 'syntheticaddress', include_pending_spent: true }));
});

test('address subscriptions copy the optional changes-only boolean and reject coercions or accessors', () => {
  const request = { address: 'syntheticaddress', changes_only: true };
  const params = validateRpcParams('subscribeaddress', request);
  request.changes_only = false;
  assert.deepEqual(params, { address: 'syntheticaddress', changes_only: true });
  assert.deepEqual(validateRpcParams('subscribeaddress', request), { address: 'syntheticaddress', changes_only: false });
  assert.deepEqual(validateRpcParams('subscribeaddress', { address: 'syntheticaddress' }), { address: 'syntheticaddress' });
  for (const changes_only of [undefined, null, 0, 1, 'true', {}, []]) {
    assert.throws(() => validateRpcParams('subscribeaddress', { address: 'syntheticaddress', changes_only }), /Invalid RPC address change option/);
  }
  let getterCalls = 0;
  assert.throws(() => validateRpcParams('subscribeaddress', {
    address: 'syntheticaddress', get changes_only() { getterCalls++; return true; },
  }), /plain data/);
  assert.equal(getterCalls, 0);
  assert.throws(() => validateRpcParams('getaddressbalance', { address: 'syntheticaddress', changes_only: true }), /Unexpected/);
});
