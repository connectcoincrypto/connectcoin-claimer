import test from 'node:test';
import assert from 'node:assert/strict';
import { formatServiceEvent, formatMetricsLine } from '../src/cli.mjs';

const txid = '1'.repeat(64);

test('CLI preserves accepted/discovery and exact metric line formats used by operational parsers', () => {
  assert.equal(formatServiceEvent('broadcast', { status: 'accepted', txid }), `Claim accepted: ${txid}`);
  assert.equal(formatServiceEvent('discovery', { height: 97672, available: 67 }), 'Discovery: height 97672, 67 available bounties.');
  const state = { status: 'running', claims: { completed: 2 }, metrics: {
    connectionsPerSecond: 599.97, activeConnections: 34, connectionsStarted: 108000,
    valid: 107959, invalid: 3, targetReached: 2,
  } };
  const line = formatMetricsLine(state);
  assert.equal(line, '[running] 600.0 connections/s (last 10s) | active 34 | started 108000 | valid 107959 | failed 3 | target reached 2 | submitted 2 | target misses 0');
  assert.equal(formatMetricsLine({ ...state, status: 'resyncing' }), line.replace('[running]', '[resyncing]'));
  assert.equal(formatMetricsLine({}), '[running] 0.0 connections/s (last 10s) | active 0 | started 0 | valid 0 | failed 0 | target reached 0 | submitted 0 | target misses 0');
  assert.equal(formatMetricsLine({ ...state, metrics: { ...state.metrics, targetMisses: 27 } }), line.replace('target misses 0', 'target misses 27'));
  assert.equal(formatServiceEvent('state', state), null);
});

test('CLI reset diagnostics distinguish initial discovery from a non-destructive catalog barrier', () => {
  assert.equal(formatServiceEvent('discovery-reset', { reason: 'initial' }), 'Discovery reset: initial; preparing a coherent catalog.');
  assert.equal(formatServiceEvent('discovery-reset', { reason: 'cursor-invalid', code: -32011 }),
    'Discovery reset: cursor-invalid (RPC -32011); no helper restart requested; new preparations and broadcasts wait for a coherent catalog.');
  assert.match(formatServiceEvent('discovery-reset', { reason: 'data-unavailable', code: -32004 }), /data-unavailable \(RPC -32004\)/);
  assert.match(formatServiceEvent('discovery-reset', { reason: 'journal-reset' }), /journal-reset; no helper restart requested/);
});

test('CLI RPC diagnostics expose safe code, failure source and transmission outcome without raw response text', () => {
  const line = formatServiceEvent('rpc-diagnostic', { method: 'getblockbounties', stage: 'stream', failureSource: 'stream-incomplete',
    error: { category: 'snapshot-stale', code: -32011, message: 'SECRET peer response with raw proof bytes' },
    sent: true, notSent: false, unknownOutcome: false, raw: 'SECRET raw reply' });
  assert.equal(line, 'RPC failure: method=getblockbounties stage=stream source=stream-incomplete category=snapshot-stale code=-32011 sent=yes not_sent=no unknown_outcome=no.');
  assert.doesNotMatch(line, /SECRET|proof bytes|raw reply/);
  assert.match(formatServiceEvent('rpc-diagnostic', { method: 'sendrawtransaction', stage: 'request', failureSource: 'socket-close',
    error: { category: 'broadcast-unknown', code: 'ECONNRESET' }, sent: true, notSent: false, unknownOutcome: true }),
  /source=socket-close category=broadcast-unknown code=ECONNRESET sent=yes not_sent=no unknown_outcome=yes/);
});

test('CLI broadcast diagnostics explain scoped reservations, recovery and quarantine without printing saved proofs', () => {
  for (const status of ['pending', 'unknown']) {
    const line = formatServiceEvent('broadcast', { status, txid, transactionHex: 'SECRET transaction', proof: 'SECRET proof',
      reason: { category: 'node-rejected', code: -32020, nodeCode: -27, message: 'SECRET server details' } });
    assert.match(line, /only this outpoint is reserved/);
    assert.match(line, /category=node-rejected code=-32020 node_code=-27/);
    assert.doesNotMatch(line, /SECRET/);
  }
  assert.match(formatServiceEvent('broadcast', { status: 'recovered-accepted', txid }), /accepted result recovered; exact transaction retained until block confirmation/);
  assert.match(formatServiceEvent('broadcast', { status: 'confirmed', txid }), /block confirmation validated; saved transaction bytes compacted/);
  assert.match(formatServiceEvent('broadcast', { status: 'reconciliation-pending', txid }), /identical saved transaction retained/);
  assert.match(formatServiceEvent('broadcast', { status: 'quarantined-legacy-no-bytes', txid }), /legacy record has no saved proof.*other claims continue/);
  assert.match(formatServiceEvent('broadcast', { status: 'quarantined-address-mismatch', txid }), /saved receiving address differs.*other claims continue/);
});

test('CLI new diagnostic fields are allowlisted and cannot inject arbitrary server strings or extra lines', () => {
  const secret = 'SECRET\n[forged] receipt\x1b[2J';
  const lines = [
    formatServiceEvent('discovery-reset', { reason: secret, code: secret, message: secret }),
    formatServiceEvent('rpc-diagnostic', { method: secret, stage: secret, failureSource: secret,
      error: { category: secret, code: secret, nodeCode: secret, message: secret, cause: secret },
      sent: secret, notSent: secret, unknownOutcome: secret }),
    formatServiceEvent('broadcast', { status: secret, txid: secret, reason: { category: secret, code: secret, message: secret } }),
  ];
  for (const line of lines) { assert.doesNotMatch(line, /SECRET|forged|\n|\x1b/); assert.ok(line.length < 400); }
});
