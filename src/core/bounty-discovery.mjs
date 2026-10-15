import { createHash } from 'node:crypto';
import { validateTip } from './config.mjs';

const HASH = /^[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const MAX_ROWS = 100000;
// More than the default 10,000-event journal (100 pages), plus replay/fences.
// This is a work budget, not evidence of invalid RPC data. Smaller server pages
// or sustained updates fall back to a fresh, fully validated snapshot.
const MAX_JOURNAL_PAGES = 128;
export const bountyKey = row => `${row.txid}:${row.vout}`;
const uint = (value, maximum = 0xffffffff) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const cursorValid = value => typeof value === 'string' && value.length > 0 && value.length <= 4096;
class RescanRequired extends Error {}
class DiscoveryBudgetExceeded extends RescanRequired {}
class UnknownBountyReference extends Error {}
const IMMUTABLE_BOUNTY_FIELDS = ['txid', 'vout', 'block_hash', 'block_height', 'amount', 'domain',
  'connection_work_target', 'root_certificates_version', 'signature_algorithms_mask', 'coinbase'];
const digest = fields => createHash('sha256').update(JSON.stringify(fields)).digest('hex');
export const bountyStateDigest = (tip, cursor) => digest(['bounty-state-v1', tip.chain, tip.genesis_hash,
  tip.height, tip.hash, tip.mediantime, cursor]);
export const bountyImmutableDigest = row => digest(['bounty-immutable-v1', ...IMMUTABLE_BOUNTY_FIELDS.map(key => row[key])]);
export class BountyDiscoveryBusy extends Error {
  constructor() {
    super('The bounty snapshot is still changing; retrying discovery shortly.');
    this.code = 'CLAIMS_SYNC_BUSY';
  }
}

function validateRecentBlocks(response, network, count) {
  validateTip(response?.tip, network);
  // Older servers may ignore count and return the complete window. No other
  // short/overlong response is accepted as a valid prefix.
  const fullCount = Math.min(600, response.tip.height + 1);
  if (response.window !== 600 || !Array.isArray(response.blocks) ||
      (response.blocks.length !== Math.min(count, response.tip.height + 1) && response.blocks.length !== fullCount)) throw new Error('RPC did not provide the complete requested recent-block window.');
  const hashes = new Set();
  for (const [index, block] of response.blocks.entries()) {
    if (!block || typeof block.hash !== 'string' || !HASH.test(block.hash) || block.height !== response.tip.height - index || hashes.has(block.hash) || (index === 0 && block.hash !== response.tip.hash) || (block.height === 0 && block.hash !== response.tip.genesis_hash)) throw new Error('Invalid recent-block sequence.');
    hashes.add(block.hash);
  }
}

function rpcBlockCounts(response) {
  if (response.bounty_counts === undefined) {
    if (response.blocks?.some(block => Object.hasOwn(block, 'bounty_count'))) throw new Error('Missing bounty count capability.');
    return [];
  }
  if (response.bounty_counts !== 1 || !Array.isArray(response.blocks) ||
      response.blocks.some(block => !block || !uint(block.bounty_count, MAX_ROWS))) throw new Error('Invalid authoritative bounty counts.');
  return response.blocks.map(block => [block.hash, block.bounty_count]);
}

function windowFrom(response, network, lookback) {
  validateRecentBlocks(response, network, 600);
  return response.blocks.slice(0, lookback);
}

function validatedWindow(response, network, retainedCounts) {
  windowFrom(response, network, 600);
  const counts = {}, canonical = new Set(response.blocks.map(block => block.hash));
  if (retainedCounts !== undefined) {
    if (!retainedCounts || Array.isArray(retainedCounts) || typeof retainedCounts !== 'object' ||
        ![null, Object.prototype].includes(Object.getPrototypeOf(retainedCounts))) throw new Error('Invalid cached block counts.');
    for (const hash of Reflect.ownKeys(retainedCounts)) {
      const descriptor = Object.getOwnPropertyDescriptor(retainedCounts, hash);
      if (typeof hash !== 'string' || !HASH.test(hash) || !canonical.has(hash) || !Object.hasOwn(descriptor, 'value') ||
          !uint(descriptor.value, MAX_ROWS)) throw new Error('Invalid cached block count.');
      counts[hash] = descriptor.value;
    }
  }
  // Only publish a complete, privately owned immutable snapshot. Callers must
  // retain it together with the processed journal cursor, never a partial read.
  return Object.freeze({ window: 600, tip: Object.freeze({ ...response.tip }),
    blocks: Object.freeze(response.blocks.map(({ height, hash }) => Object.freeze({ height, hash }))),
    ...(Object.keys(counts).length ? { blockCounts: Object.freeze(counts) } : {}) });
}

function retainedBlockCounts(known, blocks, additions = []) {
  const hashes = new Set(blocks.map(block => block.hash));
  const counts = Object.fromEntries(Object.entries(known?.blockCounts ?? {}).filter(([hash]) => hashes.has(hash)));
  for (const [hash, count] of additions) {
    if (counts[hash] !== undefined && counts[hash] !== count) throw new Error('Inconsistent immutable block count.');
    if (hashes.has(hash)) counts[hash] = count;
  }
  return counts;
}

function sameTip(left, right) {
  if (left.hash !== right.hash) return false;
  // A hash identifies one header and its ancestry. Matching hashes must not
  // conceal contradictory heights/times (including from a cached response).
  if (left.height !== right.height || left.mediantime !== right.mediantime ||
      left.chain !== right.chain || left.genesis_hash !== right.genesis_hash) {
    throw new Error('The RPC server returned inconsistent metadata for the same chain tip.');
  }
  return true;
}

function joinRecentWindow(response, known, network) {
  sameTip(known.tip, response.tip); // Check metadata if the tip hash matches.
  const knownHeights = new Map(known.blocks.map(block => [block.hash, block.height]));
  const knownHashes = new Map(known.blocks.map(block => [block.height, block.hash]));
  let anchor = -1;
  for (const [index, block] of response.blocks.entries()) {
    if (knownHeights.has(block.hash)) {
      if (knownHeights.get(block.hash) !== block.height) throw new Error('Inconsistent recent-block hash height.');
      if (anchor < 0) anchor = index;
    }
    // One block identifies its ancestry too: never splice a prefix whose
    // overlapping ancestors contradict the validated cached chain.
    if (anchor >= 0 && knownHashes.has(block.height) && knownHashes.get(block.height) !== block.hash) throw new Error('Inconsistent recent-block ancestry.');
  }
  const size = Math.min(600, response.tip.height + 1);
  if (response.blocks.length === size) return validatedWindow(response, network, retainedBlockCounts(known, response.blocks, rpcBlockCounts(response)));
  if (anchor < 0) return null;
  const anchorHeight = response.blocks[anchor].height;
  const blocks = [...response.blocks.slice(0, anchor), ...known.blocks.filter(block => block.height <= anchorHeight)].slice(0, size);
  // A rollback can find an anchor while still lacking the oldest required
  // blocks. Escalate rather than silently publishing an incomplete window.
  if (blocks.length !== size) return null;
  return validatedWindow({ window: 600, tip: response.tip, blocks }, network, retainedBlockCounts(known, blocks, rpcBlockCounts(response)));
}

async function refreshRecentWindow(query, known, network) {
  if (!known) {
    const response = await query('getrecentblockhashes');
    return validatedWindow(response, network, Object.fromEntries(rpcBlockCounts(response)));
  }
  for (const count of [5, 100, 600]) {
    let response;
    try { response = await query('getrecentblockhashes', count === 600 ? {} : { count }); }
    catch (error) {
      if (count === 600 || error.code !== -32602) throw error;
      // Compatibility with servers that reject the optional count parameter.
      // Transport errors and malformed responses must never take this path.
      response = await query('getrecentblockhashes');
      validateRecentBlocks(response, network, 600);
    }
    validateRecentBlocks(response, network, count);
    // Each response has its own tip. Do not combine the 5- and 100-block
    // responses: the chain may have changed between those requests.
    const joined = joinRecentWindow(response, known, network);
    if (joined) return joined;
  }
  throw new Error('RPC did not provide the complete recent-block window.');
}

function validateBlockDelta(page, known, network) {
  if (page.block_deltas === undefined) {
    if (Object.hasOwn(page, 'block_delta')) throw new Error('Invalid block delta capability.');
    return null;
  }
  if (page.block_deltas !== 1 || page.bounty_deltas !== 1 || !known || !Object.hasOwn(page, 'block_delta')) throw new Error('Invalid block delta capability.');
  const delta = page.block_delta;
  if (delta === null) {
    if (sameTip(known.tip, page.tip)) throw new Error('Missing canonical block delta.');
    return null;
  }
  if (!delta || Array.isArray(delta) || delta.base_height !== known.tip.height || delta.base_hash !== known.tip.hash ||
      !Array.isArray(delta.blocks) || delta.blocks.length > 5 || delta.blocks.length !== page.tip.height - known.tip.height) throw new Error('Invalid block delta base or sequence.');
  sameTip(known.tip, page.tip);
  const counts = new Map(), hashes = new Set(known.blocks.map(block => block.hash));
  for (const [index, block] of delta.blocks.entries()) {
    if (!block || Array.isArray(block) || block.height !== known.tip.height + index + 1 ||
        typeof block.hash !== 'string' || !HASH.test(block.hash) || hashes.has(block.hash) ||
        !uint(block.bounty_count, MAX_ROWS)) throw new Error('Invalid block delta metadata.');
    hashes.add(block.hash); counts.set(block.hash, block.bounty_count);
  }
  const blocks = [...delta.blocks.slice().reverse(), ...known.blocks].slice(0, Math.min(600, page.tip.height + 1));
  const window = validatedWindow({ window: 600, tip: page.tip, blocks }, network, retainedBlockCounts(known, blocks, counts));
  return { window, counts };
}

function validateBountyRow(row, tip, hash, height, delta = false) {
  if (!row || Array.isArray(row) || typeof row.txid !== 'string' || !HASH.test(row.txid) || row.block_hash !== hash || !uint(row.vout) || !uint(row.block_height) || (height !== undefined && row.block_height !== height) || row.block_height > tip.height || typeof row.amount !== 'string' || !/^\d{1,19}$/.test(row.amount) || BigInt(row.amount) > 1000000000000000000n || typeof row.connection_work_target !== 'string' || !HASH.test(row.connection_work_target) || typeof row.domain !== 'string' || !DOMAIN.test(row.domain) || row.domain.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || !uint(row.root_certificates_version) || row.root_certificates_version === 0 || !uint(row.signature_algorithms_mask, 7) || row.signature_algorithms_mask === 0 || typeof row.coinbase !== 'boolean' || !uint(row.confirmations) || row.confirmations !== tip.height - row.block_height + 1 || !['available','spent','pending_spend','immature'].includes(row.status) || (row.spending_txid !== null && (typeof row.spending_txid !== 'string' || !HASH.test(row.spending_txid))) || (row.status === 'available' && row.coinbase && row.confirmations < 100)) throw new Error('Invalid bounty metadata.');
  if (delta && (row.block_height < Math.max(0, tip.height - 599) ||
      (['spent', 'pending_spend'].includes(row.status) !== (row.spending_txid !== null)) ||
      ((row.status === 'immature') !== (row.coinbase && row.confirmations < 100)))) throw new Error('Invalid bounty delta metadata.');
}

// Compact v2 changes transport representation only. Reconstruct a v1-shaped
// page before the same sequence/count/row/canonical-window validators run.
// No array/null alias may borrow state from another request or RPC epoch.
function normalizeCompactV2Page(page, { requestedVersion, state, base, network }) {
  if (page?.compact !== 2) return page;
  if (requestedVersion !== 2) throw new Error('Unrequested compact bounty version.');
  if (Object.hasOwn(page, 'unchanged')) {
    if (page.unchanged !== true || Reflect.ownKeys(page).length !== 2) throw new Error('Invalid unchanged bounty acknowledgement.');
    return { compact: 1, unchanged: true };
  }
  if (Object.hasOwn(page, 'bounty_deltas') || Object.hasOwn(page, 'block_deltas') ||
      !Array.isArray(page.changes) || page.changes.length > 10000 ||
      !Array.isArray(page.tips) || page.tips.length > 10000) throw new Error('Invalid compact v2 bounty page.');
  const bound = Array.isArray(page.tip);
  let tip = page.tip, blockDelta = page.block_delta, cursor = page.next_cursor;
  if (bound) {
    if (!state || !base || state.digest !== bountyStateDigest(state.tip, state.cursor) ||
        !sameTip(state.tip, base.tip) || tip.length !== 3 || !Array.isArray(blockDelta) || blockDelta.length > 5) {
      throw new Error('Invalid request-bound bounty page.');
    }
    validateTip(state.tip, network);
    tip = { height: tip[0], hash: tip[1], mediantime: tip[2], chain: state.tip.chain, genesis_hash: state.tip.genesis_hash };
    validateTip(tip, network);
    if (blockDelta.length !== tip.height - base.tip.height) throw new Error('Invalid request-bound block sequence.');
    blockDelta = { base_height: base.tip.height, base_hash: base.tip.hash, blocks: blockDelta.map((entry, index) => {
      const height = base.tip.height + index + 1;
      if (!Array.isArray(entry) || entry.length !== 2 || !uint(entry[1], MAX_ROWS) ||
          (entry[0] === null ? index !== page.block_delta.length - 1 || height !== tip.height : typeof entry[0] !== 'string' || !HASH.test(entry[0]))) {
        throw new Error('Invalid request-bound block metadata.');
      }
      return { height, hash: entry[0] === null ? tip.hash : entry[0], bounty_count: entry[1] };
    }) };
    if (cursor === null) {
      if (page.changes.length || page.has_more !== false || !cursorValid(state.cursor)) throw new Error('Invalid unchanged bounty cursor.');
      cursor = state.cursor;
    }
  } else if (Array.isArray(blockDelta) || cursor === null) throw new Error('Unbound compact bounty alias.');
  validateTip(tip, network);
  const tips = page.tips.slice();
  let currentTipIndex;
  const changes = page.changes.map(original => {
    if (!original || Array.isArray(original) ||
        (original.tip_ref !== -1 && !uint(original.tip_ref, page.tips.length - 1))) throw new Error('Invalid compact bounty event.');
    const event = { ...original };
    if (event.tip_ref === -1) {
      currentTipIndex ??= tips.push(tip) - 1;
      event.tip_ref = currentTipIndex;
    }
    if (event.type === 'added') {
      if (['txid', 'vout', 'block_hash', 'block_height'].some(key => Object.hasOwn(event, key))) throw new Error('Mixed compact added identity.');
      const eventTip = tips[event.tip_ref];
      validateTip(eventTip, network);
      validateBountyRow(event.bounty, eventTip, event.bounty?.block_hash, undefined, true);
      Object.assign(event, { txid: event.bounty.txid, vout: event.bounty.vout, block_hash: event.bounty.block_hash, block_height: event.bounty.block_height });
    }
    if (Object.hasOwn(event, 'spending_txid_ref')) {
      if (event.spending_txid_ref !== true || Object.hasOwn(event, 'spending_txid') ||
          !['pending_spend', 'spent', 'available_again', 'matured'].includes(event.type) ||
          !event.bounty_delta || !Object.hasOwn(event.bounty_delta, 'spending_txid')) throw new Error('Invalid compact spender alias.');
      event.spending_txid = event.bounty_delta.spending_txid;
      delete event.spending_txid_ref;
    }
    return event;
  });
  return { ...page, compact: 1, tip, tips, changes, next_cursor: cursor, bounty_deltas: 1,
    ...(base || Object.hasOwn(page, 'block_delta') ? { block_deltas: 1, block_delta: blockDelta } : {}) };
}

function expandCompactPage(page, { requested, state, base, staged, network, lastSequence, inline, expectedCounts, lookback }) {
  if (page?.compact === undefined) {
    if (page && (Object.hasOwn(page, 'unchanged') || Object.hasOwn(page, 'tips'))) throw new Error('Missing compact bounty capability.');
    return page;
  }
  if (!requested || page.compact !== 1) throw new Error('Invalid compact bounty capability.');
  if (Object.hasOwn(page, 'unchanged')) {
    if (page.unchanged !== true || Reflect.ownKeys(page).length !== 2 || !state || !base ||
        state.digest !== bountyStateDigest(state.tip, state.cursor) || !sameTip(state.tip, base.tip)) throw new Error('Invalid unchanged bounty acknowledgement.');
    // This request's privately owned, complete hash window is the only source
    // of an ACK's tip/cursor. An ACK cannot introduce a hash, row or zero count.
    return { tip: state.tip, next_cursor: state.cursor, has_more: false, changes: [], bounty_deltas: 1,
      block_deltas: 1, block_delta: { base_height: base.tip.height, base_hash: base.tip.hash, blocks: [] } };
  }
  if (page.bounty_deltas !== 1 || !Array.isArray(page.tips) || page.tips.length > 10000 ||
      !Array.isArray(page.changes) || page.changes.length > 10000) throw new Error('Invalid compact bounty page.');
  validateTip(page.tip, network);
  for (const tip of page.tips) {
    validateTip(tip, network); sameTip(tip, page.tip);
    if (tip.height > page.tip.height) throw new Error('Invalid bounty publication tip.');
  }
  // Validate the complete wire shape before deciding whether an unknown row
  // requires an expanded replay. Malformation is never a negotiation signal.
  const events = page.changes.map(event => {
    if (!event || !['added', 'spent', 'pending_spend', 'available_again', 'matured', 'window_exit'].includes(event.type) ||
        typeof event.txid !== 'string' || !HASH.test(event.txid) || !uint(event.vout) ||
        !uint(event.sequence, Number.MAX_SAFE_INTEGER) || event.sequence <= lastSequence ||
        !uint(event.tip_ref, page.tips.length - 1) || Object.hasOwn(event, 'tip') || Object.hasOwn(event, 'spending_txid_ref') ||
        (event.block_hash !== undefined && (typeof event.block_hash !== 'string' || !HASH.test(event.block_hash))) ||
        (event.spending_txid !== undefined && event.spending_txid !== null && (typeof event.spending_txid !== 'string' || !HASH.test(event.spending_txid)))) throw new Error('Invalid compact bounty event.');
    lastSequence = event.sequence;
    const tip = page.tips[event.tip_ref];
    if (event.type === 'added' || event.type === 'window_exit') {
      if (Object.hasOwn(event, 'bounty_ref') || Object.hasOwn(event, 'bounty_delta') ||
          (event.type === 'window_exit' && event.bounty !== null)) throw new Error('Invalid compact bounty payload.');
      if (event.type === 'added') {
        if (typeof event.bounty?.block_hash !== 'string' || !HASH.test(event.bounty.block_hash) ||
            (event.block_hash !== undefined && event.block_hash !== event.bounty.block_hash)) throw new Error('Invalid bounty delta identity.');
        validateBountyRow(event.bounty, tip, event.bounty?.block_hash, undefined, true);
        if (event.bounty.txid !== event.txid || event.bounty.vout !== event.vout) throw new Error('Invalid bounty delta identity.');
      }
    } else {
      const delta = event.bounty_delta;
      if (Object.hasOwn(event, 'bounty') || typeof event.bounty_ref !== 'string' || !HASH.test(event.bounty_ref) ||
          !delta || Array.isArray(delta) || Reflect.ownKeys(delta).length !== 3 ||
          Reflect.ownKeys(delta).some(key => !['status', 'spending_txid', 'confirmations'].includes(key)) ||
          !['available', 'spent', 'pending_spend', 'immature'].includes(delta.status) || !uint(delta.confirmations) || delta.confirmations === 0 ||
          (delta.spending_txid !== null && (typeof delta.spending_txid !== 'string' || !HASH.test(delta.spending_txid))) ||
          (['spent', 'pending_spend'].includes(delta.status) !== (delta.spending_txid !== null))) throw new Error('Invalid compact bounty state.');
    }
    return { ...event, tip };
  });
  const rows = new Map();
  if (events.length) for (const block of staged.values()) for (const row of block) {
    const key = bountyKey(row);
    if (rows.has(key)) throw new Error('Duplicate bounty across the recent window.');
    rows.set(key, row);
  }
  const canonicalWindow = inline?.window ?? (base && sameTip(base.tip, page.tip) ? base : null);
  const canonical = new Map(canonicalWindow?.blocks.map(block => [block.height, block.hash]) ?? []);
  const heights = new Map(canonicalWindow?.blocks.map(block => [block.hash, block.height]) ?? []);
  const selected = new Set(canonicalWindow?.blocks.slice(0, lookback).map(block => block.hash) ?? []);
  const counts = new Map([...expectedCounts, ...Object.entries(inline?.window.blockCounts ?? {})]);
  const sizes = new Map([...staged].map(([hash, block]) => [hash, block.length]));
  let unknown = false;
  for (const event of events) {
    const key = bountyKey(event);
    if (canonical.has(event.tip.height) && canonical.get(event.tip.height) !== event.tip.hash) throw new RescanRequired('Bounty publication is no longer canonical.');
    if (event.type === 'window_exit') {
      const hash = event.block_hash ?? rows.get(key)?.block_hash;
      if (selected.has(hash)) throw new RescanRequired('A bounty exited a retained canonical block.');
      continue;
    }
    if (event.type === 'added') {
      const previous = rows.get(key);
      if (previous && IMMUTABLE_BOUNTY_FIELDS.some(field => previous[field] !== event.bounty[field])) throw new Error('Inconsistent immutable bounty metadata.');
      if (!previous) sizes.set(event.bounty.block_hash, (sizes.get(event.bounty.block_hash) ?? 0) + 1);
      rows.set(key, event.bounty);
    }
    else if (Object.hasOwn(event, 'bounty_ref')) {
      const previous = rows.get(key);
      if (!previous) {
        if (event.block_hash !== undefined && counts.get(event.block_hash) === 0) throw new Error('Bounty delta contradicts its immutable block count.');
        unknown = true; continue;
      }
      if (bountyImmutableDigest(previous) !== event.bounty_ref) throw new Error('Inconsistent immutable bounty reference.');
      event.bounty = { ...previous, ...event.bounty_delta };
      validateBountyRow(event.bounty, event.tip, event.bounty.block_hash, undefined, true);
      rows.set(key, event.bounty);
    }
    if (event.bounty) {
      const row = event.bounty;
      if (event.block_hash !== undefined && event.block_hash !== row.block_hash) throw new Error('Invalid bounty delta identity.');
      validateBountyRow(row, event.tip, row.block_hash, heights.get(row.block_hash), true);
      if (canonical.has(row.block_height) && canonical.get(row.block_height) !== row.block_hash) throw new RescanRequired('Bounty delta is no longer canonical.');
      if (counts.get(row.block_hash) === 0 || (counts.has(row.block_hash) && (sizes.get(row.block_hash) ?? 0) > counts.get(row.block_hash))) {
        throw new Error('Bounty delta contradicts its immutable block count.');
      }
    }
  }
  if (unknown) throw new UnknownBountyReference();
  return { ...page, changes: events };
}

/** A block is applied only after the transport acknowledges a complete stream. */
export async function readBountyBlock({ rpc, network, hash, height, check = () => {}, budget = { count: 0, limit: MAX_ROWS } }) {
  if (!HASH.test(hash)) throw new Error('Invalid bounty block hash.');
  const records = [], seen = new Set();
  let sawSnapshot = false, sawState = false, chunks = 0;
  check();
  const end = await rpc.request('getblockbounties', { block_hash: hash }, { onChunk: chunk => {
    check(); validateTip(chunk?.tip, network); chunks++;
    if (chunk.type === 'snapshot' && !sawSnapshot && chunks === 1 && chunk.block_hash === hash && chunk.unit === 'connects' && cursorValid(chunk.cursor)) sawSnapshot = true;
    else if (chunk.type === 'bounties' && sawSnapshot && !sawState && Array.isArray(chunk.items) && chunk.items.length <= 1000) {
      for (const row of chunk.items) {
        validateBountyRow(row, chunk.tip, hash, height);
        const key = bountyKey(row);
        if (seen.has(key)) throw new Error('Duplicate bounty in block stream.');
        if (records.length >= MAX_ROWS || budget.count >= Math.min(MAX_ROWS, budget.limit ?? MAX_ROWS)) throw new Error('Recent bounty data exceeds the wallet resource limit; no partial snapshot was applied.');
        seen.add(key); budget.count++; records.push(structuredClone(row));
      }
    } else if (chunk.type === 'state' && sawSnapshot && !sawState && cursorValid(chunk.cursor)) sawState = true;
    else throw new Error('Invalid bounty stream order.');
  } });
  check();
  if (!sawSnapshot || !sawState || end?.records !== records.length || end?.chunks !== chunks) throw new Error('Incomplete bounty snapshot.');
  return records;
}

/** Stage the complete window, replay every journal page, then publish atomically. */
export async function discoverBounties({ rpc, network, lookback = 600, previous = new Map(), previousWindow = null, cursor = null, capabilities, check = () => {}, onInvalidate = () => {}, onWindow = () => {}, onReset = async () => {}, readBlock }) {
  if (!Number.isInteger(lookback) || lookback < 1 || lookback > 600) throw new Error('Invalid bounty lookback.');
  let cached = new Map(previous);
  // blockCounts is local snapshot metadata, explicitly copied from our prior
  // publication. Raw getrecentblockhashes extras never confer count authority.
  let knownWindow = previousWindow ? validatedWindow(previousWindow, network, previousWindow.blockCounts) : null;
  let cachedWindow = cursor ? knownWindow : null;
  let requestDeltas = true, requestBlocks = true, requestCompact = true, requestCounts = true;
  let requestCompactV2 = capabilities?.compactVersion !== 1;
  if (!cursor) { check(); await onReset({ reason: 'initial' }); check(); cached = new Map(); }
  for (let restart = 0; restart < 4; restart++) {
    check();
    const staged = new Map(cached), dirty = new Set(), deltaBlocks = new Map();
    const expectedCounts = new Map(Object.entries(cachedWindow?.blockCounts ?? {}));
    const budget = { count: 0, limit: MAX_ROWS };
    for (const [hash, rows] of staged) {
      if (expectedCounts.has(hash) && rows.length !== expectedCounts.get(hash)) throw new Error('Cached bounty block contradicts its immutable count.');
      budget.count += rows.length; if (budget.count > MAX_ROWS) throw new Error('Recent bounty data exceeds the wallet resource limit.');
    }
    let wanted = [], desired = new Set(), snapshot = cachedWindow, journalPages = 0, lastSequence = -1, readsSincePage = true;
    const pageBlocks = new WeakMap();
    const query = async (method, params = {}) => {
      check();
      if (method === 'getrecentblockhashes') readsSincePage = true;
      let value;
      try { value = await rpc.request(method, method === 'getrecentblockhashes' && requestCounts ? { ...params, include_bounty_counts: true } : params); }
      catch (error) {
        if (method !== 'getrecentblockhashes' || !requestCounts || error.code !== -32602) throw error;
        check(); requestCounts = false; value = await rpc.request(method, params);
      }
      check();
      if (method !== 'getbountychanges') {
        validateTip(value?.tip, network); rpcBlockCounts(value);
        if (value.bounty_counts === undefined) requestCounts = false;
      }
      return value;
    };
    const resetError = error => error instanceof RescanRequired || [-32004, -32011].includes(error.code);
    const readWindow = async (expectedTip, inline) => {
      if (!snapshot || !sameTip(snapshot.tip, expectedTip)) {
        snapshot = inline?.window ?? await refreshRecentWindow(query, snapshot ?? knownWindow, network);
        // A racing response may have a different tip, but the same hash must
        // never contradict the triggering journal/fence's header metadata.
        sameTip(expectedTip, snapshot.tip);
        knownWindow = snapshot;
      }
      wanted = windowFrom(snapshot, network, lookback); desired = new Set(wanted.map(block => block.hash));
      onWindow(snapshot);
      const canonical = new Map(snapshot.blocks.map(block => [block.height, block.hash]));
      const canonicalHashes = new Set(canonical.values());
      for (const hash of expectedCounts.keys()) if (!canonicalHashes.has(hash)) expectedCounts.delete(hash);
      for (const [hash, count] of Object.entries(snapshot.blockCounts ?? {})) {
        if (expectedCounts.has(hash) && expectedCounts.get(hash) !== count) throw new Error('Inconsistent immutable block count.');
        expectedCounts.set(hash, count);
      }
      const oldest = snapshot.blocks.at(-1).height;
      for (const [hash, rows] of staged) if (!desired.has(hash)) {
        for (const row of rows) {
          // Use the full API window, not just the selected lookback: a replaced
          // block at a known height is a reorg, never an ordinary aging event.
          const agedOut = row.block_height < oldest || canonical.get(row.block_height) === hash;
          onInvalidate(row, agedOut ? 'window_exit' : 'reorg');
        }
        budget.count -= rows.length; staged.delete(hash); dirty.delete(hash); deltaBlocks.delete(hash);
      }
      for (const [hash, count] of expectedCounts) if (desired.has(hash)) {
        if (staged.has(hash) && staged.get(hash).length !== count) throw new Error('Cached bounty block contradicts its immutable count.');
        if (count === 0) {
          if (dirty.has(hash)) throw new Error('Inconsistent empty bounty block.');
          // Only acknowledged all-output counts, from a coherent journal or
          // hash-window snapshot, authorize an empty complete cache entry.
          if (!staged.has(hash)) staged.set(hash, []);
        }
      }
    };
    const changes = async () => {
      check();
      if (journalPages >= MAX_JOURNAL_PAGES) throw new DiscoveryBudgetExceeded('Bounty journal work budget reached.');
      const from = cursor;
      const params = from ? { cursor: from } : {};
      let page, inline, base = requestDeltas && requestBlocks ? snapshot ?? knownWindow : null;
      const validatePage = value => {
        validateTip(value?.tip, network);
        if (!cursorValid(value.next_cursor) || typeof value.has_more !== 'boolean' || !Array.isArray(value.changes) || value.changes.length > 10000 ||
            (value.has_more && !value.changes.length) || (value.changes.length && value.next_cursor === from)) throw new Error('Invalid or excessive bounty journal response.');
        if (value.bounty_deltas !== undefined && value.bounty_deltas !== 1) throw new Error('Invalid bounty delta capability.');
        return validateBlockDelta(value, base, network);
      };
      for (;;) {
        const expanded = requestDeltas ? { ...params, include_bounties: true } : params;
        const compact = requestDeltas && requestCompact;
        const requestedVersion = compact && requestCompactV2 ? 2 : 1;
        const state = compact && base && from ? { tip: Object.freeze({ ...base.tip }), cursor: from } : null;
        if (state) state.digest = bountyStateDigest(state.tip, state.cursor);
        try {
          page = await query('getbountychanges', { ...expanded,
            ...(base ? { known_tip: { height: base.tip.height, hash: base.tip.hash } } : {}),
            ...(compact ? { compact: true } : {}), ...(compact && requestCompactV2 ? { compact_version: 2 } : {}), ...(state ? { known_state: state.digest } : {}) });
          const returnedVersion = page?.compact;
          page = normalizeCompactV2Page(page, { requestedVersion, state, base, network });
          if (page?.changes?.some?.(event => event?.type === 'resync_required')) throw new RescanRequired('Bounty journal requested a new snapshot.');
          const advertisedCompact = page?.compact !== undefined;
          // Unknown immutable rows permit an expanded replay, not forgiveness
          // of an invalid cursor/page/canonical block delta in this response.
          const acknowledgement = page?.unchanged === true;
          if (!acknowledgement) inline = validatePage(page);
          page = expandCompactPage(page, { requested: compact, state, base, staged, network, lastSequence, inline, expectedCounts, lookback });
          if (acknowledgement) inline = validatePage(page);
          if (compact && requestedVersion === 2 && returnedVersion === 1) {
            requestCompactV2 = false; if (capabilities) capabilities.compactVersion = 1;
          }
          if (!advertisedCompact) requestCompact = false;
          break;
        } catch (error) {
          // Replay the same cursor, before any event/cursor publication, when
          // a patch cannot bind to a locally validated immutable row.
          if (error instanceof UnknownBountyReference) { requestCompact = false; continue; }
          if (!requestDeltas || error.code !== -32602) throw error;
          // Negotiate one optional extension at a time, at this exact cursor.
          // Transport/backend failures are never compatibility signals.
          if (compact && requestCompactV2) { requestCompactV2 = false; if (capabilities) capabilities.compactVersion = 1; }
          else if (compact) requestCompact = false;
          else if (base) { requestBlocks = false; base = null; }
          else { requestDeltas = false; requestBlocks = false; }
        }
      }
      journalPages++;
      // A reset revokes the old catalog before any following hash request can
      // block on quota, timeout or hide the reset behind an unrelated failure.
      if (page.changes.some(event => event?.type === 'resync_required')) throw new RescanRequired('Bounty journal requested a new snapshot.');
      if (page.bounty_deltas === undefined) requestDeltas = false;
      if (base && page.block_deltas === undefined) requestBlocks = false;
      if (inline) pageBlocks.set(page, inline);
      cursor = page.next_cursor;
      // A complete page is itself an atomic tip+cursor fence. Hash/stream I/O
      // after this response revokes it until another page has been replayed.
      readsSincePage = false;
      return page;
    };
    const apply = async page => {
      // Expanded rows are checked against the current canonical window, while
      // their confirmations are checked against their original publication tip.
      if (!sameTip(snapshot.tip, page.tip)) await readWindow(page.tip, pageBlocks.get(page));
      const canonical = page.bounty_deltas === 1 ? new Map(snapshot.blocks.map(block => [block.height, block.hash])) : null;
      const heights = page.bounty_deltas === 1 ? new Map(snapshot.blocks.map(block => [block.hash, block.height])) : null;
      // Most pages are empty or already identify the affected block. Only
      // build the fallback index for an event that actually needs it, after
      // validating that event. Keep it page-local: block reloads/reorgs between
      // pages must never reuse an index of a former staged catalog.
      let outpoints;
      for (const event of page.changes) {
        if (event?.type === 'resync_required') throw new RescanRequired('Bounty journal requested a new snapshot.');
        if (!event || !['added','spent','pending_spend','available_again','matured','window_exit'].includes(event.type) || !uint(event.sequence, Number.MAX_SAFE_INTEGER) || event.sequence <= lastSequence || typeof event.txid !== 'string' || !HASH.test(event.txid) || !uint(event.vout) || (event.block_hash !== undefined && (typeof event.block_hash !== 'string' || !HASH.test(event.block_hash)))) throw new Error('Invalid bounty change event.');
        lastSequence = event.sequence;
        if (page.bounty_deltas === 1) {
          validateTip(event.tip, network);
          sameTip(event.tip, page.tip);
          if (event.tip.height > page.tip.height) throw new Error('Invalid bounty publication tip.');
          if (event.tip.height > snapshot.tip.height || (canonical.has(event.tip.height) && canonical.get(event.tip.height) !== event.tip.hash)) throw new RescanRequired('Bounty publication is no longer canonical.');
          if (event.spending_txid !== undefined && event.spending_txid !== null && (typeof event.spending_txid !== 'string' || !HASH.test(event.spending_txid))) throw new Error('Invalid bounty delta identity.');
          const row = event.bounty;
          if (event.type === 'window_exit') {
            if (row !== null) throw new Error('Invalid bounty window-exit delta.');
            if (event.block_hash === undefined && !outpoints) {
              outpoints = new Map();
              for (const [hash, rows] of staged) for (const cached of rows) outpoints.set(bountyKey(cached), hash);
            }
            const hash = event.block_hash ?? outpoints.get(bountyKey(event));
            if (desired.has(hash)) throw new RescanRequired('A bounty exited a retained canonical block.');
            onInvalidate(event, event.type);
            continue;
          }
          if (typeof row?.block_hash !== 'string' || !HASH.test(row.block_hash) ||
              (event.block_hash !== undefined && event.block_hash !== row.block_hash)) throw new Error('Invalid bounty delta identity.');
          validateBountyRow(row, event.tip, row.block_hash, heights.get(row.block_hash), true);
          if (expectedCounts.get(row.block_hash) === 0) throw new Error('Bounty delta contradicts an empty block.');
          if (row.txid !== event.txid || row.vout !== event.vout) throw new Error('Invalid bounty delta identity.');
          // A reorg racing the page/window request must rescan, rather than
          // applying rows from a displaced block or advancing past them.
          if (canonical.has(row.block_height) && canonical.get(row.block_height) !== row.block_hash) throw new RescanRequired('Bounty delta is no longer canonical.');
          if (desired.has(row.block_hash) && staged.has(row.block_hash) && !dirty.has(row.block_hash)) {
            let block = deltaBlocks.get(row.block_hash);
            if (!block) {
              const rows = staged.get(row.block_hash).slice(), positions = new Map();
              for (const [index, existing] of rows.entries()) {
                const key = bountyKey(existing);
                if (positions.has(key)) throw new Error('Duplicate bounty in cached block.');
                positions.set(key, index);
              }
              block = { rows, positions }; deltaBlocks.set(row.block_hash, block); staged.set(row.block_hash, rows);
            }
            const key = bountyKey(row), index = block.positions.get(key), existing = index === undefined ? undefined : block.rows[index];
            if (existing && IMMUTABLE_BOUNTY_FIELDS.some(field => existing[field] !== row[field])) throw new Error('Inconsistent immutable bounty metadata.');
            if (!existing) {
              if (expectedCounts.has(row.block_hash) && block.rows.length >= expectedCounts.get(row.block_hash)) throw new Error('Bounty delta exceeds its immutable block count.');
              if (budget.count >= MAX_ROWS) throw new Error('Recent bounty data exceeds the wallet resource limit; no partial snapshot was applied.');
              budget.count++; block.positions.set(key, block.rows.length); block.rows.push(structuredClone(row));
              outpoints?.set(key, row.block_hash);
            } else block.rows[index] = structuredClone(row);
          }
          // Event labels may describe an intermediate mutation in a coalesced
          // publication. Its final full row determines admission and status.
          if (row.status !== 'available') onInvalidate(row, row.status);
          continue;
        }
        if (event.block_hash === undefined && !outpoints) {
          outpoints = new Map();
          for (const [hash, rows] of staged) for (const row of rows) outpoints.set(bountyKey(row), hash);
        }
        const hash = event.block_hash ?? outpoints.get(bountyKey(event));
        if (hash && desired.has(hash) && event.type !== 'window_exit') dirty.add(hash);
        if (['spent','pending_spend','window_exit'].includes(event.type)) onInvalidate(event, event.type);
      }
    };
    const loadDirty = async () => {
      // The server lists newest first. Read the oldest required blocks first,
      // before new blocks can push them out of the recent window. Reverse only
      // the work queue; keep the validated window and journal order unchanged.
      const pending = wanted.filter(block => !staged.has(block.hash) || dirty.has(block.hash)).reverse();
      if (pending.length) readsSincePage = true;
      let position = 0, failure;
      const current = () => { check(); if (failure) throw failure; };
      const workers = Array.from({ length: Math.min(4, pending.length) }, async () => {
        while (position < pending.length) {
          current(); const block = pending[position++];
          const old = staged.get(block.hash);
          if (old) { budget.count -= old.length; staged.delete(block.hash); }
          try {
            // A sibling's busy/quota failure must not escape through this
            // stream's onChunk callback: the transport correctly treats
            // callback validation exceptions as malformed data. Finish every
            // already-started bounded stream with its full validation and the
            // real epoch/cancellation fence; stop new work/publication below.
            const rows = await readBlock(block.hash, { height: block.height, check, budget });
            if (expectedCounts.has(block.hash) && rows.length !== expectedCounts.get(block.hash)) throw new Error('Bounty stream contradicts its immutable block count.');
            current(); staged.set(block.hash, rows); dirty.delete(block.hash); deltaBlocks.delete(block.hash);
            for (const row of rows) if (row.status !== 'available') onInvalidate(row);
          } catch (error) { failure ??= error; throw error; }
        }
      });
      const results = await Promise.allSettled(workers);
      const failures = results.filter(result => result.status === 'rejected');
      // Do not let an earlier worker's retryable reply hide a genuine malformed
      // sibling or a contradictory complete count. This changes only which
      // existing failure is propagated; no parsing/stream check is relaxed.
      const deferred = error => error?.name === 'AbortError' || error instanceof RescanRequired ||
        ['RPC_QUEUE_FULL', -32001, -32002, -32004, -32011, -32029, -32030].includes(error?.code);
      const rejected = failures.find(result => !deferred(result.reason)) ?? failures[0];
      if (rejected) throw rejected.reason;
    };
    try {
      // Capture a watermark BEFORE streaming any blocks. Replay begins there,
      // not at the streams' final cursors, so changes during transfer cannot vanish.
      let page = await changes();
      await readWindow(page.tip, pageBlocks.get(page)); await apply(page);
      while (page.has_more) { page = await changes(); await apply(page); }
      for (let pass = 0; pass < 32; pass++) {
        await loadDirty();
        if (readsSincePage) do { page = await changes(); await apply(page); } while (page.has_more);
        if (dirty.size || readsSincePage) continue;
        // All pages and any intervening hash/block reads are covered by this
        // final page. Later server changes remain after its cursor for the next
        // cycle; a second empty poll/tip request adds no stronger atomicity.
        if (!sameTip(snapshot.tip, page.tip)) throw new RescanRequired('Bounty page and canonical window differ.');
        const tip = snapshot.tip;
        if (wanted.some(block => !staged.has(block.hash))) continue;
        check();
        const outpoints = new Set();
        for (const [hash, rows] of staged) {
          let updated;
          for (const [index, row] of rows.entries()) {
            const key = bountyKey(row);
            if (outpoints.has(key)) throw new Error('Duplicate bounty across the recent window.');
            outpoints.add(key);
            if (row.confirmations !== undefined && row.confirmations !== tip.height - row.block_height + 1) {
              const confirmations = tip.height - row.block_height + 1;
              if (!uint(confirmations) || confirmations === 0 || (row.status === 'available' && row.coinbase && confirmations < 100)) throw new RescanRequired('Bounty confirmations changed across a rollback.');
              updated ??= rows.slice(); updated[index] = { ...row, confirmations };
            }
          }
          if (updated) staged.set(hash, updated);
        }
        return { blocks: staged, cursor, tip, window: snapshot };
      }
      throw new DiscoveryBudgetExceeded('Bounty snapshot coherence work budget reached.');
    } catch (error) {
      if (!resetError(error)) throw error;
      check(); await onReset({ reason: error instanceof DiscoveryBudgetExceeded ? 'work-budget' : error.code === -32004 ? 'data-unavailable' : error.code === -32011 ? 'cursor-invalid' : 'journal-reset',
        ...([-32004, -32011].includes(error.code) ? { code: error.code } : {}) });
      // A reset invalidates all bounty state and the cursor, not block hashes.
      // Retain only the hash anchor, requiring a fresh prefix even for an ABA
      // reorg to the same tip, and reload every required bounty stream.
      check(); cached = new Map(); cachedWindow = null; cursor = null;
      if (knownWindow) knownWindow = validatedWindow(knownWindow, network);
    }
  }
  // Every exhausted attempt already closed admission through onReset. Preserve
  // its proofs/counters while the caller backs off; never publish partial state.
  throw new BountyDiscoveryBusy();
}
