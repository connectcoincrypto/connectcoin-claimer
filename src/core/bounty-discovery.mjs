import { validateTip } from './config.mjs';

const HASH = /^[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const MAX_ROWS = 100000;
export const bountyKey = row => `${row.txid}:${row.vout}`;
const uint = (value, maximum = 0xffffffff) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const cursorValid = value => typeof value === 'string' && value.length > 0 && value.length <= 4096;
class RescanRequired extends Error {}

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

function windowFrom(response, network, lookback) {
  validateRecentBlocks(response, network, 600);
  return response.blocks.slice(0, lookback);
}

function validatedWindow(response, network) {
  windowFrom(response, network, 600);
  // Only publish a complete, privately owned immutable snapshot. Callers must
  // retain it together with the processed journal cursor, never a partial read.
  return Object.freeze({ window: 600, tip: Object.freeze({ ...response.tip }),
    blocks: Object.freeze(response.blocks.map(({ height, hash }) => Object.freeze({ height, hash }))) });
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
  if (response.blocks.length === size) return validatedWindow(response, network);
  if (anchor < 0) return null;
  const anchorHeight = response.blocks[anchor].height;
  const blocks = [...response.blocks.slice(0, anchor), ...known.blocks.filter(block => block.height <= anchorHeight)].slice(0, size);
  // A rollback can find an anchor while still lacking the oldest required
  // blocks. Escalate rather than silently publishing an incomplete window.
  if (blocks.length !== size) return null;
  return validatedWindow({ window: 600, tip: response.tip, blocks }, network);
}

async function refreshRecentWindow(query, known, network) {
  if (!known) return validatedWindow(await query('getrecentblockhashes'), network);
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
        if (!row || typeof row.txid !== 'string' || !HASH.test(row.txid) || row.block_hash !== hash || !uint(row.vout) || !uint(row.block_height) || (height !== undefined && row.block_height !== height) || row.block_height > chunk.tip.height || typeof row.amount !== 'string' || !/^\d{1,19}$/.test(row.amount) || BigInt(row.amount) > 1000000000000000000n || typeof row.connection_work_target !== 'string' || !HASH.test(row.connection_work_target) || typeof row.domain !== 'string' || !DOMAIN.test(row.domain) || row.domain.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || !uint(row.root_certificates_version) || row.root_certificates_version === 0 || !uint(row.signature_algorithms_mask, 7) || row.signature_algorithms_mask === 0 || typeof row.coinbase !== 'boolean' || !uint(row.confirmations) || row.confirmations !== chunk.tip.height - row.block_height + 1 || !['available','spent','pending_spend','immature'].includes(row.status) || (row.spending_txid !== null && (typeof row.spending_txid !== 'string' || !HASH.test(row.spending_txid))) || (row.status === 'available' && row.coinbase && row.confirmations < 100)) throw new Error('Invalid bounty metadata.');
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
export async function discoverBounties({ rpc, network, lookback = 600, previous = new Map(), previousWindow = null, cursor = null, check = () => {}, onInvalidate = () => {}, onWindow = () => {}, onReset = async () => {}, readBlock }) {
  if (!Number.isInteger(lookback) || lookback < 1 || lookback > 600) throw new Error('Invalid bounty lookback.');
  let cached = new Map(previous);
  let knownWindow = previousWindow ? validatedWindow(previousWindow, network) : null;
  let cachedWindow = cursor ? knownWindow : null;
  if (!cursor) { check(); await onReset({ reason: 'initial' }); check(); cached = new Map(); }
  for (let restart = 0; restart < 4; restart++) {
    check();
    const staged = new Map(cached), dirty = new Set();
    const budget = { count: 0, limit: MAX_ROWS };
    for (const rows of staged.values()) { budget.count += rows.length; if (budget.count > MAX_ROWS) throw new Error('Recent bounty data exceeds the wallet resource limit.'); }
    let wanted = [], desired = new Set(), snapshot = cachedWindow, journalPages = 0, lastSequence = -1;
    const query = async (method, params = {}) => { check(); const value = await rpc.request(method, params); check(); validateTip(value?.tip, network); return value; };
    const currentTip = async () => { check(); const value = await rpc.request('getchaintip'); check(); return validateTip(value, network); };
    const resetError = error => error instanceof RescanRequired || [-32004, -32011].includes(error.code);
    const readWindow = async expectedTip => {
      if (!snapshot || !sameTip(snapshot.tip, expectedTip)) {
        snapshot = await refreshRecentWindow(query, snapshot ?? knownWindow, network);
        // A racing response may have a different tip, but the same hash must
        // never contradict the triggering journal/fence's header metadata.
        sameTip(expectedTip, snapshot.tip);
        knownWindow = snapshot;
      }
      wanted = windowFrom(snapshot, network, lookback); desired = new Set(wanted.map(block => block.hash));
      onWindow(snapshot);
      const canonical = new Map(snapshot.blocks.map(block => [block.height, block.hash]));
      const oldest = snapshot.blocks.at(-1).height;
      for (const [hash, rows] of staged) if (!desired.has(hash)) {
        for (const row of rows) {
          // Use the full API window, not just the selected lookback: a replaced
          // block at a known height is a reorg, never an ordinary aging event.
          const agedOut = row.block_height < oldest || canonical.get(row.block_height) === hash;
          onInvalidate(row, agedOut ? 'window_exit' : 'reorg');
        }
        budget.count -= rows.length; staged.delete(hash); dirty.delete(hash);
      }
    };
    const changes = async () => {
      const from = cursor;
      const page = await query('getbountychanges', from ? { cursor: from } : {});
      if (++journalPages > 100 || !cursorValid(page.next_cursor) || typeof page.has_more !== 'boolean' || !Array.isArray(page.changes) || page.changes.length > 10000 || (page.has_more && !page.changes.length) || (page.changes.length && page.next_cursor === from)) throw new Error('Invalid or excessive bounty journal response.');
      cursor = page.next_cursor;
      return page;
    };
    const apply = page => {
      // Most pages are empty or already identify the affected block. Only
      // build the fallback index for an event that actually needs it, after
      // validating that event. Keep it page-local: block reloads/reorgs between
      // pages must never reuse an index of a former staged catalog.
      let outpoints;
      for (const event of page.changes) {
        if (event?.type === 'resync_required') throw new RescanRequired('Bounty journal requested a new snapshot.');
        if (!event || !['added','spent','pending_spend','available_again','matured','window_exit'].includes(event.type) || !uint(event.sequence, Number.MAX_SAFE_INTEGER) || event.sequence <= lastSequence || typeof event.txid !== 'string' || !HASH.test(event.txid) || !uint(event.vout) || (event.block_hash !== undefined && !HASH.test(event.block_hash))) throw new Error('Invalid bounty change event.');
        lastSequence = event.sequence;
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
      let position = 0, failure;
      const current = () => { check(); if (failure) throw failure; };
      const workers = Array.from({ length: Math.min(4, pending.length) }, async () => {
        while (position < pending.length) {
          current(); const block = pending[position++];
          const old = staged.get(block.hash);
          if (old) { budget.count -= old.length; staged.delete(block.hash); }
          try {
            const rows = await readBlock(block.hash, { height: block.height, check: current, budget });
            current(); staged.set(block.hash, rows); dirty.delete(block.hash);
            for (const row of rows) if (row.status !== 'available') onInvalidate(row);
          } catch (error) { failure ??= error; throw error; }
        }
      });
      const results = await Promise.allSettled(workers);
      const rejected = results.find(result => result.status === 'rejected');
      if (rejected) throw rejected.reason;
    };
    try {
      // Capture a watermark BEFORE streaming any blocks. Replay begins there,
      // not at the streams' final cursors, so changes during transfer cannot vanish.
      let page = await changes();
      await readWindow(page.tip); apply(page);
      while (page.has_more) { page = await changes(); apply(page); }
      for (let pass = 0; pass < 32; pass++) {
        await loadDirty();
        do { page = await changes(); apply(page); } while (page.has_more);
        if (dirty.size) continue;
        // Mempool changes are replayed even when the chain tip stays unchanged.
        // The final lightweight tip fence also catches a block/reorg arriving
        // AFTER that replay. A changed tip refreshes the canonical window by
        // anchoring a small prefix, escalating only when necessary.
        const tip = await currentTip();
        if (!sameTip(snapshot.tip, tip)) { await readWindow(tip); continue; }
        if (wanted.some(block => !staged.has(block.hash))) continue;
        check();
        const outpoints = new Set();
        for (const rows of staged.values()) for (const row of rows) {
          const key = bountyKey(row);
          if (outpoints.has(key)) throw new Error('Duplicate bounty across the recent window.');
          outpoints.add(key);
        }
        return { blocks: staged, cursor, tip, window: snapshot };
      }
      throw new Error('The bounty window is changing too quickly. Retry discovery shortly.');
    } catch (error) {
      if (!resetError(error)) throw error;
      check(); await onReset({ reason: error.code === -32004 ? 'data-unavailable' : error.code === -32011 ? 'cursor-invalid' : 'journal-reset',
        ...([-32004, -32011].includes(error.code) ? { code: error.code } : {}) });
      // A reset invalidates all bounty state and the cursor, not block hashes.
      // Retain only the hash anchor, requiring a fresh prefix even for an ABA
      // reorg to the same tip, and reload every required bounty stream.
      check(); cached = new Map(); cachedWindow = null; cursor = null;
    }
  }
  throw new Error('The bounty snapshot could not remain coherent; Automatic Claims was stopped.');
}
