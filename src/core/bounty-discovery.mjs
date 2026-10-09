import { validateTip } from './config.mjs';

const HASH = /^[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const MAX_ROWS = 100000;
export const bountyKey = row => `${row.txid}:${row.vout}`;
const uint = (value, maximum = 0xffffffff) => Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const cursorValid = value => typeof value === 'string' && value.length > 0 && value.length <= 4096;
class RescanRequired extends Error {}

function windowFrom(response, network, lookback) {
  validateTip(response?.tip, network);
  if (response.window !== 600 || !Array.isArray(response.blocks) || response.blocks.length !== Math.min(600, response.tip.height + 1)) throw new Error('RPC did not provide the complete recent-block window.');
  const hashes = new Set();
  for (const [index, block] of response.blocks.entries()) {
    if (!block || typeof block.hash !== 'string' || !HASH.test(block.hash) || block.height !== response.tip.height - index || hashes.has(block.hash) || (index === 0 && block.hash !== response.tip.hash)) throw new Error('Invalid recent-block sequence.');
    hashes.add(block.hash);
  }
  return response.blocks.slice(0, lookback);
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
export async function discoverBounties({ rpc, network, lookback = 600, previous = new Map(), cursor = null, check = () => {}, onInvalidate = () => {}, onWindow = () => {}, onReset = async () => {}, readBlock }) {
  if (!Number.isInteger(lookback) || lookback < 1 || lookback > 600) throw new Error('Invalid bounty lookback.');
  let cached = new Map(previous);
  for (let restart = 0; restart < 4; restart++) {
    check();
    if (!cursor) { await onReset(); check(); cached = new Map(); }
    const staged = new Map(cached), dirty = new Set();
    const budget = { count: 0, limit: MAX_ROWS };
    for (const rows of staged.values()) { budget.count += rows.length; if (budget.count > MAX_ROWS) throw new Error('Recent bounty data exceeds the wallet resource limit.'); }
    let wanted = [], desired = new Set(), snapshot, journalPages = 0, lastSequence = -1;
    const query = async (method, params = {}) => { check(); const value = await rpc.request(method, params); check(); validateTip(value?.tip, network); return value; };
    const resetError = error => error instanceof RescanRequired || [-32004, -32011].includes(error.code);
    const readWindow = async () => {
      snapshot = await query('getrecentblockhashes');
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
      const outpoints = new Map();
      for (const [hash, rows] of staged) for (const row of rows) outpoints.set(bountyKey(row), hash);
      for (const event of page.changes) {
        if (event?.type === 'resync_required') throw new RescanRequired('Bounty journal requested a new snapshot.');
        if (!event || !['added','spent','pending_spend','available_again','matured','window_exit'].includes(event.type) || !uint(event.sequence, Number.MAX_SAFE_INTEGER) || event.sequence <= lastSequence || typeof event.txid !== 'string' || !HASH.test(event.txid) || !uint(event.vout) || (event.block_hash !== undefined && !HASH.test(event.block_hash))) throw new Error('Invalid bounty change event.');
        lastSequence = event.sequence;
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
      await readWindow(); apply(page);
      while (page.has_more) { page = await changes(); apply(page); }
      for (let pass = 0; pass < 32; pass++) {
        await loadDirty();
        do { page = await changes(); apply(page); } while (page.has_more);
        if (dirty.size) continue;
        const before = snapshot.tip.hash;
        await readWindow();
        if (snapshot.tip.hash !== before || wanted.some(block => !staged.has(block.hash))) continue;
        check();
        const outpoints = new Set();
        for (const rows of staged.values()) for (const row of rows) {
          const key = bountyKey(row);
          if (outpoints.has(key)) throw new Error('Duplicate bounty across the recent window.');
          outpoints.add(key);
        }
        return { blocks: staged, cursor, tip: snapshot.tip };
      }
      throw new Error('The bounty window is changing too quickly. Retry discovery shortly.');
    } catch (error) {
      if (!resetError(error)) throw error;
      check(); await onReset(); check(); cached = new Map(); cursor = null;
    }
  }
  throw new Error('The bounty snapshot could not remain coherent; Automatic Claims was stopped.');
}
