import { open, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_RECORDS = 20000;
export const MAX_REPLAY_HEX = 132000;
export const transactionDigest = hex => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');
const HASH = /^[0-9a-f]{64}$/;
const OUTPOINT = /^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/;
const validOutpoint = value => typeof value === 'string' && OUTPOINT.test(value) && Number(value.slice(65)) <= 0xffffffff;

function replayFields(row) {
  if (row.transactionHex === undefined && row.transactionHash === undefined) return {};
  if (row.status === 'confirmed' || typeof row.transactionHex !== 'string' || row.transactionHex.length < 20 ||
      row.transactionHex.length > MAX_REPLAY_HEX || row.transactionHex.length % 2 || !/^[0-9a-f]+$/.test(row.transactionHex) ||
      typeof row.transactionHash !== 'string' || !HASH.test(row.transactionHash) || transactionDigest(row.transactionHex) !== row.transactionHash) {
    throw new Error('Invalid saved claim transaction bytes.');
  }
  return { transactionHex: row.transactionHex, transactionHash: row.transactionHash };
}

function confirmationFields(row) {
  if (row.status !== 'confirmed') {
    if (row.blockHash !== undefined || row.blockHeight !== undefined) throw new Error('Unexpected claim confirmation.');
    return {};
  }
  if (typeof row.blockHash !== 'string' || !HASH.test(row.blockHash) || !Number.isSafeInteger(row.blockHeight) || row.blockHeight < 0) {
    throw new Error('Invalid claim confirmation.');
  }
  return { blockHash: row.blockHash, blockHeight: row.blockHeight };
}

/** ACKs retain exact public witnesses; only validated block confirmations compact them. */
export class BroadcastJournal {
  constructor(path) {
    this.path = path;
    this.records = new Map();
    this.loaded = false;
    this.writing = Promise.resolve();
    this.serializedBytes = 0;
  }

  async load() {
    let handle;
    try {
      handle = await open(this.path, 'r');
      const info = await handle.stat();
      if (!info.isFile() || info.size > MAX_BYTES) throw new Error('Claim broadcast state is not a bounded regular file.');
      const buffer = Buffer.alloc(MAX_BYTES + 1);
      // A regular-file read may return fewer bytes than requested without
      // reaching EOF. Validate the entire bounded file, never a JSON prefix;
      // the extra byte also detects growth beyond the earlier stat result.
      let bytesRead = 0;
      while (bytesRead < buffer.length) {
        const chunk = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
        if (chunk.bytesRead === 0) break;
        bytesRead += chunk.bytesRead;
      }
      if (bytesRead > MAX_BYTES) throw new Error('Claim broadcast state exceeds its size limit.');
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytesRead)));
      if (!data || ![1, 2, 3].includes(data.version) || Object.keys(data).some(key => !['version', 'records'].includes(key)) ||
          !Array.isArray(data.records) || data.records.length > MAX_RECORDS) throw new Error('Invalid claim broadcast state.');
      const records = new Map();
      for (const row of data.records) {
        const allowed = ['outpoint', 'txid', 'receivingAddress', 'status', 'updatedAt', ...(data.version >= 2 ? ['transactionHex', 'transactionHash'] : []),
          ...(data.version === 3 ? ['blockHash', 'blockHeight'] : [])];
        if (!row || Object.keys(row).some(key => !allowed.includes(key)) ||
            !validOutpoint(row.outpoint) || typeof row.txid !== 'string' || !HASH.test(row.txid) || records.has(row.outpoint) ||
            typeof row.receivingAddress !== 'string' || !/^[a-zA-Z0-9]{8,90}$/.test(row.receivingAddress) ||
            !['pending', 'accepted', 'unknown', ...(data.version === 3 ? ['confirmed'] : [])].includes(row.status) ||
            !Number.isSafeInteger(row.updatedAt) || row.updatedAt < 0) throw new Error('Invalid claim broadcast record.');
        if (data.version < 3 && row.status === 'accepted' && row.transactionHex !== undefined) throw new Error('Invalid legacy accepted record.');
        replayFields(row); confirmationFields(row);
        records.set(row.outpoint, Object.freeze({ ...row }));
      }
      this.records = records;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      this.records = new Map();
    } finally {
      await handle?.close();
    }
    this.loaded = true;
    this.serializedBytes = Buffer.byteLength(JSON.stringify({ version: 3, records: [...this.records.values()] }, null, 2) + '\n');
    return this.entries();
  }

  entries() { return [...this.records.values()].map(row => ({ ...row })); }
  unresolved() { return this.entries().filter(row => row.status === 'pending' || row.status === 'unknown'); }
  awaitingConfirmation() { return this.entries().filter(row => row.status === 'accepted'); }

  canRetainAdditionalProofs(count) {
    // Reserve the largest legal witness BEFORE starting captures, including
    // in-flight preparations. Keep room for metadata/status transitions too.
    // Running out of capacity must pause admission, never evict a saved winner.
    return this.loaded && Number.isSafeInteger(count) && count >= 0 &&
      this.records.size + count <= MAX_RECORDS &&
      this.serializedBytes + this.records.size * 128 + count * (MAX_REPLAY_HEX + 1024) <= MAX_BYTES;
  }

  update(outpoint, fields, { check = () => {} } = {}) {
    const operation = this.writing.then(async () => {
      check();
      if (!this.loaded) throw new Error('Claim broadcast state has not been loaded.');
      if (!validOutpoint(outpoint)) throw new Error('Invalid broadcast outpoint.');
      const next = new Map(this.records);
      if (fields === null) next.delete(outpoint);
      else {
        if (typeof fields.txid !== 'string' || !HASH.test(fields.txid) || !['pending', 'accepted', 'unknown', 'confirmed'].includes(fields.status) ||
            typeof fields.receivingAddress !== 'string' || !/^[a-zA-Z0-9]{8,90}$/.test(fields.receivingAddress)) {
          throw new Error('Invalid broadcast record.');
        }
        const previous = next.get(outpoint);
        if (previous && (previous.txid !== fields.txid || previous.receivingAddress !== fields.receivingAddress)) {
          throw new Error('A reserved claim cannot be replaced by another transaction or recipient.');
        }
        const replay = fields.status === 'confirmed' ? {} : replayFields({ ...fields,
          transactionHex: fields.transactionHex ?? previous?.transactionHex,
          transactionHash: fields.transactionHash ?? previous?.transactionHash });
        if (previous?.transactionHash && replay.transactionHash && previous.transactionHash !== replay.transactionHash) {
          throw new Error('A saved claim witness cannot be replaced.');
        }
        if (previous?.status === 'accepted' && !['accepted', 'confirmed'].includes(fields.status)) throw new Error('An accepted claim cannot become pending.');
        if (previous?.status === 'confirmed' && fields.status !== 'confirmed') throw new Error('A confirmed claim cannot become pending.');
        next.set(outpoint, Object.freeze({ outpoint, txid: fields.txid, receivingAddress: fields.receivingAddress, ...replay,
          ...confirmationFields(fields), status: fields.status, updatedAt: Date.now() }));
      }
      const data = JSON.stringify({ version: 3, records: [...next.values()] }, null, 2) + '\n';
      if (next.size > MAX_RECORDS || Buffer.byteLength(data) > MAX_BYTES) throw new Error('Claim broadcast state is full; review the saved state before continuing.');
      const temporary = join(dirname(this.path), `.claimer-state-${randomBytes(12).toString('hex')}.tmp`);
      let handle;
      try {
        handle = await open(temporary, 'wx', 0o600);
        await handle.writeFile(data);
        await handle.sync();
        await handle.close(); handle = null;
        // Confirmation may have waited behind other durable writes. Recheck
        // its canonical-read fence before the atomic replacement discards the
        // old witness; failures leave both memory and the on-disk file intact.
        check();
        await rename(temporary, this.path);
        // Replacement is now visible even if flushing/closing its directory
        // fails. Keep queued writers on that published state: using the old
        // map could erase a new proof or downgrade an accepted receipt. The
        // durability error still rejects this operation; it is not an ACK.
        this.records = next;
        this.serializedBytes = Buffer.byteLength(data);
        // POSIX requires the containing directory to be flushed as well as the
        // file. Node cannot open Windows directories for fsync; there the file
        // handle is flushed before the same-volume atomic replacement.
        if (process.platform !== 'win32') {
          const directory = await open(dirname(this.path), 'r');
          try { await directory.sync(); } finally { await directory.close(); }
        }
      } finally {
        await handle?.close().catch(() => {});
        await unlink(temporary).catch(() => {});
      }
    });
    this.writing = operation.catch(() => {});
    return operation;
  }

  async flush() { await this.writing; }
}
