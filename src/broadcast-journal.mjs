import { open, rename, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_RECORDS = 20000;
const HASH = /^[0-9a-f]{64}$/;
const OUTPOINT = /^[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})$/;
const validOutpoint = value => typeof value === 'string' && OUTPOINT.test(value) && Number(value.slice(65)) <= 0xffffffff;

/** Public outpoints and transaction IDs only. A pending write is durable before broadcast. */
export class BroadcastJournal {
  constructor(path) {
    this.path = path;
    this.records = new Map();
    this.loaded = false;
    this.writing = Promise.resolve();
  }

  async load() {
    let handle;
    try {
      handle = await open(this.path, 'r');
      const info = await handle.stat();
      if (!info.isFile() || info.size > MAX_BYTES) throw new Error('Claim broadcast state is not a bounded regular file.');
      const buffer = Buffer.alloc(MAX_BYTES + 1);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead > MAX_BYTES) throw new Error('Claim broadcast state exceeds its size limit.');
      const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytesRead)));
      if (!data || data.version !== 1 || Object.keys(data).some(key => !['version', 'records'].includes(key)) ||
          !Array.isArray(data.records) || data.records.length > MAX_RECORDS) throw new Error('Invalid claim broadcast state.');
      const records = new Map();
      for (const row of data.records) {
        if (!row || Object.keys(row).some(key => !['outpoint', 'txid', 'receivingAddress', 'status', 'updatedAt'].includes(key)) ||
            !validOutpoint(row.outpoint) || !HASH.test(row.txid) || records.has(row.outpoint) ||
            typeof row.receivingAddress !== 'string' || !/^[a-zA-Z0-9]{8,90}$/.test(row.receivingAddress) ||
            !['pending', 'accepted', 'unknown'].includes(row.status) ||
            !Number.isSafeInteger(row.updatedAt) || row.updatedAt < 0) throw new Error('Invalid claim broadcast record.');
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
    return this.entries();
  }

  entries() { return [...this.records.values()].map(row => ({ ...row })); }
  unresolved() { return this.entries().filter(row => row.status !== 'accepted'); }

  update(outpoint, fields) {
    const operation = this.writing.then(async () => {
      if (!this.loaded) throw new Error('Claim broadcast state has not been loaded.');
      if (!validOutpoint(outpoint)) throw new Error('Invalid broadcast outpoint.');
      const next = new Map(this.records);
      if (fields === null) next.delete(outpoint);
      else {
        if (!HASH.test(fields.txid) || !['pending', 'accepted', 'unknown'].includes(fields.status) ||
            typeof fields.receivingAddress !== 'string' || !/^[a-zA-Z0-9]{8,90}$/.test(fields.receivingAddress)) {
          throw new Error('Invalid broadcast record.');
        }
        next.set(outpoint, Object.freeze({ outpoint, txid: fields.txid, receivingAddress: fields.receivingAddress,
          status: fields.status, updatedAt: Date.now() }));
      }
      const data = JSON.stringify({ version: 1, records: [...next.values()] }, null, 2) + '\n';
      if (next.size > MAX_RECORDS || Buffer.byteLength(data) > MAX_BYTES) throw new Error('Claim broadcast state is full; review the saved state before continuing.');
      const temporary = join(dirname(this.path), `.claimer-state-${randomBytes(12).toString('hex')}.tmp`);
      let handle;
      try {
        handle = await open(temporary, 'wx', 0o600);
        await handle.writeFile(data);
        await handle.sync();
        await handle.close(); handle = null;
        await rename(temporary, this.path);
        // POSIX requires the containing directory to be flushed as well as the
        // file. Node cannot open Windows directories for fsync; there the file
        // handle is flushed before the same-volume atomic replacement.
        if (process.platform !== 'win32') {
          const directory = await open(dirname(this.path), 'r');
          try { await directory.sync(); } finally { await directory.close(); }
        }
        this.records = next;
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
