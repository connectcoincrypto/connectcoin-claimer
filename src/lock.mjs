import { open, readFile, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

// A crash leaves the lock for explicit operator review, not an unsafe auto-unlock.
export async function acquireLock(path) {
  const token = `${process.pid}:${randomUUID()}\n`;
  let file;
  try { file = await open(path, 'wx', 0o600); }
  catch (error) {
    if (error.code === 'EEXIST') throw new Error(`Another instance or an unclean shutdown left ${path}. Stop other instances and review the state journal before manually removing this lock.`);
    throw error;
  }
  try { await file.writeFile(token); await file.sync(); }
  catch (error) { await file.close(); await unlink(path).catch(() => {}); throw error; }
  await file.close();
  return async () => { if (await readFile(path, 'utf8').catch(() => '') === token) await unlink(path); };
}
