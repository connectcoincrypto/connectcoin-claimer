import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { packageEntries, validateSymlinkTarget } from '../scripts/package-files.mjs';

test('relative POSIX symlink targets retain framework aliases and resolve inside the package', () => {
  assert.equal(validateSymlinkTarget('helpers/Python.framework/Versions/Current', '3.13'), 'helpers/Python.framework/Versions/3.13');
  assert.equal(validateSymlinkTarget('helpers/Python', 'Python.framework/Versions/3.13/Python'), 'helpers/Python.framework/Versions/3.13/Python');
  assert.equal(validateSymlinkTarget('helpers/Python.framework/Python', 'Versions/Current/Python'), 'helpers/Python.framework/Versions/Current/Python');
  assert.equal(validateSymlinkTarget('a folder/sub/alias', '../file with spaces'), 'a folder/file with spaces');
  assert.equal(validateSymlinkTarget('a/alias', '..'), '.');
  assert.equal(validateSymlinkTarget('alias', './file'), 'file');
});

test('symlink validation rejects lexical escapes, absolute paths and nonportable characters', () => {
  for (const target of ['', null, '../escape', 'a/../../escape', '/tmp/file', '//host/file', 'C:/file', 'a:b', 'a\\file', '\\server\\file', 'bad\0file', 'bad\nfile', 'bad\rfile']) {
    assert.throws(() => validateSymlinkTarget('alias', target), /symlink target|Symlink target/);
  }
  for (const name of ['', null, '../alias', '/alias', 'a//alias', 'a/./alias', 'a/../alias', 'C:/alias', 'a\\alias', 'bad\nname']) {
    assert.throws(() => validateSymlinkTarget(name, 'file'), /package path/);
  }
});

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'claimer-package-files-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

async function link(t, target, path, type = 'file') {
  try {
    await symlink(target, path, type);
    return true;
  } catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error.code)) {
      t.skip('This Windows account cannot create symlinks. Pure target validation still runs.');
      return false;
    }
    throw error;
  }
}

test('package enumeration is sorted and includes files, not directory entries', async (t) => {
  const directory = await fixture(t);
  await mkdir(join(directory, 'a folder'));
  await writeFile(join(directory, 'z.txt'), 'last');
  await writeFile(join(directory, 'a folder', 'b.txt'), 'first');
  assert.deepEqual(await packageEntries(directory), [
    { path: 'a folder/b.txt', type: 'file' },
    { path: 'z.txt', type: 'file' },
  ]);
});

test('package enumeration preserves file and directory links without traversing aliases', async (t) => {
  const directory = await fixture(t);
  await mkdir(join(directory, 'real'));
  await writeFile(join(directory, 'real', 'content'), 'file');
  await writeFile(join(directory, 'content'), 'file');
  if (!await link(t, 'content', join(directory, 'file-alias'))) return;
  if (!await link(t, 'real', join(directory, 'directory-alias'), 'dir')) return;
  assert.deepEqual(await packageEntries(directory, { allowSymlinks: true }), [
    { path: 'content', type: 'file' },
    { path: 'directory-alias', type: 'symlink', target: 'real' },
    { path: 'file-alias', type: 'symlink', target: 'content' },
    { path: 'real/content', type: 'file' },
  ]);
  await assert.rejects(packageEntries(directory), /symlinks are not allowed/);
});

test('package enumeration accepts an internal symlink chain and retains the exact target', async (t) => {
  const directory = await fixture(t);
  await writeFile(join(directory, 'content'), 'file');
  if (!await link(t, 'content', join(directory, 'b'))) return;
  if (!await link(t, 'b', join(directory, 'a'))) return;
  assert.deepEqual(await packageEntries(directory, { allowSymlinks: true }), [
    { path: 'a', type: 'symlink', target: 'b' },
    { path: 'b', type: 'symlink', target: 'content' },
    { path: 'content', type: 'file' },
  ]);
});

test('package enumeration rejects broken and cyclic symlink targets', async (t) => {
  const directory = await fixture(t);
  if (!await link(t, 'missing', join(directory, 'broken'))) return;
  await assert.rejects(packageEntries(directory, { allowSymlinks: true }), /missing, cyclic or inaccessible/);
  await rm(join(directory, 'broken'));
  if (!await link(t, 'b', join(directory, 'a'))) return;
  if (!await link(t, 'a', join(directory, 'b'))) return;
  await assert.rejects(packageEntries(directory, { allowSymlinks: true }), /missing, cyclic or inaccessible/);
});

test('package enumeration rejects targets that leave the root through another symlink', async (t) => {
  const directory = await fixture(t);
  const outside = await fixture(t);
  await writeFile(join(outside, 'content'), 'outside');
  if (!await link(t, outside, join(directory, 'z-escape'), 'dir')) return;
  if (!await link(t, 'z-escape', join(directory, 'a-alias'), 'dir')) return;
  await assert.rejects(packageEntries(directory, { allowSymlinks: true }), /escapes the package|Invalid relative POSIX/);
});
