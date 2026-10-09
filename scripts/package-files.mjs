import { readdir, readlink, realpath, stat } from 'node:fs/promises';
import { isAbsolute, join, posix, relative, resolve, sep } from 'node:path';

function packagePath(value) {
  if (typeof value !== 'string' || !value || /[\\:\x00-\x1f\x7f]/.test(value)
      || posix.isAbsolute(value) || value.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error(`Invalid relative package path: ${JSON.stringify(value)}`);
  }
}

/** Validate a portable relative POSIX link, returning its normalized package-relative destination. */
export function validateSymlinkTarget(relativePath, target) {
  packagePath(relativePath);
  if (typeof target !== 'string' || !target || /[\\:\x00-\x1f\x7f]/.test(target) || posix.isAbsolute(target)) {
    throw new Error(`Invalid relative POSIX symlink target for ${relativePath}: ${JSON.stringify(target)}`);
  }
  const destination = posix.normalize(posix.join(posix.dirname(relativePath), target));
  if (destination === '..' || destination.startsWith('../') || posix.isAbsolute(destination)) {
    throw new Error(`Symlink target escapes the package: ${relativePath} -> ${target}`);
  }
  return destination;
}

function inside(root, candidate) {
  const path = relative(root, candidate);
  return !isAbsolute(path) && path !== '..' && !path.startsWith(`..${sep}`);
}

/**
 * Enumerate regular files and, optionally, confined relative symlinks.
 * Never walk symlinked directories: aliases remain single manifest entries.
 * Both lexical and filesystem-resolved targets must stay within the package.
 */
export async function packageEntries(directory, { allowSymlinks = false } = {}) {
  const root = await realpath(resolve(directory));
  const entries = [];
  async function visit(path, prefix = '') {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      packagePath(name);
      const child = join(path, entry.name);
      if (entry.isDirectory()) {
        await visit(child, name);
      } else if (entry.isFile()) {
        entries.push({ path: name, type: 'file' });
      } else if (entry.isSymbolicLink()) {
        if (!allowSymlinks) throw new Error(`Package symlinks are not allowed: ${name}`);
        const target = await readlink(child);
        const destination = validateSymlinkTarget(name, target);
        if (!inside(root, resolve(root, ...destination.split('/')))) {
          throw new Error(`Symlink target escapes the package: ${name} -> ${target}`);
        }
        let resolved;
        try {
          resolved = await realpath(child);
        } catch (error) {
          throw new Error(`Symlink target is missing, cyclic or inaccessible: ${name} -> ${target}`, { cause: error });
        }
        if (!inside(root, resolved)) throw new Error(`Resolved symlink target escapes the package: ${name} -> ${target}`);
        const targetStat = await stat(resolved);
        if (!targetStat.isFile() && !targetStat.isDirectory()) {
          throw new Error(`Symlink points to an unsupported special entry: ${name} -> ${target}`);
        }
        entries.push({ path: name, type: 'symlink', target });
      } else {
        throw new Error(`Unsupported special package entry: ${name}`);
      }
    }
  }
  await visit(root);
  return entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
