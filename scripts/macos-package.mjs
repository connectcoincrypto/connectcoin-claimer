import { execFile } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { posix, resolve } from 'node:path';
import { promisify } from 'node:util';
import { packageEntries } from './package-files.mjs';

const execute = promisify(execFile);
const dylibCommands = new Set(['LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB', 'LC_LOAD_UPWARD_DYLIB', 'LC_LAZY_LOAD_DYLIB']);

export function isMachO(bytes) {
  if (bytes.length < 4) return false;
  const magic = bytes.readUInt32BE(0);
  if ([0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe].includes(magic)) return true;
  // CAFEBABE also starts Java classes. A Mach-O fat header has a small,
  // nonzero architecture count, not a Java minor/major version pair.
  if (bytes.length < 8) return false;
  const little = magic === 0xbebafeca || magic === 0xbfbafeca;
  if (!little && magic !== 0xcafebabe && magic !== 0xcafebabf) return false;
  const count = little ? bytes.readUInt32LE(4) : bytes.readUInt32BE(4);
  return count > 0 && count <= 16;
}

export function assertMacOSArchitecture(output, arch) {
  const target = { x64: 'x86_64', arm64: 'arm64' }[arch];
  if (!target) throw new Error(`Unsupported macOS target architecture: ${arch}`);
  const architectures = output.trim().split(/\s+/);
  if (!architectures.length || architectures.some((item) => !/^[A-Za-z0-9_]+$/.test(item)) || !architectures.includes(target)) {
    throw new Error(`Mach-O does not contain the required ${target} architecture: ${output.trim()}`);
  }
  return target;
}

export function parseMachOLoadCommands(output) {
  const result = { dependencies: [], rpaths: [], id: null };
  const blocks = output.split(/^Load command \d+\s*$/m).slice(1);
  if (!blocks.length) throw new Error('Unrecognized otool load-command output.');
  for (const block of blocks) {
    const command = /^\s*cmd (LC_[A-Z0-9_]+)\s*$/m.exec(block)?.[1];
    if (!command) throw new Error('Missing Mach-O load command.');
    if (command === 'LC_RPATH' || command === 'LC_ID_DYLIB' || dylibCommands.has(command)) {
      const field = command === 'LC_RPATH' ? 'path' : 'name';
      const value = new RegExp(`^\\s*${field} (.+) \\(offset [0-9]+\\)\\s*$`, 'm').exec(block)?.[1];
      if (!value || /[\0\r\n]/.test(value)) throw new Error(`Missing path for ${command}.`);
      if (command === 'LC_RPATH') result.rpaths.push(value);
      else if (command === 'LC_ID_DYLIB') {
        if (result.id !== null) throw new Error('Duplicate Mach-O install name.');
        result.id = value;
      } else result.dependencies.push(value);
    } else if (command.endsWith('_DYLIB')) {
      throw new Error(`Unsupported Mach-O dependency command: ${command}`);
    }
  }
  return result;
}

function within(root, path) {
  return path === root || path.startsWith(`${root}/`);
}

function systemLibrary(path) {
  // These libraries may live only in Apple's dyld shared cache; checking
  // their existence as regular files would reject valid modern macOS builds.
  return path.startsWith('/usr/lib/') || path.startsWith('/System/Library/');
}

function expandAnchor(value, binaryPath, executablePath) {
  for (const [anchor, directory] of [['@loader_path', posix.dirname(binaryPath)], ['@executable_path', posix.dirname(executablePath)]]) {
    if (value === anchor) return directory;
    if (value.startsWith(`${anchor}/`)) return posix.resolve(directory, value.slice(anchor.length + 1));
  }
  return null;
}

export function resolveMachODependency(dependency, { binaryPath, executablePath, rpaths, packageRoot, availablePaths, resolvePath = (path) => path }) {
  const root = posix.normalize(packageRoot);
  for (const path of [root, binaryPath, executablePath]) {
    if (!posix.isAbsolute(path) || /[\0\r\n]/.test(path)) throw new Error('Mach-O audit requires absolute POSIX paths.');
  }
  if (!within(root, binaryPath) || !within(root, executablePath)) throw new Error('Mach-O binary/executable must be inside the package.');
  if (typeof dependency !== 'string' || !dependency || /[\0\r\n]/.test(dependency)) throw new Error('Invalid Mach-O dependency path.');
  if (dependency.startsWith('/')) {
    const normalized = posix.normalize(dependency);
    if (systemLibrary(normalized)) return { system: true, path: normalized };
    // Even an absolute path into today's staging folder will break when the
    // downloaded ZIP is relocated, so it is not a portable dependency.
    throw new Error(`Non-portable absolute library dependency: ${dependency}`);
  }
  let candidates;
  if (dependency.startsWith('@rpath/')) {
    const suffix = dependency.slice('@rpath/'.length);
    candidates = rpaths.map((path) => {
      const anchored = expandAnchor(path, binaryPath, executablePath);
      if (anchored !== null) {
        if (!within(root, anchored)) throw new Error(`RPATH escapes the package: ${path}`);
        return { path: posix.resolve(anchored, suffix), system: false };
      }
      if (posix.isAbsolute(path) && systemLibrary(`${posix.normalize(path)}/`)) return { path: posix.resolve(path, suffix), system: true };
      throw new Error(`Non-portable or unsupported RPATH: ${path}`);
    });
  } else {
    const anchored = expandAnchor(dependency, binaryPath, executablePath);
    if (anchored === null) throw new Error(`Unsupported relative library dependency: ${dependency}`);
    candidates = [{ path: anchored, system: false }];
  }
  for (const { path, system } of candidates) {
    if (system && systemLibrary(path)) return { system: true, path };
    if (!within(root, path)) throw new Error(`Library dependency escapes the package: ${dependency}`);
    // Frameworks use both file aliases (Python -> Versions/Current/Python)
    // and directory aliases (Current -> 3.13). Resolve only this candidate;
    // never recurse through linked directories while enumerating the package.
    const canonical = resolvePath(path);
    if (canonical === null) continue;
    if (typeof canonical !== 'string' || !within(root, canonical)) throw new Error(`Resolved library dependency escapes the package: ${dependency}`);
    if (availablePaths.has(canonical)) return { system: false, path: canonical };
  }
  throw new Error(`Library is not bundled or resolvable from its own RPATHs: ${dependency} (${binaryPath})`);
}

/**
 * Strict audit for this portable Node SEA + PyInstaller onedir layout.
 * PyInstaller gives each collected binary its own relative LC_RPATH:
 * https://github.com/pyinstaller/pyinstaller/blob/develop/PyInstaller/building/utils.py
 * We intentionally do not simulate arbitrary inherited dyld run-path stacks
 * or DYLD_* overrides: every shipped binary must be independently relocatable.
 * Verification only; never signs, rewrites, or executes packaged binaries.
 */
export async function verifyMacOSPackage(directory, { arch = process.arch, executable = 'claimer', helper = 'helpers/bin/connectwallet-claims/connectwallet-claims' } = {}) {
  if (process.platform !== 'darwin') throw new Error('Native macOS package verification requires macOS.');
  const root = await realpath(resolve(directory));
  // Shared inventory rejects absolute, escaping, dangling and cyclic links.
  // Keep the real framework structure intact for codesign resource checking.
  const entries = await packageEntries(root, { allowSymlinks: true });
  const files = entries.filter((entry) => entry.type === 'file').map((entry) => posix.join(root, entry.path));
  const binaries = new Map();
  const options = { timeout: 30_000, maxBuffer: 2 * 1024 * 1024, encoding: 'utf8', shell: false };
  for (const file of files) {
    const handle = await open(file, 'r');
    let magic;
    try {
      const buffer = Buffer.alloc(8);
      const { bytesRead } = await handle.read(buffer, 0, 8, 0);
      magic = buffer.subarray(0, bytesRead);
    } finally { await handle.close(); }
    if (!isMachO(magic)) continue;
    const target = assertMacOSArchitecture((await execute('/usr/bin/lipo', ['-archs', file], options)).stdout, arch);
    // Signature integrity is checked, not Developer ID trust/notarization.
    // PyInstaller and Node SEA packaging both use ad-hoc signatures here.
    await execute('/usr/bin/codesign', ['--verify', '--strict', '--verbose=2', file], options);
    const commands = await execute('/usr/bin/otool', ['-arch', target, '-l', file], options);
    binaries.set(file, parseMachOLoadCommands(commands.stdout));
  }
  const main = posix.resolve(root, executable);
  const helperExecutable = posix.resolve(root, helper);
  for (const entry of [main, helperExecutable]) {
    if (!within(root, entry) || !binaries.has(entry)) throw new Error(`Expected Mach-O executable is missing: ${entry}`);
  }
  const availablePaths = new Set(binaries.keys());
  const resolvePath = (path) => {
    try { return realpathSync(path); }
    catch (error) {
      // An absent first RPATH candidate is normal; dyld tries the next one.
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null;
      throw error;
    }
  };
  let dependencyCount = 0;
  for (const [binaryPath, { dependencies, rpaths }] of binaries) {
    const executablePath = within(posix.dirname(helperExecutable), binaryPath) ? helperExecutable : main;
    for (const dependency of dependencies) {
      resolveMachODependency(dependency, { binaryPath, executablePath, rpaths, packageRoot: root, availablePaths, resolvePath });
      dependencyCount++;
    }
  }
  console.log(`macOS package audit passed: ${binaries.size} Mach-O binaries, ${dependencyCount} resolved dependencies, ${arch} architecture and valid signatures.`);
  return { binaryCount: binaries.size, dependencyCount };
}
