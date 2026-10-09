import assert from 'node:assert/strict';
import test from 'node:test';
import { assertMacOSArchitecture, isMachO, parseMachOLoadCommands, resolveMachODependency } from '../scripts/macos-package.mjs';

test('Mach-O detection recognizes thin and universal binaries, not Java or short files', () => {
  for (const magic of ['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe']) assert.ok(isMachO(Buffer.from(magic, 'hex')));
  for (const magic of ['cafebabe00000002', 'cafebabf00000001', 'bebafeca02000000', 'bfbafeca01000000']) assert.ok(isMachO(Buffer.from(magic, 'hex')));
  for (const magic of ['', 'cffaed', 'cafebabe00000041', 'cafebabe00000000', '4d5a000000000000', '7f454c4600000000']) assert.equal(isMachO(Buffer.from(magic, 'hex')), false);
});

test('lipo architecture audit requires the native target and allows universal dependencies', () => {
  assert.equal(assertMacOSArchitecture('x86_64\n', 'x64'), 'x86_64');
  assert.equal(assertMacOSArchitecture('x86_64 arm64\n', 'arm64'), 'arm64');
  assert.throws(() => assertMacOSArchitecture('x86_64', 'arm64'), /required arm64/);
  assert.throws(() => assertMacOSArchitecture('arm64', 'x64'), /required x86_64/);
  assert.throws(() => assertMacOSArchitecture('arm64', 'ia32'), /Unsupported/);
  assert.throws(() => assertMacOSArchitecture('arm64: garbage', 'arm64'), /required/);
});

function command(index, name, field = '') {
  return `Load command ${index}\n          cmd ${name}\n      cmdsize 80\n${field}\n`;
}

test('otool load-command parser preserves spaces, excludes install names, and includes weak/reexport deps', () => {
  const output = '/a path/extension.so:\n'
    + command(0, 'LC_SEGMENT_64')
    + command(1, 'LC_ID_DYLIB', '         name @rpath/lib-self.dylib (offset 24)')
    + command(2, 'LC_RPATH', '         path @loader_path/../a folder (offset 12)')
    + command(3, 'LC_LOAD_DYLIB', '         name @rpath/Python.framework/Versions/3.13/Python (offset 24)')
    + command(4, 'LC_LOAD_WEAK_DYLIB', '         name /usr/lib/libSystem.B.dylib (offset 24)')
    + command(5, 'LC_REEXPORT_DYLIB', '         name /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation (offset 24)');
  assert.deepEqual(parseMachOLoadCommands(output), {
    id: '@rpath/lib-self.dylib', rpaths: ['@loader_path/../a folder'],
    dependencies: ['@rpath/Python.framework/Versions/3.13/Python', '/usr/lib/libSystem.B.dylib', '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation'],
  });
});

test('otool parser fails closed on missing/unknown dependency metadata', () => {
  assert.throws(() => parseMachOLoadCommands('otool failed'), /Unrecognized/);
  assert.throws(() => parseMachOLoadCommands('Load command 0\n garbage'), /Missing Mach-O/);
  assert.throws(() => parseMachOLoadCommands(command(0, 'LC_RPATH')), /Missing path/);
  assert.throws(() => parseMachOLoadCommands(command(0, 'LC_LOAD_DYLIB', 'name missing offset')), /Missing path/);
  assert.throws(() => parseMachOLoadCommands(command(0, 'LC_NEW_DYLIB')), /Unsupported/);
  assert.throws(() => parseMachOLoadCommands(command(0, 'LC_ID_DYLIB', ' name a (offset 24)') + command(1, 'LC_ID_DYLIB', ' name b (offset 24)')), /Duplicate/);
});

const context = {
  packageRoot: '/relocated package',
  binaryPath: '/relocated package/helpers/bin/helper/_internal/lib-dynload/_ssl.so',
  executablePath: '/relocated package/helpers/bin/helper/helper',
  rpaths: ['@loader_path/..'],
  availablePaths: new Set(['/relocated package/helpers/bin/helper/_internal/libssl.3.dylib', '/relocated package/helpers/bin/helper/_internal/Python.framework/Versions/3.13/Python']),
};

test('library resolver handles PyInstaller own RPATHs and relocation with spaces', () => {
  assert.deepEqual(resolveMachODependency('@rpath/libssl.3.dylib', context), { system: false, path: '/relocated package/helpers/bin/helper/_internal/libssl.3.dylib' });
  assert.deepEqual(resolveMachODependency('@loader_path/../libssl.3.dylib', context), { system: false, path: '/relocated package/helpers/bin/helper/_internal/libssl.3.dylib' });
  assert.deepEqual(resolveMachODependency('@executable_path/_internal/libssl.3.dylib', context), { system: false, path: '/relocated package/helpers/bin/helper/_internal/libssl.3.dylib' });
  assert.deepEqual(resolveMachODependency('@rpath/Python.framework/Versions/3.13/Python', { ...context, rpaths: ['@executable_path/_internal'] }), { system: false, path: '/relocated package/helpers/bin/helper/_internal/Python.framework/Versions/3.13/Python' });
});

test('library resolver accepts only system framework/library absolutes, including dyld-cache files', () => {
  for (const path of ['/usr/lib/libSystem.B.dylib', '/System/Library/Frameworks/Security.framework/Versions/A/Security']) {
    assert.deepEqual(resolveMachODependency(path, context), { system: true, path });
  }
  assert.deepEqual(resolveMachODependency('@rpath/libSystem.B.dylib', { ...context, rpaths: ['/usr/lib'] }), { system: true, path: '/usr/lib/libSystem.B.dylib' });
  for (const path of ['/usr/local/lib/libssl.dylib', '/opt/homebrew/lib/libssl.dylib', '/Library/Frameworks/Python.framework/Python', '/Users/runner/work/lib.dylib', '/usr/lib/../../tmp/injected.dylib', '/System/Library/../../../tmp/injected.dylib', '/relocated package/helpers/bin/helper/_internal/libssl.3.dylib']) {
    assert.throws(() => resolveMachODependency(path, context), /Non-portable/);
  }
});

test('library resolver fails for missing bundled dependencies, unsafe anchors and external RPATHs', () => {
  assert.throws(() => resolveMachODependency('@rpath/missing.dylib', context), /not bundled/);
  assert.throws(() => resolveMachODependency('@rpath/libssl.3.dylib', { ...context, rpaths: [] }), /not bundled/);
  assert.throws(() => resolveMachODependency('libssl.3.dylib', context), /Unsupported relative/);
  assert.throws(() => resolveMachODependency('@loader_path_extra/libssl.3.dylib', context), /Unsupported relative/);
  assert.throws(() => resolveMachODependency('@loader_path/../../../../../../tmp/libssl.dylib', context), /escapes/);
  assert.throws(() => resolveMachODependency('@rpath/../../../../../../tmp/libssl.dylib', context), /escapes/);
  assert.throws(() => resolveMachODependency('@loader_path/../../../../../../usr/lib/libSystem.B.dylib', context), /escapes/);
  assert.throws(() => resolveMachODependency('@rpath/../../../../../../usr/lib/libSystem.B.dylib', context), /escapes/);
  for (const rpath of ['/opt/homebrew/lib', '/usr/local/lib', '/Users/runner/work', '@rpath/nested', 'relative', '@loader_path/../../../../../']) {
    assert.throws(() => resolveMachODependency('@rpath/libssl.3.dylib', { ...context, rpaths: [rpath] }), /RPATH/);
  }
  assert.throws(() => resolveMachODependency('@rpath/libssl.3.dylib', { ...context, executablePath: '/other/helper' }), /inside/);
});

test('library resolver rejects path-prefix lookalikes and checks RPATH candidates in order', () => {
  assert.throws(() => resolveMachODependency('@executable_path/../../../../relocated package-evil/lib.dylib', context), /escapes/);
  assert.throws(() => resolveMachODependency('/usr/lib-evil/lib.dylib', context), /Non-portable/);
  assert.deepEqual(resolveMachODependency('@rpath/libssl.3.dylib', { ...context, rpaths: ['@loader_path', '@loader_path/..'] }), { system: false, path: '/relocated package/helpers/bin/helper/_internal/libssl.3.dylib' });
});

test('library resolver follows framework file and directory aliases to an audited Mach-O', () => {
  const base = '/relocated package/helpers/bin/helper/_internal/Python.framework';
  const canonical = `${base}/Versions/3.13/Python`;
  const aliases = new Map([[`${base}/Python`, canonical], [`${base}/Versions/Current/Python`, canonical]]);
  const linkedContext = { ...context, resolvePath: (path) => aliases.get(path) ?? path };
  assert.deepEqual(resolveMachODependency('@rpath/Python.framework/Python', linkedContext), { system: false, path: canonical });
  assert.deepEqual(resolveMachODependency('@rpath/Python.framework/Versions/Current/Python', linkedContext), { system: false, path: canonical });
  assert.throws(() => resolveMachODependency('@rpath/Python.framework/Resources/Info.plist', linkedContext), /not bundled/);
});

test('library resolver rejects aliases outside the package and aliases to unaudited files', () => {
  for (const target of ['/opt/homebrew/lib/libssl.3.dylib', '/relocated package-evil/libssl.3.dylib', '/usr/lib/libssl.3.dylib']) {
    assert.throws(() => resolveMachODependency('@rpath/libssl.3.dylib', { ...context, resolvePath: () => target }), /escapes/);
  }
  assert.throws(() => resolveMachODependency('@rpath/libssl.3.dylib', { ...context, resolvePath: () => '/relocated package/README.md' }), /not bundled/);
  assert.throws(() => resolveMachODependency('@rpath/libssl.3.dylib', { ...context, resolvePath: () => null }), /not bundled/);
});

test('library resolver advances past a missing alias candidate and propagates cyclic-link errors', () => {
  const canonical = '/relocated package/helpers/bin/helper/_internal/libssl.3.dylib';
  assert.deepEqual(resolveMachODependency('@rpath/libssl.3.dylib', {
    ...context,
    rpaths: ['@loader_path', '@loader_path/..'],
    resolvePath: (path) => path === canonical ? canonical : null,
  }), { system: false, path: canonical });
  assert.throws(() => resolveMachODependency('@rpath/libssl.3.dylib', {
    ...context, resolvePath: () => { const error = new Error('Symlink cycle'); error.code = 'ELOOP'; throw error; },
  }), /Symlink cycle/);
});
