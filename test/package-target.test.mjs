import test from 'node:test';
import assert from 'node:assert/strict';
import { packageTarget } from '../scripts/package-target.mjs';

test('native package targets distinguish both Mac architectures without changing Windows/Linux names', () => {
  for (const arch of ['x64', 'arm64']) {
    assert.deepEqual(packageTarget('darwin', arch), { platform: 'macos', arch, executable: 'claimer' });
    assert.deepEqual(packageTarget('linux', arch), { platform: 'linux', arch, executable: 'claimer' });
    assert.deepEqual(packageTarget('win32', arch), { platform: 'win', arch, executable: 'claimer.exe' });
  }
});

test('unsupported native architectures and inherited object properties are rejected', () => {
  for (const platform of ['freebsd', 'android', '', 'constructor', '__proto__']) {
    assert.throws(() => packageTarget(platform, 'x64'), /native/);
  }
  for (const arch of ['ia32', 'arm', 'universal', '', null]) {
    assert.throws(() => packageTarget('darwin', arch), /64-bit/);
  }
});
