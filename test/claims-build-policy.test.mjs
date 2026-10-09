import test from 'node:test';
import assert from 'node:assert/strict';
import { assertStaticOpenSSL, needsStaticCryptography, staticCryptographyInstall } from '../scripts/claims-build-policy.mjs';

test('static source rebuild is limited to native Intel macOS packaging', () => {
  for (const [platform, arch] of [['win32', 'x64'], ['linux', 'x64'], ['darwin', 'arm64'], ['darwin', 'x64']]) {
    assert.equal(needsStaticCryptography(false, { platform, arch }), false);
    assert.equal(needsStaticCryptography(true, { platform, arch }), platform === 'darwin' && arch === 'x64');
  }
});

test('source rebuild cannot reuse a stale dynamic wheel or upgrade runtime dependency pins', () => {
  const environment = { PATH: '/usr/bin', OPENSSL_STATIC: '0', OPENSSL_DIR: '/old' };
  const plan = staticCryptographyInstall('50.0.1', '/usr/local/opt/openssl@3', environment);
  assert.deepEqual(plan.args, ['-m', 'pip', 'install', '--disable-pip-version-check', '--no-deps', '--force-reinstall',
    '--no-binary=cryptography', '--no-cache-dir', 'cryptography==50.0.1']);
  assert.deepEqual(plan.env, { PATH: '/usr/bin', OPENSSL_STATIC: '1', OPENSSL_DIR: '/usr/local/opt/openssl@3' });
  assert.equal(environment.OPENSSL_STATIC, '0');
  assert.equal(staticCryptographyInstall('50.0.1', '/custom OpenSSL', {}).env.OPENSSL_DIR, '/custom OpenSSL');
  for (const version of ['latest', '>=50.0.1', '50.0.1\n', '50.0.1rc1']) {
    assert.throws(() => staticCryptographyInstall(version, '/openssl'), /exact cryptography/);
  }
  for (const directory of ['', 'relative', '/one\n/two', '/one\0two']) {
    assert.throws(() => staticCryptographyInstall('50.0.1', directory), /OPENSSL_DIR/);
  }
});

const extension = '/venv/lib/python3.13/site-packages/cryptography/hazmat/bindings/_rust.abi3.so';
const output = library => `${extension}:\n\t${library} (compatibility version 1.0.0, current version 1.0.0)\n`;

test('linkage gate accepts system libraries and rejects OpenSSL dylibs despite runtime self-test success', () => {
  assert.doesNotThrow(() => assertStaticOpenSSL(output('/usr/lib/libSystem.B.dylib'), extension));
  for (const library of ['/usr/local/opt/openssl@3/lib/libssl.3.dylib', '@rpath/libcrypto.3.dylib',
    '@loader_path/libssl.dylib', '/custom OpenSSL/lib/libcrypto.4.dylib', '/Library/Frameworks/OpenSSL.framework/OpenSSL']) {
    assert.throws(() => assertStaticOpenSSL(output(library), extension), /statically link OpenSSL/);
  }
});

test('missing, unrelated or malformed otool output cannot certify static linkage', () => {
  for (const invalid of ['', `${extension}:\n`, output('/usr/lib/libSystem.B.dylib').replace(extension, '/other.so'),
    `${extension}:\nnot an otool dependency\n`]) {
    assert.throws(() => assertStaticOpenSSL(invalid, extension), /otool|dependency/);
  }
});
