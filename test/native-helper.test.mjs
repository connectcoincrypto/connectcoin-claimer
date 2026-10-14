import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getClaimsHelper } from '../src/core/claims.mjs';
import { validateNativeHelperSecurity } from '../scripts/helper-security.mjs';

test('native packaging requires the exact provider and policy attestation', () => {
  const report = { type: 'ready', protocol: 4, roots: 1,
    security: { provider: 'mbedtls', mbedtlsVersion: '3.6.7', rsaPublicExponentMaxBits: 64, admissionGate: 1 } };
  assert.doesNotThrow(() => validateNativeHelperSecurity(JSON.stringify(report)));
  for (const bad of [null, {}, { ...report, protocol: 3 }, { ...report, roots: 2 },
    { ...report, security: { ...report.security, provider: 'cryptography' } },
    { ...report, security: { ...report.security, mbedtlsVersion: '3.6.6' } },
    ...[undefined, true, 0].map(admissionGate => ({ ...report, security: { ...report.security, admissionGate } })),
    { ...report, security: { ...report.security, rsaPublicExponentMaxBits: 65 } }]) {
    assert.throws(() => validateNativeHelperSecurity(JSON.stringify(bad)));
  }
  assert.throws(() => validateNativeHelperSecurity(`${JSON.stringify(report)}\n{}`));
});

test('runtime discovery prefers C++ and never automatically selects the Python reference', async () => {
  const basePath = await mkdtemp(join(tmpdir(), 'claimer-native-discovery-'));
  try {
    const python = join(basePath, '.claims-venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
    await mkdir(join(python, '..'), { recursive: true });
    await writeFile(python, '');
    assert.equal(getClaimsHelper({ basePath }), null);
    const name = process.platform === 'win32' ? 'connectwallet-claims.exe' : 'connectwallet-claims';
    const old = join(basePath, 'helpers/bin/connectwallet-claims', name);
    const native = join(basePath, 'helpers/native-bin/connectwallet-claims', name);
    for (const path of [old, native]) { await mkdir(join(path, '..'), { recursive: true }); await writeFile(path, ''); }
    assert.deepEqual(getClaimsHelper({ basePath }), { command: native, args: [], packaged: true, native: true });
  } finally { await rm(basePath, { recursive: true, force: true }); }
});
