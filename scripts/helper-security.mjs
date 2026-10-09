// Build-time checks only. Old executables can pass their own legacy self-test,
// so packaging must verify the provider actually bundled, not the source venv.
export function pinnedCryptographyVersion(requirements) {
  const pins = [...requirements.matchAll(/^cryptography==([0-9]+\.[0-9]+\.[0-9]+)\s*$/gm)];
  if (pins.length !== 1) throw new Error('Expected one exact cryptography release pin.');
  return pins[0][1];
}

export function validateHelperSecurity(output, expectedVersion) {
  let report;
  try { report = JSON.parse(output); } catch { /* Reject invalid or extra output. */ }
  if (report?.type !== 'ready' || report.protocol !== 4 || report.roots !== 1 ||
      report.security?.cryptographyVersion !== expectedVersion ||
      report.security?.minimumCryptographyVersion !== '50.0.1' ||
      report.security?.rsaPublicExponentMaxBits !== 64 ||
      typeof report.security?.opensslVersion !== 'string' ||
      !/^OpenSSL [0-9]+\.[0-9]+\.[0-9]+(?: |$)/.test(report.security.opensslVersion)) {
    throw new Error('Bundled helper has missing or outdated security metadata. Run npm run build:claims.');
  }
  return report.security;
}
