import { posix } from 'node:path';

export function needsStaticCryptography(build, host = process) {
  return build && host.platform === 'darwin' && host.arch === 'x64';
}

export function staticCryptographyInstall(version, opensslDirectory, environment = process.env) {
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) throw new Error('An exact cryptography version is required.');
  if (typeof opensslDirectory !== 'string' || !posix.isAbsolute(opensslDirectory) || /[\0\r\n]/.test(opensslDirectory)) {
    throw new Error('OPENSSL_DIR must be one absolute macOS directory.');
  }
  return {
    // Rebuild only the provider. Runtime dependencies still come from the exact
    // requirements pins in the following installation step.
    args: ['-m', 'pip', 'install', '--disable-pip-version-check', '--no-deps', '--force-reinstall',
      '--no-binary=cryptography', '--no-cache-dir', `cryptography==${version}`],
    env: { ...environment, OPENSSL_DIR: opensslDirectory, OPENSSL_STATIC: '1' },
  };
}

export function assertStaticOpenSSL(dependencies, extension) {
  const lines = dependencies.trim().split(/\r?\n/);
  if (lines.length < 2 || lines[0] !== `${extension}:`) throw new Error('Unexpected otool output for the cryptography extension.');
  for (const line of lines.slice(1)) {
    const match = /^\s+(.+?)\s+\(compatibility version [^)]+\)$/.exec(line);
    if (!match) throw new Error('Unrecognized cryptography library dependency.');
    const library = posix.basename(match[1]);
    if (/^lib(?:ssl|crypto)(?:[.-].*)?\.dylib$/i.test(library) || /\/OpenSSL\.framework\//i.test(match[1])) {
      throw new Error(`cryptography must statically link OpenSSL before packaging; found ${match[1]}.`);
    }
  }
}
