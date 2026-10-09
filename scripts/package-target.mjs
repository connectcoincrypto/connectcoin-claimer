/** Native build and archive naming shared by the packager and its smoke test. */
export function packageTarget(platform = process.platform, arch = process.arch) {
  const labels = { win32: 'win', linux: 'linux', darwin: 'macos' };
  if (!Object.hasOwn(labels, platform) || !['x64', 'arm64'].includes(arch)) {
    throw new Error('Build on native Windows, Linux or macOS, with matching 64-bit Node.js and Python.');
  }
  return { platform: labels[platform], arch, executable: platform === 'win32' ? 'claimer.exe' : 'claimer' };
}
