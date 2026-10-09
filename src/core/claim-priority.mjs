// Wallet-local scheduling policy shared with ConnectCoin Core. Not consensus.
export const PRIORITY_FACTOR_SCALE = 1_000_000;
export const PRIORITY_FACTOR_MAX = 1_100_000;
export const MIN_EXPECTED_RETURN = 1000; // connects / second of TCP/TLS effort
const MAX_MONEY = 1_000_000_000_000_000_000n;
const HASH_SPACE = 2 ** 256;

export const MAX_P2C_SUCCESSFUL_CONNECTIONS = (1n << 64n) - 1n;

/** Core's soft per-outpoint budget: only completed CertificateVerify captures
 * count. Equality with 2/p is still eligible; pending/failed TCP never reserves
 * budget. A saturated uint64 counter stops further starts, as in Core.
 */
export function isP2CClaimConnectionLimitExceeded(target, successes) {
  if (typeof target !== 'string' || !/^[0-9a-f]{64}$/.test(target)) throw new Error('Invalid claim work target');
  if (typeof successes === 'number' && Number.isSafeInteger(successes)) successes = BigInt(successes);
  if (typeof successes !== 'bigint' || successes < 0n) throw new Error('Invalid successful connection count');
  if (successes >= MAX_P2C_SUCCESSFUL_CONNECTIONS) return true;
  return successes * (BigInt(`0x${target}`) + 1n) > (1n << 257n);
}

export function claimPriority(target, netReward) {
  if (typeof target !== 'string' || target.length !== 64 || /[^0-9a-f]/.test(target)) return 0n;
  if (typeof netReward !== 'bigint' || netReward <= 0n || netReward > MAX_MONEY) return 0n;
  // Do not truncate target+1 to 256 bits: the easiest target has probability 1.
  return (BigInt(`0x${target}`) + 1n) * netReward;
}

export function selectionPriority(raw, factor) {
  if (!Number.isSafeInteger(factor) || factor < PRIORITY_FACTOR_SCALE || factor > PRIORITY_FACTOR_MAX) throw new Error('Invalid bounty priority factor');
  return raw * BigInt(factor);
}

export function domainPriority(priority, rate, scale = 1) {
  if (typeof priority !== 'bigint' || priority < 0n || priority >= (1n << 352n) || !Number.isFinite(scale) || scale <= 0) return NaN;
  // Match Core's most-significant-word-first conversion and operation order.
  // Domain performance is approximate; the bounty/tie key remains exact.
  let numerator = 0;
  for (let shift = 320n; shift >= 0n; shift -= 32n) numerator = numerator * 4294967296 + Number((priority >> shift) & 0xffffffffn);
  const expected = numerator / HASH_SPACE;
  const score = expected * rate / scale;
  // EMA rates have no fixed maximum. Avoid poisoning scheduler ordering with
  // infinity after an extreme run of zero-duration captures. Divide first on
  // overflow so a finite scaled result is not needlessly saturated.
  return score === Infinity ? Math.min(Number.MAX_VALUE, (expected / scale) * rate) : score;
}

export function validateMinExpectedReturn(value = MIN_EXPECTED_RETURN) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) throw new Error('Minimum expected return must be a finite number between 0 and Number.MAX_SAFE_INTEGER');
  return value;
}

export function isWorthAttempting(raw, rate, minExpectedReturn = MIN_EXPECTED_RETURN) {
  validateMinExpectedReturn(minExpectedReturn);
  const expected = domainPriority(raw, rate);
  return typeof raw === 'bigint' && raw > 0n && Number.isFinite(rate) && rate > 0 && Number.isFinite(expected) && expected >= minExpectedReturn;
}

export function compareClaimPriority(a, b) {
  if (a.priority !== b.priority) return a.priority > b.priority ? -1 : 1;
  // Core's uint256 ordering uses storage bytes, not the displayed hash order.
  const hashOrder = Buffer.compare(Buffer.from(a.bounty.txid, 'hex').reverse(), Buffer.from(b.bounty.txid, 'hex').reverse());
  return hashOrder || a.bounty.vout - b.bounty.vout;
}

export class P2CDomainStats {
  constructor() {
    this.connections = 0.1;
    this.totalTime = 0.02;
    this.completed = 0;
  }
  record(success, seconds) {
    if (typeof success !== 'boolean' || !Number.isFinite(seconds) || seconds < 0) return;
    // Only the initial observation supplies the 5/s prior; it decays along
    // with the entire history rather than being added back on every query.
    this.connections = 0.999 * this.connections + 0.001 * Number(success);
    this.totalTime = 0.999 * this.totalTime + 0.001 * seconds;
    this.completed = Math.min(Number.MAX_SAFE_INTEGER, this.completed + 1);
  }
  connectionRate() {
    // Preserve a positive, finite rate even at the limits of IEEE doubles.
    // These representational bounds are not a scheduling/profitability floor.
    return Math.max(Number.MIN_VALUE, Math.min(Number.MAX_VALUE, this.connections / this.totalTime));
  }
}

export function validateAttemptStats(stats, maxAttempts) {
  if (!stats || stats.validation !== 'certificate-proof-v1' || !Number.isSafeInteger(stats.completed) || stats.completed < 0 || stats.completed > maxAttempts ||
      !Array.isArray(stats.recent) || stats.recent.length !== Math.min(100, stats.completed)) throw new Error('Invalid helper attempt statistics');
  for (const sample of stats.recent) {
    if (!Array.isArray(sample) || sample.length !== 2 || typeof sample[0] !== 'boolean' ||
        typeof sample[1] !== 'number' || !Number.isFinite(sample[1]) || sample[1] < 0 || sample[1] > 3600) throw new Error('Invalid helper attempt statistics');
  }
  return stats;
}
