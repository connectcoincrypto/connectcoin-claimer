// Wallet-local scheduling policy shared with ConnectCoin Core. Not consensus.
export const PRIORITY_FACTOR_SCALE = 1_000_000;
export const PRIORITY_FACTOR_MAX = 1_100_000;
export const MIN_EXPECTED_RETURN = 1000; // connects / second of TCP/TLS effort
const MAX_MONEY = 1_000_000_000_000_000_000n;
const HASH_SPACE = 2 ** 256;
// A permanent smoothing prior, separate from actual observations and counters.
const PERFORMANCE_PRIOR_CONNECTIONS = 5;
const PERFORMANCE_PRIOR_SECONDS = 1;

export const MAX_P2C_SUCCESSFUL_CONNECTIONS = (1n << 64n) - 1n;

/** First forbidden capture count. Compute once per immutable work target;
 * equality with 2/p remains eligible, and uint64 saturation always stops. */
export function claimConnectionStopCount(target) {
  if (typeof target !== 'string' || !/^[0-9a-f]{64}$/.test(target)) throw new Error('Invalid claim work target');
  const firstExceeded = (1n << 257n) / (BigInt(`0x${target}`) + 1n) + 1n;
  return firstExceeded < MAX_P2C_SUCCESSFUL_CONNECTIONS ? firstExceeded : MAX_P2C_SUCCESSFUL_CONNECTIONS;
}

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
  // Measured rates have no fixed maximum. Avoid poisoning scheduler ordering with
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
  #counts = new Float64Array(60);
  #valid = new Float64Array(60);
  #seconds = new Float64Array(60);
  #minute = null;
  #now;
  constructor({ now = () => performance.now() } = {}) {
    if (typeof now !== 'function') throw new Error('Performance clock must be a function');
    this.#now = now;
    this.attempts = 0;
    this.connections = 0;
    this.totalTime = 0;
    this.completed = 0;
  }
  #advance() {
    const time = this.#now();
    // Production uses a monotonic clock. A faulty/backwards injected reading
    // must not resurrect expired buckets or move new samples into the past.
    const current = Number.isFinite(time) ? Math.floor(Math.max(0, Math.min(Number.MAX_SAFE_INTEGER, time)) / 60000) : this.#minute ?? 0;
    const minute = Math.max(current, this.#minute ?? current);
    if (this.#minute === null) this.#minute = minute;
    if (minute === this.#minute) return minute % 60;
    if (minute - this.#minute >= 60) {
      this.#counts.fill(0); this.#valid.fill(0); this.#seconds.fill(0);
    } else for (let cursor = this.#minute + 1; cursor <= minute; cursor++) {
      const index = cursor % 60;
      this.#counts[index] = 0; this.#valid[index] = 0; this.#seconds[index] = 0;
    }
    // At most once per minute, rebuild totals instead of accumulating floating
    // point subtraction drift. The per-connection hot path does not scan buckets.
    this.attempts = 0; this.connections = 0; this.totalTime = 0;
    for (let index = 0; index < 60; index++) {
      this.attempts += this.#counts[index]; this.connections += this.#valid[index];
      this.totalTime = Math.min(Number.MAX_VALUE, this.totalTime + this.#seconds[index]);
    }
    this.#minute = minute;
    return minute % 60;
  }
  record(success, seconds) {
    if (typeof success !== 'boolean' || !Number.isFinite(seconds) || seconds < 0) return;
    const index = this.#advance();
    this.#counts[index]++; this.attempts++;
    this.#valid[index] += Number(success); this.connections += Number(success);
    this.#seconds[index] = Math.min(Number.MAX_VALUE, this.#seconds[index] + seconds);
    this.totalTime = Math.min(Number.MAX_VALUE, this.totalTime + seconds);
    this.completed = Math.min(Number.MAX_SAFE_INTEGER, this.completed + 1);
  }
  connectionRate() {
    this.#advance();
    // Apply the same prior once to every estimate, including an empty or expired
    // window. Never insert synthetic successes or time into the raw buckets.
    // Preserve a positive, finite rate even at the limits of IEEE doubles.
    // These representational bounds are not a scheduling/profitability floor.
    return Math.max(Number.MIN_VALUE, Math.min(Number.MAX_VALUE,
      (PERFORMANCE_PRIOR_CONNECTIONS + this.connections) / (PERFORMANCE_PRIOR_SECONDS + this.totalTime)));
  }
  snapshot() {
    this.#advance();
    return { attempts: this.attempts, connections: this.connections, totalTime: this.totalTime, completed: this.completed };
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
