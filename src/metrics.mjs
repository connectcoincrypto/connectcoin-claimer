import { performance } from 'node:perf_hooks';

const increment = value => Math.min(Number.MAX_SAFE_INTEGER, value + 1);

/** Fixed 100-slot ring: reporting memory is independent of the configured rate. */
export class ClaimMetrics {
  constructor({ now = () => performance.now() } = {}) {
    this.now = now; this.buckets = Array.from({ length: 100 }, () => ({ tick: -1, count: 0 }));
    this.connectionsStarted = 0; this.activeConnections = 0; this.attemptsFinished = 0;
    this.valid = 0; this.invalid = 0; this.cancelled = 0; this.targetReached = 0;
  }
  started() {
    const tick = Math.floor(this.now() / 100), bucket = this.buckets[tick % this.buckets.length];
    if (bucket.tick !== tick) { bucket.tick = tick; bucket.count = 0; }
    bucket.count = increment(bucket.count);
    this.connectionsStarted = increment(this.connectionsStarted); this.activeConnections++;
  }
  finished(result) {
    this.activeConnections = Math.max(0, this.activeConnections - 1);
    this.attemptsFinished = increment(this.attemptsFinished);
    if (result?.validationPassed === true) this.valid = increment(this.valid);
    if (result?.validationPassed === false) this.invalid = increment(this.invalid);
    if (result?.cancelled === true) this.cancelled = increment(this.cancelled);
    if (result?.verified === true && result?.proof && !result.cancelled) this.targetReached = increment(this.targetReached);
  }
  snapshot() {
    const now = this.now(), tick = Math.floor(now / 100);
    const count = this.buckets.reduce((sum, bucket) => sum + (bucket.tick > tick - 100 && bucket.tick <= tick ? bucket.count : 0), 0);
    return { connectionsStarted: this.connectionsStarted, activeConnections: this.activeConnections,
      connectionsPerSecond: count / 10, attemptsFinished: this.attemptsFinished,
      valid: this.valid, invalid: this.invalid, cancelled: this.cancelled, targetReached: this.targetReached };
  }
  wrap(pool) {
    const attempt = pool.attempt.bind(pool);
    pool.attempt = async (context, options = {}) => {
      let started = false, finished = false;
      const finish = result => { if (started && !finished) { finished = true; this.finished(result); } };
      try {
        return await attempt(context, { ...options,
          onStarted: (...args) => { if (!started) { started = true; this.started(); } options.onStarted?.(...args); },
          onResult: result => { finish(result); options.onResult?.(result); },
        });
      } catch (error) {
        finish({ cancelled: error?.name === 'AbortError', validationPassed: null }); throw error;
      } finally { finish({ validationPassed: null }); }
    };
    return pool;
  }
}
