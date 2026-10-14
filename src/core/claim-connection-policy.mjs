// Bounded sampling for policies excluded by the economic estimate. This never
// changes that estimate, the transport limits, or any observed counter.
export const RECOVERY_PROBE_INTERVAL_MS = 60000;
export const BOOTSTRAP_PROBE_COUNT = 32;
export const BOOTSTRAP_PROBE_INTERVAL_MS = 250;
export const MAX_RECOVERY_POLICIES = 256;

export class ClaimConnectionPolicy {
  constructor() { this.probes = new Map(); this.nextGlobalStart = 0; this.reservation = null; }
  entry(key, now) {
    if (!this.probes.has(key)) {
      if (this.probes.size >= MAX_RECOVERY_POLICIES) {
        const oldest = [...this.probes.keys()].find(candidate => candidate !== this.reservation?.key);
        this.probes.delete(oldest);
      }
      // Re-entry after bounded eviction starts another sampling episode. The
      // engine-wide 4/s gate survives eviction/retention and prevents churn bursts.
      this.probes.set(key, { started: 0, due: now });
    }
    return this.probes.get(key);
  }
  probeDue(key, now = Date.now()) { return Math.max(this.entry(key, now).due, this.nextGlobalStart); }
  reserveProbe(key, token, now = Date.now()) {
    if (this.reservation || this.probeDue(key, now) > now) return false;
    this.reservation = { key, token }; return true;
  }
  releaseProbe(token) {
    if (!this.reservation || this.reservation.token !== token) return false;
    this.reservation = null; return true;
  }
  probeStarted(key, now = Date.now(), token) {
    if (token !== undefined && (this.reservation?.token !== token || this.reservation.key !== key)) throw new Error('Invalid recovery start reservation');
    const state = this.entry(key, now);
    state.started = Math.min(BOOTSTRAP_PROBE_COUNT, state.started + 1);
    state.due = now + (state.started < BOOTSTRAP_PROBE_COUNT ? BOOTSTRAP_PROBE_INTERVAL_MS : RECOVERY_PROBE_INTERVAL_MS);
    this.nextGlobalStart = Math.max(this.nextGlobalStart, now + BOOTSTRAP_PROBE_INTERVAL_MS);
    this.probes.delete(key); this.probes.set(key, state);
    if (token !== undefined) this.releaseProbe(token);
    return this.probeDue(key, now);
  }
  retain(policies) {
    for (const key of this.probes.keys()) if (!policies.has(key) && key !== this.reservation?.key) this.probes.delete(key);
  }
  // Clear per-policy history, not a future global deadline or a live admission.
  clear() { this.probes.clear(); }
}
