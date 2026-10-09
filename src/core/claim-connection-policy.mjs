// Recovery probes for policies excluded by EMA; no transport limits or backoff.
export const RECOVERY_PROBE_INTERVAL_MS = 60000;
export const MAX_RECOVERY_POLICIES = 256;

export class ClaimConnectionPolicy {
  constructor() { this.probes = new Map(); }
  probeDue(key, now = Date.now()) {
    if (!this.probes.has(key)) {
      if (this.probes.size >= MAX_RECOVERY_POLICIES) this.probes.delete(this.probes.keys().next().value);
      // Newly admitted/re-admitted policies must wait too: eviction cannot
      // turn a changing catalog into a stream of immediate recovery probes.
      this.probes.set(key, now + RECOVERY_PROBE_INTERVAL_MS);
    }
    return this.probes.get(key);
  }
  probeStarted(key, now = Date.now()) {
    this.probeDue(key, now);
    this.probes.delete(key); this.probes.set(key, now + RECOVERY_PROBE_INTERVAL_MS);
    return this.probes.get(key);
  }
  retain(policies) {
    for (const key of this.probes.keys()) if (!policies.has(key)) this.probes.delete(key);
  }
  clear() { this.probes.clear(); }
}
