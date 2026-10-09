import { compareClaimPriority, domainPriority, isWorthAttempting, validateMinExpectedReturn, MIN_EXPECTED_RETURN, PRIORITY_FACTOR_SCALE } from './claim-priority.mjs';

const compareText = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const keyOf = job => `${job.bounty.txid}:${job.bounty.vout}`;
const eligible = job => !job.retired && !job.unavailable && !job.budgetExceeded && !job.winner;

function upperBound(values, value, compare) {
  let low = 0, high = values.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (compare(values[middle], value) <= 0) low = middle + 1;
    else high = middle;
  }
  return low;
}

/** Indexed counts: changes, prefix counts and kth-ready lookup are O(log n). */
class ReadyIndex {
  constructor(values) {
    this.tree = new Uint32Array(values.length + 1);
    this.total = 0;
    for (let index = 1; index < this.tree.length; index++) {
      this.tree[index] += values[index - 1];
      this.total += values[index - 1];
      const parent = index + (index & -index);
      if (parent < this.tree.length) this.tree[parent] += this.tree[index];
    }
  }
  add(index, delta) {
    this.total += delta;
    for (index++; index < this.tree.length; index += index & -index) this.tree[index] += delta;
  }
  before(end) {
    let total = 0;
    for (; end > 0; end -= end & -end) total += this.tree[end];
    return total;
  }
  at(order) {
    if (order < 0 || order >= this.total) return -1;
    let index = 0, bit = 1;
    while (bit * 2 < this.tree.length) bit *= 2;
    for (; bit > 0; bit >>>= 1) {
      const next = index + bit;
      if (next < this.tree.length && this.tree[next] <= order) {
        index = next;
        order -= this.tree[next];
      }
    }
    return index;
  }
}

/** Indexed heap, with replacement/removal rather than accumulating stale items. */
class IndexedHeap {
  constructor(compare) { this.compare = compare; this.items = []; this.indices = new Map(); }
  peek() { return this.items[0]?.value; }
  swap(a, b) {
    [this.items[a], this.items[b]] = [this.items[b], this.items[a]];
    this.indices.set(this.items[a].key, a); this.indices.set(this.items[b].key, b);
  }
  repair(index) {
    while (index > 0) {
      const parent = (index - 1) >>> 1;
      if (this.compare(this.items[parent].value, this.items[index].value) <= 0) break;
      this.swap(parent, index); index = parent;
    }
    for (;;) {
      let best = index;
      for (const child of [2 * index + 1, 2 * index + 2]) {
        if (child < this.items.length && this.compare(this.items[child].value, this.items[best].value) < 0) best = child;
      }
      if (best === index) break;
      this.swap(index, best); index = best;
    }
  }
  set(key, value) {
    let index = this.indices.get(key);
    if (index === undefined) {
      index = this.items.length; this.items.push({ key, value }); this.indices.set(key, index);
    } else this.items[index] = { key, value };
    this.repair(index);
  }
  remove(key) {
    const index = this.indices.get(key);
    if (index === undefined) return;
    this.indices.delete(key);
    const last = this.items.pop();
    if (index < this.items.length) {
      this.items[index] = last; this.indices.set(last.key, index); this.repair(index);
    }
  }
}

const selectionToken = Symbol('claim selection');
const rankSnapshot = job => ({ priority: job.priority, bounty: { txid: job.bounty.txid, vout: job.bounty.vout } });
const deadline = value => {
  if (!Number.isFinite(value) || value < 0) throw new Error('Invalid claim scheduler deadline');
  return value;
};

/** Core-style domain rotation, always using each domain's best ready bounty.
 * No RNG, network, keys or mutable rank comparator.
 * Rebuild (normally every five seconds) snapshots each job's exact adjusted priority
 * and each domain/mask's observed rate. The hot path uses indexed ready sets, not
 * queue scans/sorts. Call setReady/remove when a job changes outside a refresh.
 * next is a peek; commit consumes a turn only after a connection is dispatched.
 */
export class ClaimScheduler {
  constructor({ connectionRate = () => 5, isReady = eligible, minExpectedReturn = MIN_EXPECTED_RETURN } = {}) {
    if (typeof connectionRate !== 'function' || typeof isReady !== 'function') throw new Error('Invalid claim scheduler callbacks');
    this.minExpectedReturn = validateMinExpectedReturn(minExpectedReturn);
    this.connectionRate = connectionRate;
    this.isReady = isReady;
    this.domainAfter = null;
    this.preferReward = false;
    this.domainGates = new Map();
    this.serial = 0;
    this.clear({ preserveSelection: true });
  }
  clear({ preserveSelection = true } = {}) {
    this.entries = new Map(); this.groups = new Map(); this.names = [];
    this.readyDomains = new ReadyIndex([]);
    this.economic = new IndexedHeap((a, b) => b.score - a.score || compareClaimPriority(a.leader, b.leader) || compareText(a.name, b.name));
    this.waiting = new IndexedHeap((a, b) => a.due - b.due || compareText(a.id, b.id));
    this.pending = null;
    if (!preserveSelection) {
      this.serial++;
      this.domainGates.clear();
      this.domainAfter = null; this.preferReward = false;
    }
  }
  rebuild(jobs, { now = Date.now(), isReady = this.isReady } = {}) {
    deadline(now);
    if (typeof isReady !== 'function') throw new Error('Invalid claim readiness predicate');
    this.clear({ preserveSelection: true });
    const rates = new Map(), trackedDomains = new Set();
    for (const item of jobs) {
      const [key, job] = Array.isArray(item) ? item : [keyOf(item), item];
      const name = job.bounty.domain;
      trackedDomains.add(name);
      const policy = `${name}:${job.bounty.signature_algorithms_mask}`;
      if (!rates.has(policy)) rates.set(policy, this.connectionRate(job));
      const rate = rates.get(policy);
      if (!eligible(job) || (!isWorthAttempting(job.rawPriority, rate, this.minExpectedReturn) && !job.recoveryProbe)) continue;
      if (this.entries.has(key)) throw new Error('Duplicate bounty in claim schedule');
      const rank = rankSnapshot(job), score = domainPriority(rank.priority, rate, PRIORITY_FACTOR_SCALE);
      if (!Number.isFinite(score)) continue;
      let group = this.groups.get(name);
      if (!group) {
        group = { name, entries: [], masks: new Map(), active: false, gate: this.domainGates.get(name) ?? { ready: true, due: 0 } };
        this.groups.set(name, group);
      }
      const due = deadline(Math.max(job.due ?? 0, job.recoveryProbe ? job.probeDue ?? 0 : 0)), allowed = Boolean(isReady(job));
      const entry = { key, job, ...rank, score, due, allowed, active: allowed && due <= now, group };
      this.entries.set(key, entry); group.entries.push(entry);
    }
    for (const name of this.domainGates.keys()) if (!trackedDomains.has(name)) this.domainGates.delete(name);
    this.names = [...this.groups.keys()].sort(compareText);
    this.readyDomains = new ReadyIndex(this.names.map(() => 0));
    for (let index = 0; index < this.names.length; index++) {
      const group = this.groups.get(this.names[index]); group.index = index;
      group.entries.sort(compareClaimPriority);
      for (let position = 0; position < group.entries.length; position++) {
        const entry = group.entries[position]; entry.position = position;
        const maskId = entry.job.bounty.signature_algorithms_mask;
        let mask = group.masks.get(maskId);
        if (!mask) { mask = { entries: [] }; group.masks.set(maskId, mask); }
        entry.mask = mask; entry.maskPosition = mask.entries.length; mask.entries.push(entry);
        if (entry.allowed && entry.due > now) this.waiting.set(`job:${entry.key}`, { id: `job:${entry.key}`, due: entry.due, entry });
      }
      group.ready = new ReadyIndex(group.entries.map(entry => Number(entry.active)));
      for (const mask of group.masks.values()) mask.ready = new ReadyIndex(mask.entries.map(entry => Number(entry.active)));
      this.armDomain(group, now);
      this.refreshGroup(group, now);
    }
  }
  armDomain(group, now) {
    const id = `domain:${group.name}`;
    if (group.gate.ready && group.gate.due > now) this.waiting.set(id, { id, due: group.gate.due, group });
    else this.waiting.remove(id);
  }
  refreshGroup(group, now) {
    let leader;
    // There are at most seven supported signature masks, not N bounties.
    if (group.gate.ready && group.gate.due <= now) for (const mask of group.masks.values()) {
      if (!mask.ready.total) continue;
      const candidate = mask.entries[mask.ready.at(0)];
      if (!leader || candidate.score > leader.score || (candidate.score === leader.score && compareClaimPriority(candidate, leader) < 0)) leader = candidate;
    }
    const active = Boolean(leader);
    group.leader = leader;
    if (group.active !== active) { this.readyDomains.add(group.index, active ? 1 : -1); group.active = active; }
    if (active) this.economic.set(group.name, { name: group.name, score: leader.score, leader, group });
    else this.economic.remove(group.name);
  }
  setActive(entry, active, now) {
    if (entry.active === active) return;
    const delta = active ? 1 : -1; entry.active = active;
    entry.group.ready.add(entry.position, delta); entry.mask.ready.add(entry.maskPosition, delta);
    this.refreshGroup(entry.group, now);
  }
  setReady(key, ready, { due, now = Date.now() } = {}) {
    deadline(now);
    const entry = this.entries.get(key);
    if (!entry) return false;
    entry.allowed = Boolean(ready); entry.due = deadline(due ?? entry.job.due ?? 0);
    const id = `job:${key}`;
    if (entry.allowed && entry.due > now) this.waiting.set(id, { id, due: entry.due, entry });
    else this.waiting.remove(id);
    this.setActive(entry, entry.allowed && entry.due <= now, now);
    return true;
  }
  setDomainReady(name, ready, { due = 0, now = Date.now() } = {}) {
    deadline(now);
    const gate = { ready: Boolean(ready), due: deadline(due) };
    // Gates are remembered only for tracked domains, keeping state bounded.
    const group = this.groups.get(name);
    if (!group) return false;
    this.domainGates.set(name, gate); group.gate = gate;
    this.armDomain(group, now); this.refreshGroup(group, now);
    return true;
  }
  remove(key, { now = Date.now() } = {}) {
    const entry = this.entries.get(key);
    if (!entry) return false;
    this.setReady(key, false, { now });
    this.entries.delete(key);
    // Arrays retain only bounded tombstone rank data until the next refresh.
    entry.job = null;
    return true;
  }
  promote(now) {
    for (let next = this.waiting.peek(); next && next.due <= now; next = this.waiting.peek()) {
      this.waiting.remove(next.id);
      if (next.entry) this.setActive(next.entry, next.entry.allowed, now);
      else this.refreshGroup(next.group, now);
    }
  }
  nextDue() { return this.waiting.peek()?.due ?? Infinity; }
  next(now = Date.now()) {
    deadline(now); this.promote(now);
    if (!this.readyDomains.total) return undefined;
    let group;
    if (this.preferReward) group = this.economic.peek().group;
    else {
      const index = this.domainAfter === null ? 0 : upperBound(this.names, this.domainAfter, compareText);
      const before = this.readyDomains.before(index);
      group = this.groups.get(this.names[this.readyDomains.at(before < this.readyDomains.total ? before : 0)]);
    }
    // Fair and economic turns both use the leader whose mask-adjusted score
    // ranks this domain. In-flight attempts do not rotate to worse bounties.
    const entry = group.leader;
    const token = { serial: this.serial, job: entry.job, key: entry.key, domain: group.name, economic: this.preferReward, committed: false };
    const result = [entry.key, entry.job];
    Object.defineProperty(result, selectionToken, { value: token });
    this.pending = token;
    return result;
  }
  /** Prefer commit(selection) so delayed acknowledgements retain the selected domain turn.
   * A caller using commit(job) must serialize next/commit. A second outstanding
   * selection cannot consume an extra turn after another selection committed.
   */
  commit(selectionOrJob) {
    const token = selectionOrJob?.[selectionToken] ?? (this.pending?.job === selectionOrJob ? this.pending : null);
    if (!token || token.committed || token.serial !== this.serial) return false;
    token.committed = true;
    if (!token.economic) this.domainAfter = token.domain;
    this.preferReward = !token.economic;
    this.serial++; this.pending = null;
    return true;
  }
}
