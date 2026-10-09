import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { ClaimScheduler } from '../src/core/claim-scheduler.mjs';
import { claimPriority, selectionPriority, compareClaimPriority, domainPriority, isWorthAttempting, isP2CClaimConnectionLimitExceeded, MAX_P2C_SUCCESSFUL_CONNECTIONS } from '../src/core/claim-priority.mjs';

const maximum = 'f'.repeat(64);
const keyOf = job => `${job.bounty.txid}:${job.bounty.vout}`;
function job(id, domain = 'alpha.example', payout = 1000n, { target = maximum, factor = 1_000_000, mask = 1, due = 0, ...fields } = {}) {
  const rawPriority = claimPriority(target, payout);
  return { bounty: { txid: id.toString(16).padStart(64, '0'), vout: 0, domain, signature_algorithms_mask: mask, connection_work_target: target },
    rawPriority, priority: selectionPriority(rawPriority, factor), factor, due, ...fields };
}
const queue = jobs => new Map(jobs.map(item => [keyOf(item), item]));
function take(scheduler, now = 0) {
  const selection = scheduler.next(now);
  if (selection) assert.equal(scheduler.commit(selection), true);
  return selection?.[1];
}

test('domains alternate lexicographic fair turns and best economic turns', () => {
  const jobs = [job(1, 'alpha.example', 3000n), job(2, 'beta.example', 1000n), job(3, 'gamma.example', 1000n)];
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue(jobs), { now: 0 });
  const names = Array.from({ length: 12 }, () => take(scheduler).bounty.domain);
  assert.deepEqual(names, ['alpha.example', 'alpha.example', 'beta.example', 'alpha.example', 'gamma.example', 'alpha.example',
    'alpha.example', 'alpha.example', 'beta.example', 'alpha.example', 'gamma.example', 'alpha.example']);
});

test('each domain keeps selecting its best stable factor-adjusted bounty until the leader changes', () => {
  const jobs = [job(1, 'alpha.example', 1000n, { factor: 1_100_000 }), job(2, 'alpha.example', 1099n), job(3, 'alpha.example', 800n)];
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue(jobs), { now: 0 });
  assert.deepEqual(Array.from({ length: 9 }, () => take(scheduler)), Array(9).fill(jobs[0]));
  // A 10% factor cannot reverse a greater-than-10% economic difference.
  jobs[1].rawPriority = claimPriority(maximum, 1101n); jobs[1].priority = selectionPriority(jobs[1].rawPriority, jobs[1].factor);
  scheduler.clear({ preserveSelection: false }); scheduler.rebuild(queue(jobs), { now: 0 });
  assert.equal(take(scheduler), jobs[1]);
});

test('a refreshed domain immediately selects its new highest score without rotating through lower ranks', () => {
  const first = job(1, 'alpha.example', 3000n), second = job(2, 'alpha.example', 2000n), third = job(3, 'alpha.example', 1000n);
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue([first, second, third]), { now: 0 });
  assert.equal(take(scheduler), first);
  first.rawPriority = claimPriority(maximum, 500n); first.priority = selectionPriority(first.rawPriority, first.factor);
  scheduler.rebuild(queue([first, second, third]), { now: 0 });
  assert.deepEqual(Array.from({ length: 4 }, () => take(scheduler)), Array(4).fill(second));
  const higher = job(4, 'alpha.example', 4000n);
  scheduler.rebuild(queue([first, second, third, higher]), { now: 0 });
  assert.deepEqual(Array.from({ length: 4 }, () => take(scheduler)), Array(4).fill(higher));
});

test('same-domain equal payouts consistently prefer difficulty 10 over difficulty 15', () => {
  const target = bits => ((1n << (256n - bits)) - 1n).toString(16).padStart(64, '0');
  const easier = job(1, 'alpha.example', 100_000_000n, { target: target(10n) });
  const harder = job(2, 'alpha.example', 100_000_000n, { target: target(15n), factor: 1_100_000 });
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue([harder, easier]), { now: 0 });
  assert.equal(scheduler.entries.size, 2, 'both targets exceed the raw profitability floor');
  assert.deepEqual(Array.from({ length: 12 }, () => take(scheduler)), Array(12).fill(easier));
});

for (const reason of ['removed', 'not ready', 'cooling', 'proof winner', 'budget exceeded']) {
  test(`the next-best same-domain bounty takes over when the leader is ${reason}`, () => {
    const best = job(1, 'alpha.example', 3000n), next = job(2, 'alpha.example', 2000n), last = job(3, 'alpha.example', 1000n);
    const scheduler = new ClaimScheduler(); scheduler.rebuild(queue([last, next, best]), { now: 0 });
    assert.equal(take(scheduler), best);
    if (reason === 'removed') scheduler.remove(keyOf(best), { now: 0 });
    else if (reason === 'not ready') scheduler.setReady(keyOf(best), false, { now: 0 });
    else if (reason === 'cooling') scheduler.setReady(keyOf(best), true, { due: 100, now: 0 });
    else {
      best[reason === 'proof winner' ? 'winner' : 'budgetExceeded'] = true;
      scheduler.rebuild(queue([last, next, best]), { now: 0 });
    }
    assert.deepEqual(Array.from({ length: 4 }, () => take(scheduler)), Array(4).fill(next));
    if (reason === 'not ready') {
      scheduler.setReady(keyOf(best), true, { now: 0 });
      assert.equal(take(scheduler), best);
    } else if (reason === 'cooling') assert.equal(take(scheduler, 100), best);
  });
}

test('peek, failed DNS and removed candidates do not consume connection turns', () => {
  const a = job(1, 'alpha.example', 3000n), b = job(2, 'beta.example');
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue([a, b]), { now: 0 });
  assert.equal(scheduler.next(0)[1], a); assert.equal(scheduler.next(0)[1], a);
  scheduler.setDomainReady('alpha.example', false, { now: 0 });
  assert.equal(take(scheduler), b); // Still the initial fair turn.
  scheduler.setDomainReady('alpha.example', true, { now: 0 });
  assert.equal(take(scheduler), a); // Economic turn, without moving fair cursor.
  assert.equal(take(scheduler), a); // Fair wraps after beta.
  scheduler.remove(keyOf(a), { now: 0 });
  assert.equal(take(scheduler), b);
});

test('connection ACK retains its domain turn across refresh or deletion and cannot commit twice', () => {
  const a = job(1, 'alpha.example', 3000n), b = job(2, 'alpha.example', 2000n);
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue([a, b]), { now: 0 });
  const selected = scheduler.next(0);
  a.priority = selectionPriority(claimPriority(maximum, 500n), a.factor);
  scheduler.rebuild(queue([a, b]), { now: 0 });
  scheduler.remove(keyOf(a), { now: 0 });
  assert.equal(scheduler.commit(selected), true);
  assert.equal(scheduler.commit(selected), false);
  assert.equal(take(scheduler), b);
  const pending = scheduler.next(0); scheduler.clear({ preserveSelection: false });
  assert.equal(scheduler.commit(pending), false);
});

test('mask-specific rate selects the same best bounty on both fair and economic domain turns', () => {
  const a1 = job(1, 'alpha.example', 3000n, { mask: 1, rate: 1 });
  const a2 = job(2, 'alpha.example', 1000n, { mask: 2, rate: 20 });
  const b = job(3, 'beta.example', 2000n, { rate: 5 });
  const scheduler = new ClaimScheduler({ connectionRate: item => item.rate });
  scheduler.rebuild(queue([a1, a2, b]), { now: 0 });
  assert.equal(take(scheduler), a2); assert.equal(take(scheduler), a2);
  assert.equal(take(scheduler), b); assert.equal(take(scheduler), a2);
  scheduler.setReady(keyOf(a2), false, { now: 0 });
  assert.equal(take(scheduler), a1); assert.equal(take(scheduler), b);
});

test('raw eligibility floor, external budget, proof-winner and unavailable flags remain separate from factor', () => {
  const below = job(1, 'alpha.example', 199n, { factor: 1_100_000 });
  const at = job(2, 'beta.example', 200n);
  const exceeded = job(3, 'gamma.example', 1000n, { budgetExceeded: true });
  const unavailable = job(4, 'delta.example', 1000n, { unavailable: true });
  const winner = job(5, 'epsilon.example', 1000n, { winner: true });
  const retired = job(6, 'zeta.example', 1000n, { retired: true });
  const blocked = job(7, 'theta.example', 1000n, { ready: false });
  const scheduler = new ClaimScheduler({ isReady: item => item.ready !== false });
  scheduler.rebuild(queue([below, at, exceeded, unavailable, winner, retired, blocked]), { now: 0 });
  assert.equal(take(scheduler), at);
  assert.equal(scheduler.setReady(keyOf(below), true, { now: 0 }), false);
  scheduler.setReady(keyOf(at), false, { now: 0 });
  assert.equal(scheduler.next(0), undefined);
  scheduler.setReady(keyOf(blocked), true, { now: 0 });
  assert.equal(take(scheduler), blocked);
});

test('job cooldown and domain DNS deadline promote only when due, with bounded timer replacement', () => {
  const a = job(1, 'alpha.example'), b = job(2, 'beta.example', 1000n, { due: 50 });
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue([a, b]), { now: 0 });
  scheduler.setDomainReady('alpha.example', true, { due: 100, now: 0 });
  assert.equal(scheduler.nextDue(), 50); assert.equal(scheduler.next(49), undefined);
  assert.equal(take(scheduler, 50), b);
  for (let delay = 100; delay < 1100; delay++) scheduler.setReady(keyOf(b), true, { due: delay, now: 50 });
  assert.equal(scheduler.waiting.items.length, 2);
  assert.equal(scheduler.nextDue(), 100); assert.equal(take(scheduler, 100), a);
  scheduler.setDomainReady('alpha.example', false, { now: 100 });
  assert.equal(scheduler.next(1098), undefined); assert.equal(take(scheduler, 1099), b);
  assert.equal(scheduler.nextDue(), Infinity);
});

test('exact ties follow Core outpoint storage-byte order, not transport order or shuffle', () => {
  const jobs = [job(1), job(256), job(2)];
  const expected = [...jobs].sort(compareClaimPriority);
  assert.notEqual(expected[0], jobs[0]);
  const scheduler = new ClaimScheduler(); scheduler.rebuild(queue(jobs), { now: 0 });
  for (const best of expected) {
    assert.deepEqual(Array.from({ length: 3 }, () => take(scheduler)), Array(3).fill(best));
    scheduler.remove(keyOf(best), { now: 0 });
  }
  assert.equal(scheduler.next(0), undefined);
});

test('indexed scheduler matches an independent scan/sort oracle through dynamic readiness, DNS, cooldown and rebuilds', () => {
  let seed = 0x31415926;
  const random = max => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % max; };
  const jobs = Array.from({ length: 350 }, (_, id) => job(id + 1, `domain${String(id % 35).padStart(2, '0')}.example`,
    200n + BigInt(random(10000)), { factor: 1_000_000 + random(100001), mask: 1 + Math.floor(id / 35) % 7, ready: true }));
  const items = queue(jobs), gates = new Map();
  const rate = item => 1 + item.bounty.signature_algorithms_mask;
  const scheduler = new ClaimScheduler({ connectionRate: rate, isReady: item => item.ready });
  scheduler.rebuild(items, { now: 0 });
  let after = null, economic = false;
  for (let now = 0; now < 1500; now++) {
    const changed = jobs[random(jobs.length)], key = keyOf(changed);
    if (now % 3 === 0) {
      changed.ready = random(4) !== 0; changed.due = now + random(15);
      scheduler.setReady(key, changed.ready, { due: changed.due, now });
    }
    if (now % 11 === 0) {
      const gate = { ready: random(5) !== 0, due: now + random(10) };
      gates.set(changed.bounty.domain, gate);
      scheduler.setDomainReady(changed.bounty.domain, gate.ready, { due: gate.due, now });
    }
    if (now % 71 === 0) {
      const raw = claimPriority(maximum, 200n + BigInt(random(10000)));
      changed.rawPriority = raw; changed.priority = selectionPriority(raw, changed.factor);
      scheduler.rebuild(items, { now });
    }
    if (now % 83 === 0) { items.delete(key); scheduler.remove(key, { now }); }
    const groups = new Map();
    for (const item of items.values()) {
      const gate = gates.get(item.bounty.domain);
      if (!item.ready || item.due > now || (gate && (!gate.ready || gate.due > now)) || !isWorthAttempting(item.rawPriority, rate(item))) continue;
      const entries = groups.get(item.bounty.domain) ?? [];
      entries.push(item); groups.set(item.bounty.domain, entries);
    }
    let expected;
    if (groups.size) {
      let name;
      if (economic) {
        let leader, score;
        for (const [domain, entries] of groups) for (const item of entries) {
          const value = domainPriority(item.priority, rate(item), 1_000_000);
          if (!leader || value > score || (value === score && compareClaimPriority(item, leader) < 0)) { leader = item; score = value; name = domain; }
        }
      } else {
        const names = [...groups.keys()].sort(); name = names.find(domain => after === null || domain > after) ?? names[0];
      }
      expected = groups.get(name).sort((a, b) =>
        domainPriority(b.priority, rate(b), 1_000_000) - domainPriority(a.priority, rate(a), 1_000_000) || compareClaimPriority(a, b))[0];
    }
    const selection = scheduler.next(now);
    assert.equal(selection?.[1], expected, `Different selected bounty at tick ${now}`);
    if (!selection) continue;
    assert.equal(scheduler.commit(selection), true);
    if (!economic) after = expected.bounty.domain;
    economic = !economic;
  }
});

test('20,000 candidates: 1,000 selections never rescan jobs, call rate estimation or sort', () => {
  let rateCalls = 0, propertyReads = 0;
  const jobs = Array.from({ length: 20000 }, (_, id) => {
    const value = job(id + 1, `d${String(id % 200).padStart(3, '0')}.example`, 1000n + BigInt(id), { mask: id % 7 + 1 });
    return new Proxy(value, { get(target, key, receiver) { propertyReads++; return Reflect.get(target, key, receiver); } });
  });
  const scheduler = new ClaimScheduler({ connectionRate: () => { rateCalls++; return 5; } });
  scheduler.rebuild(queue(jobs), { now: 0 });
  const ratesBefore = rateCalls, readsBefore = propertyReads, started = performance.now();
  const originalSort = Array.prototype.sort;
  Array.prototype.sort = function forbiddenHotSort() { throw new Error('Sort in per-connection hot path'); };
  try { for (let index = 0; index < 1000; index++) assert.ok(take(scheduler)); }
  finally { Array.prototype.sort = originalSort; }
  assert.equal(rateCalls, ratesBefore); assert.equal(propertyReads, readsBefore);
  assert.ok(performance.now() - started < 3000, 'Indexed selections unexpectedly slow');
  assert.equal(scheduler.entries.size, 20000);
});

test('successful connection budget is strict and exact across easiest/hardest targets and uint64 saturation', () => {
  assert.equal(isP2CClaimConnectionLimitExceeded(maximum, 2), false);
  assert.equal(isP2CClaimConnectionLimitExceeded(maximum, 3), true);
  for (const bits of [1n, 10n, 32n, 60n]) {
    const target = ((1n << (256n - bits)) - 1n).toString(16).padStart(64, '0');
    const twiceExpected = 1n << (bits + 1n);
    assert.equal(isP2CClaimConnectionLimitExceeded(target, twiceExpected), false);
    assert.equal(isP2CClaimConnectionLimitExceeded(target, twiceExpected + 1n), true);
  }
  assert.equal(isP2CClaimConnectionLimitExceeded('0'.repeat(64), MAX_P2C_SUCCESSFUL_CONNECTIONS - 1n), false);
  assert.equal(isP2CClaimConnectionLimitExceeded('0'.repeat(64), MAX_P2C_SUCCESSFUL_CONNECTIONS), true);
  assert.equal(isP2CClaimConnectionLimitExceeded(maximum, 1n << 100n), true);
  assert.throws(() => isP2CClaimConnectionLimitExceeded(maximum, -1));
  assert.throws(() => isP2CClaimConnectionLimitExceeded(maximum, Number.MAX_SAFE_INTEGER + 1));
  assert.throws(() => isP2CClaimConnectionLimitExceeded('garbage', 1));
});
