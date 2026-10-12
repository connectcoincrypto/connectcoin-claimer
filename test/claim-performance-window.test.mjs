import test from 'node:test';
import assert from 'node:assert/strict';
import { P2CDomainStats } from '../src/core/claim-priority.mjs';

const MINUTE = 60000;
function fixture(initial = 0) {
  let time = initial;
  return { stats: new P2CDomainStats({ now: () => time }), set: value => { time = value; } };
}

test('minute bucket expires at the sixtieth minute boundary, including an observation near its end', () => {
  const { stats, set } = fixture(MINUTE - 1);
  stats.record(true, 0.25); stats.record(false, 0.75);
  set(60 * MINUTE - 1);
  assert.equal(stats.connectionRate(), 3);
  assert.deepEqual(stats.snapshot(), { attempts: 2, connections: 1, totalTime: 1, completed: 2 });
  set(60 * MINUTE);
  assert.equal(stats.connectionRate(), 5);
  assert.deepEqual(stats.snapshot(), { attempts: 0, connections: 0, totalTime: 0, completed: 2 });
});

test('each of the sixty minute buckets rotates independently while cumulative completions keep increasing', () => {
  const { stats, set } = fixture();
  for (let minute = 0; minute < 120; minute++) {
    set(minute * MINUTE); stats.record(minute % 2 === 0, 0.5);
    const count = Math.min(minute + 1, 60);
    assert.deepEqual(stats.snapshot(), { attempts: count, connections: minute < 60 ? Math.ceil(count / 2) : 30,
      totalTime: count * 0.5, completed: minute + 1 });
  }
  assert.equal(stats.connectionRate(), 35 / 31);
});

test('a long idle gap expires on read and retains only the permanent smoothing prior', () => {
  const { stats, set } = fixture();
  assert.equal(stats.connectionRate(), 5);
  stats.record(true, 0.1);
  set(50000 * MINUTE); assert.equal(stats.connectionRate(), 5);
  assert.equal(stats.completed, 1);
  stats.record(false, 1); assert.equal(stats.connectionRate(), 2.5);
  assert.deepEqual(stats.snapshot(), { attempts: 1, connections: 0, totalTime: 1, completed: 2 });
  stats.record(true, 1); assert.equal(stats.connectionRate(), 2);
});

test('record expires old buckets before adding observations without any intervening read', () => {
  const { stats, set } = fixture();
  stats.record(false, 300);
  set(60 * MINUTE); stats.record(true, 0.5);
  assert.equal(stats.connectionRate(), 4);
  assert.deepEqual(stats.snapshot(), { attempts: 1, connections: 1, totalTime: 0.5, completed: 2 });
});

test('backwards and nonfinite clock readings cannot resurrect or prematurely expire observations', () => {
  const { stats, set } = fixture();
  stats.record(false, 10);
  set(60 * MINUTE); assert.equal(stats.connectionRate(), 5);
  set(MINUTE); stats.record(true, 0.5);
  for (const now of [-100, NaN, Infinity, -Infinity, 59 * MINUTE]) {
    set(now); assert.equal(stats.connectionRate(), 4); assert.equal(stats.completed, 2);
  }
  set(119 * MINUTE); assert.equal(stats.connectionRate(), 4);
  set(120 * MINUTE); assert.equal(stats.connectionRate(), 5);
  assert.equal(stats.completed, 2);
});

test('invalid samples never change either window totals or cumulative completion counts', () => {
  const { stats } = fixture();
  stats.record(true, 1);
  const before = stats.snapshot();
  for (const seconds of [-1, NaN, Infinity, -Infinity, '1', null, undefined]) stats.record(true, seconds);
  for (const valid of [undefined, null, 0, 1, 'true', {}]) stats.record(valid, 1);
  assert.deepEqual(stats.snapshot(), before);
  assert.throws(() => new P2CDomainStats({ now: 0 }), /clock/);
});

test('zero durations and representational overflow retain finite positive rates through expiration', () => {
  const { stats, set } = fixture();
  stats.record(false, 0); assert.equal(stats.connectionRate(), 5);
  stats.record(true, 0); assert.equal(stats.connectionRate(), 6);
  stats.record(false, Number.MAX_VALUE); stats.record(false, Number.MAX_VALUE);
  assert.equal(Number.isFinite(stats.connectionRate()), true);
  assert.equal(Number.isFinite(stats.totalTime), true);
  set(MINUTE); stats.record(true, 0.5);
  set(60 * MINUTE); assert.equal(stats.connectionRate(), 4);
  assert.deepEqual(stats.snapshot(), { attempts: 1, connections: 1, totalTime: 0.5, completed: 5 });
});

test('an unobserved policy retains its prior across clock jumps without inventing observations', () => {
  const { stats, set } = fixture();
  set(1000 * MINUTE); assert.equal(stats.connectionRate(), 5);
  assert.deepEqual(stats.snapshot(), { attempts: 0, connections: 0, totalTime: 0, completed: 0 });
});

test('the prior smooths the first failure without adding synthetic observations on queries or expiry', () => {
  const { stats, set } = fixture();
  assert.equal(stats.connectionRate(), 5);
  stats.record(false, 1);
  const observed = { attempts: 1, connections: 0, totalTime: 1, completed: 1 };
  for (let read = 0; read < 1000; read++) {
    assert.equal(stats.connectionRate(), 2.5);
    assert.deepEqual(stats.snapshot(), observed);
  }
  set(60 * MINUTE);
  for (let read = 0; read < 100; read++) assert.equal(stats.connectionRate(), 5);
  assert.deepEqual(stats.snapshot(), { attempts: 0, connections: 0, totalTime: 0, completed: 1 });
  stats.record(false, 1);
  assert.equal(stats.connectionRate(), 2.5);
  assert.deepEqual(stats.snapshot(), { ...observed, completed: 2 });
});

test('minute aggregation and smoothing match an independent randomized observation oracle', () => {
  const { stats, set } = fixture();
  const observations = [];
  let seed = 0x517ab32, minute = 0;
  const random = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed; };
  for (let step = 0; step < 2000; step++) {
    minute += random() % 5;
    set(minute * MINUTE + random() % MINUTE);
    if (step % 7 !== 0) {
      const valid = Boolean(random() & 1), seconds = (random() % 1024) / 32;
      stats.record(valid, seconds); observations.push({ minute, valid, seconds });
    }
    const recent = observations.filter(sample => sample.minute > minute - 60);
    const valid = recent.filter(sample => sample.valid).length;
    const seconds = recent.reduce((sum, sample) => sum + sample.seconds, 0);
    assert.equal(stats.connectionRate(), (5 + valid) / (1 + seconds));
    assert.deepEqual(stats.snapshot(), { attempts: recent.length, connections: valid, totalTime: seconds, completed: observations.length });
  }
});
