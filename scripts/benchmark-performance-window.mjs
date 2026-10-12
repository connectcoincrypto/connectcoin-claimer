// Offline bookkeeping-only benchmark. No DNS, sockets, RPC or claims.
import { performance } from 'node:perf_hooks';
import { P2CDomainStats } from '../src/core/claim-priority.mjs';

class PreviousEma {
  connections = 0.1; totalTime = 0.02; completed = 0;
  record(valid, seconds) {
    this.connections = 0.999 * this.connections + 0.001 * Number(valid);
    this.totalTime = 0.999 * this.totalTime + 0.001 * seconds;
    this.completed++;
  }
  connectionRate() { return Math.max(Number.MIN_VALUE, Math.min(Number.MAX_VALUE, this.connections / this.totalTime)); }
}

let sink = 0;
function run(Type, count) {
  let now = 0;
  const stats = Array.from({ length: 64 }, () => new Type({ now: () => now }));
  const cpu = process.cpuUsage(), start = performance.now();
  for (let i = 0; i < count; i++) {
    now = i * 1.25; // Simulated 800/s; includes minute rotations and hour expiry.
    const entry = stats[i % stats.length];
    entry.record(i % 17 !== 0, 0.005 + (i % 37) * 0.003);
    sink += entry.connectionRate();
  }
  const durationMs = performance.now() - start, used = process.cpuUsage(cpu);
  if (stats.reduce((sum, entry) => sum + entry.completed, 0) !== count) throw new Error('Counter regression');
  return { samples: count, wallMs: durationMs, cpuMs: (used.user + used.system) / 1000,
    nanosecondsPerSample: durationMs * 1e6 / count,
    estimatedOneCoreCpuPercentAt800PerSecond: (used.user + used.system) / 1000 / count * 80 };
}

run(PreviousEma, 100000); run(P2CDomainStats, 100000);
const rounds = Array.from({ length: 3 }, () => ({ ema: run(PreviousEma, 5760000), window: run(P2CDomainStats, 5760000) }));
global.gc?.();
const before = process.memoryUsage();
const histories = Array.from({ length: 8192 }, () => new P2CDomainStats({ now: () => 0 }));
for (const history of histories) history.record(true, 0.1);
global.gc?.();
const after = process.memoryUsage();
console.log(JSON.stringify({ scope: 'Offline domain bookkeeping only, 64 policies, two simulated hours at 800/s per round; not end-to-end TLS throughput.',
  rounds, memory: { histories: histories.length, numericBucketBytesPerHistory: 60 * 3 * 8,
    gcExposed: !!global.gc, heapUsedDeltaBytes: after.heapUsed - before.heapUsed,
    arrayBufferDeltaBytes: after.arrayBuffers - before.arrayBuffers, rssDeltaBytes: after.rss - before.rss },
  checksum: sink + histories[0].connectionRate() }, null, 2));
