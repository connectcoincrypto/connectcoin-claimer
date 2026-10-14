import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main } from '../src/cli.mjs';

const address = 'cc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqr7enya';
const turn = () => new Promise(resolve => setImmediate(resolve));
async function flush() { for (let i = 0; i < 12; i++) await turn(); }

for (const trigger of ['signal', 'fatal-event', 'startup-error']) {
  test(`CLI preserves the live proof owner through repeated shutdown IO failures (${trigger})`, async t => {
    const directory = await mkdtemp(join(tmpdir(), 'claimer-cli-stop-'));
    const configPath = join(directory, 'claimer.conf'), lockPath = `${configPath}.lock`;
    await writeFile(configPath, `receiving_address=${address}\n`);
    const messages = [], started = Promise.withResolvers();
    const proof = Object.freeze({ proof: 'original verified witness', transactionHex: 'original signed bytes' });
    const startupError = new Error('Startup stopped after capturing a verified proof');
    let settled = false, storageReady = false, starts = 0, stops = 0, owner, emit;
    t.mock.method(console, 'log', (...args) => messages.push(args.join(' ')));
    t.mock.method(console, 'error', (...args) => messages.push(args.join(' ')));
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const operation = main(['--config', configPath], {
      helperAvailable: () => true,
      serviceFactory(options) {
        emit = options.emit;
        owner = {
          heldProofs: new Map([['outpoint', proof]]),
          async start() { starts++; started.resolve(); if (trigger === 'startup-error') throw startupError; },
          async stop() {
            stops++;
            if (!storageReady) throw Object.assign(new Error('Injected full disk'), { code: 'ENOSPC' });
            // The real service clears ownership only after its atomic write;
            // service/journal tests exercise the bytes and filesystem boundary.
            owner.heldProofs.clear();
          },
          snapshot: () => ({ claims: { completed: 7, attempts: 12 } }),
        };
        return owner;
      },
    });
    const outcome = operation.then(value => { settled = true; return { value }; }, error => { settled = true; return { error }; });
    t.after(async () => {
      storageReady = true;
      t.mock.timers.tick(5000);
      await flush();
      await outcome;
      t.mock.timers.reset();
      await rm(directory, { recursive: true, force: true });
    });
    await started.promise;
    const lockOwner = await readFile(lockPath, 'utf8');
    if (trigger === 'signal') process.emit('SIGTERM');
    if (trigger === 'fatal-event') emit('error', { fatal: true, message: 'Storage failure' });
    await flush();
    assert.equal(settled, false, 'The CLI must stay alive while a verified proof has no durable owner');
    assert.equal(stops, 1);
    assert.equal(owner.heldProofs.get('outpoint'), proof);
    assert.equal(await readFile(lockPath, 'utf8'), lockOwner);
    // Additional shutdown requests share the same drain and cannot bypass it.
    process.emit('SIGTERM'); process.emit('SIGTERM');
    await flush();
    assert.equal(stops, 1);
    for (let retry = 0; retry < 3; retry++) {
      t.mock.timers.tick(5000);
      await flush();
      assert.equal(stops, retry + 2);
      assert.equal(settled, false);
      assert.equal(owner.heldProofs.get('outpoint'), proof);
      assert.equal(await readFile(lockPath, 'utf8'), lockOwner);
    }
    assert.match(messages.join('\n'), /proof.*memory|memory.*proof/i);
    assert.equal(starts, 1, 'Persistence retries must never restart claims');
    assert.deepEqual(owner.snapshot().claims, { completed: 7, attempts: 12 });
    storageReady = true;
    t.mock.timers.tick(5000);
    const result = await outcome;
    if (trigger === 'startup-error') assert.equal(result.error, startupError);
    else assert.equal(result.value, 1, 'A recovered shutdown must still report the original IO failure');
    assert.equal(owner.heldProofs.size, 0);
    await assert.rejects(readFile(lockPath), { code: 'ENOENT' });
  });
}

for (const fail of [false, true]) {
  test(`CLI shutdown without a volatile proof ${fail ? 'propagates errors without endless retries' : 'still exits normally'}`, async t => {
    const directory = await mkdtemp(join(tmpdir(), 'claimer-cli-empty-stop-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const configPath = join(directory, 'claimer.conf'), lockPath = `${configPath}.lock`;
    await writeFile(configPath, `receiving_address=${address}\n`);
    const started = Promise.withResolvers(), shutdownError = new Error('Unrelated cleanup failure');
    let stops = 0;
    t.mock.method(console, 'log', () => {});
    t.mock.method(console, 'error', () => {});
    const operation = main(['--config', configPath], {
      helperAvailable: () => true,
      serviceFactory: () => ({
        heldProofs: new Map(), start: async () => { started.resolve(); },
        stop: async () => { stops++; if (fail) throw shutdownError; },
        snapshot: () => ({}),
      }),
    });
    const outcome = operation.then(value => ({ value }), error => ({ error }));
    await started.promise;
    process.emit('SIGINT');
    const result = await outcome;
    assert.equal(stops, 1, 'Normal/final cleanup shares one shutdown operation');
    if (fail) {
      assert.equal(result.error, shutdownError);
      assert.match(await readFile(lockPath, 'utf8'), /^\d+:/, 'An unclean shutdown must not erase its instance lock');
    } else {
      assert.equal(result.value, 0);
      await assert.rejects(readFile(lockPath), { code: 'ENOENT' });
    }
  });
}
