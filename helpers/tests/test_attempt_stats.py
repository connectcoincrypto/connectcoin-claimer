"""Offline scheduler telemetry tests; all public-network capture calls are mocked."""

from __future__ import annotations

import dataclasses
import io
import json
import math
import sys
import threading
import unittest
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

HELPERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPERS))
import claims_bridge
from connectcoin_p2c_tools import generator
from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.errors import ProofVerificationError


def context():
    return ConnectionProof(domain="example.com", txid="01" * 32, input_index=0,
                           connection_work_target="00" * 32, root_certificates_version=1,
                           signature_algorithms_mask=1, validation_time=1800000000, proof=b"")


def capture():
    return SimpleNamespace(encoded_proof=b"\x01", peer_ip="8.8.8.8")


def progress(stats, *, finished=False, elapsed=1.0):
    return generator.GenerationProgress(stats.completed, elapsed, 0.0, None, None,
                                        attempt_stats=stats, finished=finished)


class AttemptStatsTests(unittest.TestCase):
    def run_paced_generation(self, *, rate, concurrency, attempts, quantum=0.0, submit_delays=None):
        clock, starts, sleeps = [100.0], [], []
        def sleep(seconds):
            sleeps.append(seconds)
            step = max(seconds, math.ulp(clock[0]))
            clock[0] += math.ceil(step / quantum) * quantum if quantum else step
        def submit(*args, **kwargs):
            starts.append(clock[0])
            clock[0] += (submit_delays or {}).get(len(starts), 0.0)
            future = Future()
            future.set_exception(OSError("offline capture failure"))
            return future
        executor = SimpleNamespace(submit=submit, shutdown=Mock())
        with patch.object(generator, "ThreadPoolExecutor", return_value=executor) as create, \
             patch.object(generator, "validate_root_bundle"), \
             patch.object(generator, "resolve_endpoints", return_value=(object(),)), \
             patch.object(generator.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(generator.time, "sleep", side_effect=sleep):
            with self.assertRaisesRegex(generator.GenerationError, "no proof met the target"):
                generator.generate_connection_proof(context(), "unused", generator.GenerationOptions(
                    connections_per_second=rate, concurrency=concurrency, max_attempts=attempts))
            self.assertEqual(create.call_args.kwargs["max_workers"], concurrency)
        executor.shutdown.assert_called_once_with(wait=True, cancel_futures=True)
        return starts, sleeps

    def test_legacy_generator_accepts_int32_limits_without_eager_worker_allocation(self):
        for value in (257, 400, 1000, 2147483647):
            with self.subTest(value=value):
                generator._validate_options(generator.GenerationOptions(connections_per_second=value, concurrency=value))
                starts, _ = self.run_paced_generation(rate=value, concurrency=value, attempts=3)
                self.assertEqual(len(starts), 3)
        for name in ("connections_per_second", "concurrency"):
            for value in (True, 1.5, 2147483648):
                with self.subTest(name=name, value=value), self.assertRaises(generator.GenerationError):
                    generator._validate_options(generator.GenerationOptions(**{name: value}))

    def test_legacy_generator_recovers_coarse_wakes_without_new_interval_per_start(self):
        starts, sleeps = self.run_paced_generation(rate=100, concurrency=1000, attempts=1001, quantum=0.015625)
        self.assertGreaterEqual(starts[-1] - starts[0], 10.0 - 1e-8)
        self.assertLessEqual(starts[-1] - starts[0], 10.0 + 0.015625)
        self.assertTrue(any(left == right for left, right in zip(starts, starts[1:])))
        self.assertTrue(sleeps)

    def test_legacy_generator_caps_debt_from_fresh_time_after_delayed_submit(self):
        starts, _ = self.run_paced_generation(rate=10, concurrency=1000, attempts=30, submit_delays={1: 5.0})
        self.assertEqual(starts[0], 100.0)
        caught_up = sum(abs(start - 105.0) < 1e-8 for start in starts[1:])
        self.assertGreaterEqual(caught_up, 10)
        self.assertLessEqual(caught_up, 12)
        self.assertGreater(starts[-1], 105.0)

    def fake_network(self, stack, captured, *, met_target=False):
        stack.enter_context(patch.object(generator, "validate_root_bundle"))
        stack.enter_context(patch.object(generator, "resolve_endpoints", return_value=(object(),)))
        stack.enter_context(patch.object(generator, "_capture", side_effect=captured))
        stack.enter_context(patch.object(generator, "parse_proof", return_value=SimpleNamespace(
            connection_work_hash=b"\xff" * 32)))
        stack.enter_context(patch.object(generator, "meets_work_target", return_value=met_target))
        return stack.enter_context(patch.object(generator, "verify_connection_proof"))

    def test_rolling_window_is_bounded_with_cumulative_sequence(self):
        recorder = generator._AttemptRecorder()
        for index in range(100000):
            recorder.record(index % 3 == 0, index / 1000000)
        snapshot = recorder.snapshot()
        self.assertEqual(snapshot.completed, 100000)
        self.assertEqual(snapshot.recent, tuple((i % 3 == 0, i / 1000000)
                                               for i in range(99900, 100000)))
        self.assertEqual(len(snapshot.recent), 100)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snapshot.completed = 1
        recorder.record(False, 2.0)
        self.assertEqual(snapshot.completed, 100000)  # Snapshot is detached/immutable.
        self.assertEqual(recorder.snapshot().completed, 100001)

    def test_invalid_durations_are_ignored_and_precision_is_bounded(self):
        recorder = generator._AttemptRecorder()
        for seconds in (float("nan"), float("inf"), float("-inf"), -0.1):
            recorder.record(False, seconds)
        recorder.record(1, 0.1)
        self.assertEqual(recorder.snapshot(), generator.AttemptStats())
        recorder.record(True, 0.123456789)
        recorder.record(False, 0.0)
        self.assertEqual(recorder.snapshot(), generator.AttemptStats(2, ((True, 0.123457), (False, 0.0))))

    def test_completion_order_is_not_start_order(self):
        entered = [threading.Event() for _ in range(3)]
        release = [threading.Event() for _ in range(3)]
        recorded = [threading.Event() for _ in range(3)]

        class ObservedRecorder(generator._AttemptRecorder):
            def record(self, success, seconds):
                super().record(success, seconds)
                recorded[self.snapshot().completed - 1].set()

        recorder = ObservedRecorder()

        def fake_capture(index, *_):
            entered[index].set()
            if not release[index].wait(3):
                raise RuntimeError("test synchronization timeout")
            if index == 2:
                raise OSError("controlled connection failure")
            return capture()

        with patch.object(generator, "_capture", side_effect=fake_capture), patch.object(
                generator, "verify_connection_proof"), ThreadPoolExecutor(3) as executor:
            futures = [executor.submit(generator._capture_observed, i, context(), 1, recorder, "unused")
                       for i in range(3)]
            try:
                self.assertTrue(all(item.wait(3) for item in entered))
                for sequence, index in enumerate((2, 1, 0)):
                    release[index].set()
                    self.assertTrue(recorded[sequence].wait(3))
            finally:
                for item in release: item.set()
            self.assertEqual(futures[0].result().peer_ip, "8.8.8.8")
            self.assertEqual(futures[1].result().peer_ip, "8.8.8.8")
            with self.assertRaises(OSError): futures[2].result()
        stats = recorder.snapshot()
        self.assertEqual(stats.completed, 3)
        self.assertEqual([item[0] for item in stats.recent], [False, True, True])
        self.assertTrue(all(seconds >= 0 for _, seconds in stats.recent))

    def test_duration_measures_only_the_capture_call(self):
        recorder = generator._AttemptRecorder()
        with patch.object(generator.time, "monotonic", side_effect=[100.0, 100.125]), patch.object(
                generator, "_capture", return_value=capture()), patch.object(generator, "verify_connection_proof"):
            generator._capture_observed(None, context(), 10, recorder, "unused")
        self.assertEqual(recorder.snapshot().recent, ((True, 0.125),))

    def test_queued_cancelled_capture_does_not_create_failure(self):
        entered, release = threading.Event(), threading.Event()
        recorder = generator._AttemptRecorder()

        def fake_capture(*_):
            entered.set()
            if not release.wait(3): raise RuntimeError("test synchronization timeout")
            return capture()

        with patch.object(generator, "_capture", side_effect=fake_capture), patch.object(
                generator, "verify_connection_proof"), ThreadPoolExecutor(1) as executor:
            active = executor.submit(generator._capture_observed, None, context(), 1, recorder, "unused")
            self.assertTrue(entered.wait(3))
            queued = executor.submit(generator._capture_observed, None, context(), 1, recorder, "unused")
            try:
                self.assertTrue(queued.cancel())
                self.assertEqual(recorder.snapshot().completed, 0)
            finally:
                release.set()
            active.result(3)
        self.assertEqual(recorder.snapshot().completed, 1)
        self.assertTrue(recorder.snapshot().recent[0][0])

    def test_successful_capture_counts_when_work_target_misses(self):
        updates = []
        with ExitStack() as stack:
            verifier = self.fake_network(stack, [capture(), OSError("TLS failed"), capture()])
            with self.assertRaisesRegex(generator.GenerationError, "no proof met the target"):
                generator.generate_connection_proof(context(), "unused", generator.GenerationOptions(
                    connections_per_second=-1, concurrency=1, max_attempts=3), updates.append)
            self.assertEqual(verifier.call_count, 2)
            self.assertTrue(all(call.args[0].connection_work_target == "f" * 64
                                for call in verifier.call_args_list))
        self.assertEqual(sum(update.finished for update in updates), 1)
        self.assertTrue(updates[-1].finished)
        self.assertEqual(updates[-1].attempts, 3)
        self.assertEqual([item[0] for item in updates[-1].attempt_stats.recent], [True, False, True])
        counts = [item.attempt_stats.completed for item in updates]
        self.assertEqual(counts, sorted(counts))

    def test_invalid_certificate_is_recorded_as_failed_validation(self):
        updates = []
        with ExitStack() as stack:
            verify = self.fake_network(stack, [capture()])
            verify.side_effect = ProofVerificationError("untrusted test certificate")
            with self.assertRaises(generator.GenerationError):
                generator.generate_connection_proof(context(), "unused", generator.GenerationOptions(
                    connections_per_second=-1, concurrency=1, max_attempts=1), updates.append)
        self.assertFalse(updates[-1].attempt_stats.recent[0][0])

    def test_later_target_misses_are_also_cryptographically_verified(self):
        updates = []
        with ExitStack() as stack:
            verifier = self.fake_network(stack, [capture(), capture(), capture()])
            verifier.side_effect = [None, ProofVerificationError("bad CertificateVerify"), None]
            with self.assertRaises(generator.GenerationError):
                generator.generate_connection_proof(context(), "unused", generator.GenerationOptions(
                    connections_per_second=-1, concurrency=1, max_attempts=3), updates.append)
        self.assertEqual(verifier.call_count, 3)
        self.assertEqual([item[0] for item in updates[-1].attempt_stats.recent], [True, False, True])

    def test_final_snapshot_includes_inflight_completion_after_winning_proof(self):
        updates = []
        second_started, release_second = threading.Event(), threading.Event()
        lock = threading.Lock()
        started = 0

        def fake_capture(*_):
            nonlocal started
            with lock:
                started += 1
                index = started
            if index == 1:
                if not second_started.wait(3): raise RuntimeError("test synchronization timeout")
                return capture()
            second_started.set()
            if not release_second.wait(3): raise RuntimeError("test synchronization timeout")
            raise OSError("second attempt completed during winner verification/shutdown")

        with ExitStack() as stack:
            verify = self.fake_network(stack, fake_capture, met_target=True)
            verify.side_effect = lambda *_args, **_kwargs: release_second.set()
            try:
                result = generator.generate_connection_proof(context(), "unused", generator.GenerationOptions(
                    connections_per_second=-1, concurrency=2, max_attempts=2), updates.append)
            finally:
                release_second.set()
        self.assertEqual(result.attempts, 2)
        self.assertTrue(updates[-1].finished)
        self.assertEqual(updates[-1].attempt_stats.completed, 2)
        self.assertEqual([item[0] for item in updates[-1].attempt_stats.recent], [True, False])

    def test_dns_failure_has_final_zero_snapshot_not_failed_tls_attempt(self):
        updates = []
        with patch.object(generator, "validate_root_bundle"), patch.object(generator, "resolve_endpoints",
                side_effect=generator.GenerationError("DNS failed")), patch.object(generator, "_capture") as captured:
            with self.assertRaisesRegex(generator.GenerationError, "DNS failed"):
                generator.generate_connection_proof(context(), "unused", progress=updates.append)
        captured.assert_not_called()
        self.assertEqual(len(updates), 1)
        self.assertTrue(updates[0].finished)
        self.assertEqual(updates[0].attempt_stats, generator.AttemptStats())

    def test_inflight_capture_after_winning_proof_still_verifies_and_records_once(self):
        updates = []
        second_started, winner_selected = threading.Event(), threading.Event()
        lock = threading.Lock()
        started = 0

        def capture_inflight(*_):
            nonlocal started
            with lock:
                started += 1
                index = started
            if index == 1:
                if not second_started.wait(3): raise RuntimeError("second capture did not start")
                return capture()
            second_started.set()
            if not winner_selected.wait(3): raise RuntimeError("winning proof was not selected")
            return SimpleNamespace(encoded_proof=b"invalid signature", peer_ip="8.8.8.8")

        def verify(candidate, *_args, **_kwargs):
            if candidate.proof == b"invalid signature":
                raise ProofVerificationError("invalid CertificateVerify")

        with ExitStack() as stack:
            verifier = self.fake_network(stack, capture_inflight, met_target=True)
            verifier.side_effect = verify
            stack.enter_context(patch.object(generator, "meets_work_target",
                side_effect=lambda *_: winner_selected.set() or True))
            try:
                result = generator.generate_connection_proof(context(), "unused", generator.GenerationOptions(
                    connections_per_second=-1, concurrency=2, max_attempts=2), updates.append)
            finally:
                winner_selected.set()
        self.assertEqual(verifier.call_count, 2)
        self.assertEqual(result.attempts, 2)
        self.assertEqual([item[0] for item in updates[-1].attempt_stats.recent], [True, False])
        self.assertEqual(updates[-1].attempt_stats.completed, 2)

    def test_bridge_final_stats_precede_result_or_verification_error(self):
        for succeeds in (True, False):
            with self.subTest(succeeds=succeeds), ExitStack() as stack:
                self.fake_network(stack, [capture()], met_target=True)
                request_context = dataclasses.asdict(context())
                del request_context["proof"]
                request_context = {key: request_context[key] for key in claims_bridge.CONTEXT_KEYS}
                request = {"context": request_context, "options": {"connectionsPerSecond": 100,
                    "concurrency": 1, "overallTimeout": 1, "maxAttempts": 1}}
                stack.enter_context(patch.object(sys, "argv", ["claims_bridge.py"]))
                stack.enter_context(patch.object(sys, "stdin", SimpleNamespace(
                    buffer=io.BytesIO(json.dumps(request).encode() + b"\n"))))
                emitted = stack.enter_context(patch.object(claims_bridge, "emit"))
                verifier = stack.enter_context(patch.object(claims_bridge, "verify_connection_proof",
                    return_value=generator.AttemptStats()))
                if succeeds:
                    self.assertEqual(claims_bridge.main(), 0)
                else:
                    verifier.side_effect = ProofVerificationError("independent verification failed")
                    with self.assertRaises(ProofVerificationError): claims_bridge.main()
                frames = [call.args[0] for call in emitted.call_args_list]
                self.assertEqual(frames[0]["type"], "progress")
                self.assertEqual(frames[0]["attemptStats"]["completed"], 1)
                self.assertTrue(frames[0]["attemptStats"]["recent"][0][0])
                self.assertEqual([frame["type"] for frame in frames],
                                 ["progress", "result"] if succeeds else ["progress"])

    def test_once_per_second_and_forced_final_snapshot_even_without_new_completion(self):
        stats = generator.AttemptStats(1, ((True, 0.25),))
        reporter = claims_bridge.ProgressReporter()
        with patch.object(claims_bridge, "emit") as emit, patch.object(claims_bridge.time, "monotonic",
                side_effect=[5, 5.1, 5.9, 6, 6.01]):
            for _ in range(4): reporter(progress(stats))
            reporter(progress(stats, finished=True))
            reporter(progress(stats, finished=True))  # Does not consume clock/emit twice.
        self.assertEqual(emit.call_count, 3)
        for call in emit.call_args_list:
            frame = json.loads(json.dumps(call.args[0]))
            self.assertEqual(frame["attempts"], frame["attemptStats"]["completed"])
            self.assertEqual(frame["attemptStats"]["validation"], "certificate-proof-v1")
            self.assertEqual(frame["attemptStats"]["recent"], [[True, 0.25]])

    def test_one_hundred_thousand_attempts_cannot_expand_progress_payload(self):
        recorder = generator._AttemptRecorder()
        reporter = claims_bridge.ProgressReporter()
        now = 0.0
        stream = io.StringIO()
        with patch.object(claims_bridge.time, "monotonic", side_effect=lambda: now), patch.object(sys, "stdout", stream):
            for index in range(100000):
                now = index * 0.006  # Longest permitted bridge run, <=600 seconds.
                recorder.record(index % 2 == 0, 3599.999999)
                reporter(progress(recorder.snapshot(), elapsed=now))
            reporter(progress(recorder.snapshot(), finished=True, elapsed=now))
        data = stream.getvalue()
        frames = [json.loads(line) for line in data.splitlines()]
        self.assertLessEqual(len(frames), 602)
        self.assertLess(len(data.encode()), 4 * 1024 * 1024 - 150000)
        self.assertTrue(all(len(line.encode()) < 4096 for line in data.splitlines()))
        self.assertEqual(frames[-1]["attemptStats"]["completed"], 100000)
        self.assertTrue(all(len(frame["attemptStats"]["recent"]) == min(100, frame["attempts"])
                            for frame in frames))


if __name__ == "__main__":
    unittest.main()
