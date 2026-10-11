"""Encoded NDJSON output and capture bookkeeping under blocked IPC."""

from __future__ import annotations

import io
import json
import threading
import time
import unittest
from unittest.mock import patch

from test_claims_service import Fixture, fake_capture, service, claims_bridge


class EncodedOutputTests(unittest.TestCase):
    def test_broken_pipe_releases_writer_lock_and_does_not_retry_frame(self):
        with Fixture() as h:
            calls = []

            def broken_writer(encoded):
                calls.append(encoded)
                raise BrokenPipeError("test pipe closed")

            h.service.emit_callback = broken_writer
            with self.assertRaises(BrokenPipeError):
                h.service.emit({"type": "test", "id": 1})
            self.assertEqual(len(calls), 1)
            self.assertTrue(h.service.output_lock.acquire(blocking=False))
            h.service.output_lock.release()
            received = []
            h.service.emit_callback = received.append
            h.service.emit({"type": "test", "id": 2})
            self.assertEqual([json.loads(frame)["id"] for frame in received], [2])

    def test_production_service_bridge_boundary_serializes_exactly_once(self):
        output = io.StringIO()
        value = {"type": "capture", "id": 1, "unicode": "\u00e7\u2603", "escaped": "first\nsecond"}
        with Fixture() as h:
            h.service.emit_callback = claims_bridge.emit_encoded
            with patch.object(claims_bridge.sys, "stdout", output), \
                 patch.object(service.json, "dumps", wraps=json.dumps) as dumps:
                h.service.emit(value)
            dumps.assert_called_once_with(value, separators=(",", ":"), allow_nan=False)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertTrue(output.getvalue().endswith("\n"))
        self.assertEqual(json.loads(output.getvalue()), value)

    def test_legacy_dict_bridge_still_serializes_one_valid_ndjson_frame(self):
        output = io.StringIO()
        value = {"ok": True, "message": "one\ntwo"}
        with patch.object(claims_bridge.sys, "stdout", output), \
             patch.object(claims_bridge.json, "dumps", wraps=json.dumps) as dumps:
            claims_bridge.emit(value)
        self.assertEqual(dumps.call_count, 1)
        self.assertEqual(json.loads(output.getvalue()), value)
        self.assertEqual(output.getvalue().count("\n"), 1)

    def test_invalid_numbers_and_oversized_frames_never_reach_writer(self):
        limit = 160 * 1024
        with Fixture() as h:
            received = []
            h.service.emit_callback = received.append
            for number in (float("nan"), float("inf"), -float("inf")):
                with self.subTest(number=number), self.assertRaises(ValueError):
                    h.service.emit({"value": number})
            self.assertEqual(received, [])
            # The limit applies to the complete encoded UTF-8 frame, not just
            # its payload, and excludes the NDJSON newline added by the bridge.
            overhead = len(json.dumps({"value": ""}, separators=(",", ":")).encode("utf-8"))
            h.service.emit({"value": "x" * (limit - overhead)})
            self.assertEqual(len(received[0].encode("utf-8")), limit)
            with self.assertRaises(ValueError):
                h.service.emit({"value": "x" * (limit - overhead + 1)})
            self.assertEqual(len(received), 1)
            with self.assertRaises(ValueError):
                h.service.emit({"value": "\u2603" * limit})
            self.assertEqual(len(received), 1)

    def test_concurrent_frames_are_atomic_even_with_fragmented_writes(self):
        class FragmentingStream:
            def __init__(self):
                self.parts = []
                self.flushes = 0

            def write(self, value):
                midpoint = len(value) // 2
                self.parts.append(value[:midpoint])
                time.sleep(0)
                self.parts.append(value[midpoint:])

            def flush(self):
                self.flushes += 1
                time.sleep(0)

        output = FragmentingStream()
        barrier = threading.Barrier(12)
        failures = []
        with Fixture() as h:
            h.service.emit_callback = claims_bridge.emit_encoded

            def writer(index):
                try:
                    barrier.wait(3)
                    for sequence in range(20):
                        h.service.emit({"type": "test", "worker": index, "sequence": sequence,
                                        "payload": "\u2603\n" * 16})
                except BaseException as error:
                    failures.append(error)

            workers = [threading.Thread(target=writer, args=(index,)) for index in range(12)]
            with patch.object(claims_bridge.sys, "stdout", output):
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join(5)
            self.assertFalse(any(worker.is_alive() for worker in workers))
            self.assertEqual(failures, [])
        frames = [json.loads(line) for line in "".join(output.parts).splitlines()]
        self.assertEqual(len(frames), 240)
        self.assertEqual(output.flushes, 240)
        self.assertEqual({(frame["worker"], frame["sequence"]) for frame in frames},
                         {(index, sequence) for index in range(12) for sequence in range(20)})
        for index in range(12):
            self.assertEqual([frame["sequence"] for frame in frames if frame["worker"] == index], list(range(20)))


class CaptureBookkeepingTests(unittest.TestCase):
    def test_blocked_capture_writer_does_not_block_other_capture_counters_or_cancel(self):
        barrier = threading.Barrier(2)
        entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()
        with Fixture(connectionsPerSecond=1000, concurrency=2) as h:
            h.resolve_domain()
            original_emit = h.service.emit_callback
            blocked_id = []

            def capture(*args, **kwargs):
                result = fake_capture(*args, **kwargs)
                barrier.wait(3)  # Both TCP starts precede the blocked capture.
                return result

            def blocked_emit(encoded):
                frame = json.loads(encoded)
                if frame["type"] == "capture" and not entered.is_set():
                    blocked_id.append(frame["id"])
                    entered.set()
                    if not release.wait(5):
                        raise AssertionError("blocked writer release timed out")
                original_emit(encoded)

            h.capture.side_effect = capture
            h.service.emit_callback = blocked_emit
            h.attempt(2, connection_work_target="00" * 32)
            h.attempt(3, connection_work_target="00" * 32)
            cancel_worker = None
            try:
                self.assertTrue(entered.wait(3))
                # A worker waiting for stdout must release bookkeeping locks:
                # the other completed capture can count before either is sent.
                deadline = time.monotonic() + 2
                observed = None
                while time.monotonic() < deadline:
                    acquired = h.service.condition.acquire(timeout=0.05)
                    if acquired:
                        try:
                            observed = (h.service.budgets[f"{1:064x}:0"].successes,
                                        sorted(job.successful_connections or 0 for job in h.service.jobs.values()))
                        finally:
                            h.service.condition.release()
                        if observed == (2, [1, 2]):
                            break
                    time.sleep(0.001)
                self.assertEqual(observed, (2, [1, 2]))

                def cancel():
                    h.service.command({"type": "cancel", "id": blocked_id[0]})
                    cancelled.set()

                cancel_worker = threading.Thread(target=cancel)
                cancel_worker.start()
                self.assertTrue(cancelled.wait(1), "cancellation is waiting on blocked IPC")
            finally:
                release.set()
                if cancel_worker is not None:
                    cancel_worker.join(3)
            captures = {identifier: h.wait("capture", identifier) for identifier in (2, 3)}
            terminals = {identifier: h.wait("attempt", identifier) for identifier in (2, 3)}
            self.assertEqual({frame["successfulConnections"] for frame in captures.values()}, {"1", "2"})
            for identifier in (2, 3):
                self.assertEqual(terminals[identifier]["successfulConnections"], captures[identifier]["successfulConnections"])
                self.assertEqual(terminals[identifier]["seconds"], captures[identifier]["seconds"])
                self.assertEqual([frame["type"] for frame in h.frames if frame.get("id") == identifier],
                                 ["started", "capture", "attempt"])
            self.assertTrue(terminals[blocked_id[0]]["cancelled"])
            self.assertIsNone(terminals[blocked_id[0]]["validationPassed"])
            h.verify.assert_called_once()  # Only the non-cancelled capture is verified.

    def test_reordered_capture_frames_keep_per_attempt_snapshots_and_terminal_order(self):
        entered, release = threading.Event(), threading.Event()
        with Fixture(connectionsPerSecond=1000, concurrency=2) as h:
            h.resolve_domain()
            original_emit = h.service.emit

            def delayed_emit(frame):
                if frame["type"] == "capture" and frame["id"] == 2:
                    entered.set()
                    if not release.wait(5):
                        raise AssertionError("first capture release timed out")
                original_emit(frame)

            h.service.emit = delayed_emit
            h.attempt(2, connection_work_target="00" * 32)
            try:
                self.assertTrue(entered.wait(3))
                h.attempt(3, connection_work_target="00" * 32)
                self.assertEqual(h.wait("capture", 3)["successfulConnections"], "2")
                self.assertEqual(h.wait("attempt", 3)["successfulConnections"], "2")
            finally:
                release.set()
            self.assertEqual(h.wait("capture", 2)["successfulConnections"], "1")
            self.assertEqual(h.wait("attempt", 2)["successfulConnections"], "1")
            self.assertEqual([frame["id"] for frame in h.frames if frame["type"] == "capture"], [3, 2])
            self.assertEqual(h.service.budgets[f"{1:064x}:0"].successes, 2)
            self.assertEqual(h.verify.call_count, 2)
            self.assertEqual(h.meets.call_count, 2)

    def test_simultaneous_captures_saturate_uint64_without_losing_snapshots(self):
        barrier = threading.Barrier(2)
        with Fixture(connectionsPerSecond=1000, concurrency=2) as h:
            h.resolve_domain()

            def capture(*args, **kwargs):
                result = fake_capture(*args, **kwargs)
                barrier.wait(3)
                return result

            h.capture.side_effect = capture
            for identifier in (2, 3):
                h.attempt(identifier, successes=str(service.MAX_UINT64 - 1), connection_work_target="00" * 32)
            for identifier in (2, 3):
                capture_frame = h.wait("capture", identifier)
                terminal = h.wait("attempt", identifier)
                self.assertEqual(capture_frame["successfulConnections"], str(service.MAX_UINT64))
                self.assertEqual(terminal["successfulConnections"], capture_frame["successfulConnections"])
                self.assertTrue(terminal["validationPassed"])
            self.assertEqual(h.service.budgets[f"{1:064x}:0"].successes, service.MAX_UINT64)
            self.assertEqual(h.verify.call_count, 2)


if __name__ == "__main__":
    unittest.main()
