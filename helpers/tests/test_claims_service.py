"""Persistent protocol-4 tests: validated outcomes and loopback cancellation."""

from __future__ import annotations

import io
import json
import math
import socket
import sys
import threading
import time
import unittest
from dataclasses import replace
from contextlib import ExitStack
from pathlib import Path
from time import monotonic as fixture_clock
from types import SimpleNamespace
from unittest.mock import patch

HELPERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPERS))
import claims_bridge
import claims_service as service
from connectcoin_p2c_tools.errors import ProofVerificationError
from connectcoin_p2c_tools.protocol import parse_proof
from connectcoin_p2c_tools.tls13 import CaptureCancelled, CaptureControl, Endpoint, TLSGenerationError, capture_tls13_proof
from test_verifier_security import certificate, signed_proof, verify_fixture


def public_context(**changes):
    return {"domain": "example.com", "txid": "01" * 32, "input_index": 0,
            "connection_work_target": "ff" * 32, "root_certificates_version": 1,
            "signature_algorithms_mask": 1, "validation_time": 1800000000, **changes}


def endpoint(ip="8.8.8.8"):
    return Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, (ip, 443), ip)


def fake_capture(_endpoint, _domain, _challenge, *, control, before_start, on_started, on_connecting=None, **_):
    with control:
        before_start()
        control.begin(SimpleNamespace(shutdown=lambda *_: None, close=lambda: None), on_started)
        if on_connecting is not None: on_connecting()
        return SimpleNamespace(encoded_proof=b"\x02\x01", peer_ip=_endpoint.ip)


class Fixture:
    def __init__(self, **options):
        self.options = {"connectionsPerSecond": 256, "concurrency": 2, **options}
        self.frames = []
        self.condition = threading.Condition()
        self.stack = ExitStack()

    def __enter__(self):
        self.resolve = self.stack.enter_context(patch.object(service, "resolve_endpoints", return_value=(endpoint(),)))
        self.capture = self.stack.enter_context(patch.object(service, "capture_tls13_proof", side_effect=fake_capture))
        self.parse = self.stack.enter_context(patch.object(service, "parse_proof", return_value=SimpleNamespace(connection_work_hash=b"\x00" * 32)))
        self.meets = self.stack.enter_context(patch.object(service, "meets_work_target", return_value=True))
        self.verify = self.stack.enter_context(patch.object(service, "verify_connection_proof"))
        self.service = service.ClaimsService(self.options, self.emit, claims_bridge.parse_context, HELPERS / "p2c_roots_v1.pem")
        return self

    def emit(self, frame):
        with self.condition:
            self.frames.append(frame)
            self.condition.notify_all()

    def wait(self, kind, identifier, timeout=4):
        # Service clock patches simulate network/IPC time, not the harness's
        # real deadline for waiting on another thread's protocol frames.
        deadline = fixture_clock() + timeout
        with self.condition:
            while True:
                found = next((frame for frame in self.frames if frame["type"] == kind and frame.get("id") == identifier), None)
                if found is not None: return found
                remaining = deadline - fixture_clock()
                if remaining <= 0: raise AssertionError(f"Missing {kind} frame for request {identifier}")
                self.condition.wait(remaining)

    def resolve_domain(self, identifier=1, domain="example.com"):
        self.service.command({"type": "resolve", "id": identifier, "domain": domain})
        return self.wait("resolved", identifier)

    def attempt(self, identifier, *, bounty=1, successes="0", **context):
        self.service.command({"type": "attempt", "id": identifier, "context": public_context(**context),
            "bountyId": f"{bounty:064x}:0", "successfulConnections": successes})

    def __exit__(self, *_):
        self.service.close()
        self.service.executor.shutdown(wait=True)
        self.stack.close()


class FixtureTests(unittest.TestCase):
    def test_intermediate_frames_and_simulated_time_jumps_do_not_expire_real_wait(self):
        h = Fixture()
        clock = [100.0]
        notifications = iter(((11.0, {"type": "capture", "id": 2}),
                              (20.0, {"type": "attempt", "id": 2})))
        def notified_wait(remaining):
            self.assertGreater(remaining, 0)
            self.assertLessEqual(remaining, 4)
            advance, frame = next(notifications)
            clock[0] += advance
            h.emit(frame)
        # Force the capture notification to wake the waiter before the terminal
        # frame. The former shared clock expired here after the first jump.
        with patch.object(service.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(h.condition, "wait", side_effect=notified_wait) as wait:
            self.assertEqual(h.wait("attempt", 2), {"type": "attempt", "id": 2})
        self.assertEqual(wait.call_count, 2)
        self.assertEqual(clock[0], 131.0)


class PacingClock:
    """Deterministic local waits; no socket or real sleeping is involved."""
    def __init__(self, quantum=0.0):
        self.now = 100.0
        self.quantum = quantum
        self.sleeps = []
        self.reads = 0
        self.jumps = {}
        self.on_sleep = None

    def monotonic(self):
        self.reads += 1
        self.now += self.jumps.pop(self.reads, 0.0)
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        step = max(seconds, math.ulp(self.now))
        if self.quantum:
            step = math.ceil(step / self.quantum) * self.quantum
        self.now += step
        if self.on_sleep is not None:
            self.on_sleep()

    def __enter__(self):
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(service.time, "monotonic", side_effect=self.monotonic))
        self.stack.enter_context(patch.object(service.time, "sleep", side_effect=self.sleep))
        return self

    def __exit__(self, *_):
        self.stack.close()


class PacingTests(unittest.TestCase):
    RATES = (1, 7, 10, 50, 100, 256, 400, 1000)

    def job(self, helper, identifier=1, domain="example.com"):
        helper.budgets.setdefault("fixture", service.Budget(0, 0))
        return service.Job(identifier, "attempt", domain=domain, bounty_id="fixture")

    def test_single_gate_uses_the_configured_interval_and_only_sleeps_the_remainder(self):
        for rate in self.RATES:
            with self.subTest(rate=rate), Fixture(connectionsPerSecond=rate) as h, PacingClock() as clock:
                h.service._connecting(self.job(h.service))
                deadline = 100.0 + 1.0 / rate
                self.assertAlmostEqual(h.service.next_connection, deadline, places=12)
                clock.now += 0.4 / rate
                began_wait = clock.now
                job = self.job(h.service, 2)
                h.service._before_start(job)
                self.assertEqual(clock.sleeps, [])
                self.assertFalse(job.started)
                h.service._connecting(job)
                self.assertAlmostEqual(clock.now, deadline, places=10)
                self.assertAlmostEqual(sum(clock.sleeps), deadline - began_wait, places=10)
                self.assertTrue(all(0 < delay <= 0.010 for delay in clock.sleeps))
                self.assertEqual([frame["id"] for frame in h.frames if frame["type"] == "started"], [1, 2])

    def test_coarse_timer_wakes_recover_without_compounding_delay(self):
        with Fixture(connectionsPerSecond=100) as h, PacingClock(quantum=0.015625) as clock:
            starts = []
            for index in range(1001):
                job = self.job(h.service, index, "other.example" if index % 2 else "example.com")
                h.service._before_start(job)
                h.service._connecting(job)
                starts.append(job.started_at)
            self.assertAlmostEqual(h.service.next_connection, 110.01, places=9)
            self.assertGreaterEqual(starts[-1] - starts[0], 10.0 - 1e-8)
            self.assertLessEqual(starts[-1] - starts[0], 10.0 + clock.quantum)
            self.assertTrue(any(right == left for left, right in zip(starts, starts[1:])))

    def test_one_second_debt_cap_is_applied_after_advancing_phase(self):
        for rate in self.RATES:
            interval = 1.0 / rate
            for extra in (0.0, interval - 1e-9, interval, interval + 1e-9, 5.0):
                with self.subTest(rate=rate, extra=extra), Fixture(connectionsPerSecond=rate) as h, PacingClock() as clock:
                    h.service._connecting(self.job(h.service))
                    previous = h.service.next_connection
                    clock.now = previous + 1.0 + extra
                    h.service._connecting(self.job(h.service, 2))
                    self.assertAlmostEqual(h.service.next_connection,
                                           max(previous + interval, clock.now - 1.0), places=11)

    def test_phase_uses_fresh_time_after_start_report_and_excludes_ipc_duration(self):
        for rate in self.RATES:
            for idle in (False, True):
                with self.subTest(rate=rate, idle=idle), Fixture(connectionsPerSecond=rate) as h, PacingClock() as clock:
                    if not idle:
                        h.service._connecting(self.job(h.service))
                        clock.now = h.service.next_connection
                    before = clock.now
                    emit = h.service.emit_callback
                    def delayed_emit(frame):
                        if frame["type"] == "started": clock.now += 3.0
                        emit(frame)
                    h.service.emit_callback = delayed_emit
                    job = self.job(h.service, 2)
                    h.service._connecting(job)
                    self.assertEqual(job.started_at, before + 3.0)
                    self.assertAlmostEqual(h.service.next_connection,
                                           clock.now + 1.0 / rate if idle else clock.now - 1.0, places=11)

    def test_delayed_acknowledgements_do_not_add_a_second_rate_interval(self):
        for rate in self.RATES:
            with self.subTest(rate=rate), Fixture(connectionsPerSecond=rate) as h, PacingClock() as clock:
                h.service._connecting(self.job(h.service))
                clock.now = h.service.next_connection
                emit = h.service.emit_callback
                def delayed_emit(frame):
                    if frame["type"] == "started": clock.now += 1.5 / rate
                    emit(frame)
                h.service.emit_callback = delayed_emit
                starts = []
                for identifier in range(2, 6):
                    job = self.job(h.service, identifier)
                    h.service._before_start(job)
                    h.service._connecting(job)
                    starts.append(job.started_at)
                self.assertEqual(clock.sleeps, [])
                for left, right in zip(starts, starts[1:]):
                    self.assertAlmostEqual(right - left, 1.5 / rate, places=11)

    def test_catch_up_has_no_separate_rolling_one_second_quota(self):
        for rate in self.RATES:
            with self.subTest(rate=rate), Fixture(connectionsPerSecond=rate) as h, PacingClock() as clock:
                h.service._connecting(self.job(h.service))
                clock.now += 5.0
                starts = []
                for identifier in range(2 * rate + 3):
                    job = self.job(h.service, identifier + 2)
                    h.service._connecting(job)
                    starts.append(job.started_at)
                    self.assertGreaterEqual(h.service.next_connection, clock.now - 1.0)
                # Core's bounded lateness can admit more than rate permits in a
                # rolling second after preemption, but debt never exceeds one second.
                self.assertGreater(sum(then < starts[0] + 1.0 for then in starts), rate)
                self.assertTrue(clock.sleeps)

    def test_cancellation_and_stop_while_waiting_do_not_spend_a_start(self):
        for stop in (False, True):
            with self.subTest(stop=stop), Fixture(connectionsPerSecond=10) as h, PacingClock() as clock:
                h.service._connecting(self.job(h.service))
                deadline = h.service.next_connection
                job = self.job(h.service, 2)
                clock.on_sleep = h.service.close if stop else job.control.cancel
                with self.assertRaises(CaptureCancelled): h.service._connecting(job)
                self.assertEqual(h.service.next_connection, deadline)
                self.assertFalse(job.started)
                self.assertEqual(len(h.frames), 1)

    def test_budget_exhausted_during_rate_wait_does_not_advance_phase_or_ack(self):
        with Fixture(connectionsPerSecond=100) as h, PacingClock() as clock:
            h.service._connecting(self.job(h.service))
            deadline = h.service.next_connection
            clock.on_sleep = lambda: setattr(h.service.budgets["fixture"], "successes", service.MAX_UINT64)
            with self.assertRaises(service.BudgetExhausted): h.service._connecting(self.job(h.service, 2))
            self.assertEqual(h.service.next_connection, deadline)
            self.assertEqual(len(h.frames), 1)

    def test_live_capacity_demand_keeps_phase_but_cancelled_only_jobs_do_not_bridge_idle(self):
        with patch.object(service.ClaimsService, "_schedule"), Fixture(connectionsPerSecond=10, concurrency=1) as h, PacingClock() as clock:
            def admit(identifier):
                h.attempt(identifier, bounty=identifier, connection_work_target="00" * 32)
                job = h.service.jobs[identifier]
                h.service.pending.remove(job)
                job.running = True
                h.service._before_start(job); h.service._connecting(job)
                return job
            first = admit(1)
            h.service.active_tls = 1
            clock.now += 5.0
            second = admit(2)
            self.assertAlmostEqual(h.service.next_connection, clock.now - 1.0)
            h.service._cancel(first); h.service._cancel(second)
            third = admit(3)
            self.assertAlmostEqual(h.service.next_connection, third.started_at + 0.1)

    def test_idle_preserves_a_future_deadline(self):
        with patch.object(service.ClaimsService, "_schedule"), Fixture(connectionsPerSecond=1) as h, PacingClock() as clock:
            h.attempt(1, connection_work_target="00" * 32)
            first = h.service.jobs[1]; h.service.pending.remove(first); first.running = True
            h.service._before_start(first); h.service._connecting(first)
            h.service._cancel(first)
            clock.now += 0.2
            h.attempt(2, connection_work_target="00" * 32)
            second = h.service.jobs[2]; h.service.pending.remove(second); second.running = True
            h.service._before_start(second); h.service._connecting(second)
            self.assertAlmostEqual(second.started_at, 101.0, places=10)
            self.assertAlmostEqual(h.service.next_connection, 102.0, places=10)

    def test_low_rate_high_concurrency_keeps_ack_behind_the_socket_gate(self):
        with Fixture(connectionsPerSecond=1, concurrency=1000) as h, PacingClock() as clock:
            h.service._connecting(self.job(h.service))
            job = self.job(h.service, 2)
            h.service._before_start(job)
            self.assertFalse(job.started)
            def while_waiting():
                self.assertFalse(job.started)
                self.assertEqual(len(h.frames), 1)
            clock.on_sleep = while_waiting
            h.service._connecting(job)
            self.assertAlmostEqual(job.started_at, 101.0, places=10)
            self.assertEqual([frame["id"] for frame in h.frames], [1, 2])

    def test_cancellation_while_another_start_report_holds_gate_is_responsive(self):
        with Fixture(connectionsPerSecond=100) as h:
            job = self.job(h.service)
            h.service.connection_lock.acquire()
            done = threading.Event()
            outcome = []
            def connect():
                try:
                    h.service._connecting(job)
                except CaptureCancelled:
                    outcome.append("cancelled")
                finally:
                    done.set()
            worker = threading.Thread(target=connect)
            worker.start()
            try:
                job.control.cancel()
                self.assertTrue(done.wait(1))
                self.assertEqual(outcome, ["cancelled"])
                self.assertFalse(job.started)
                self.assertEqual(h.frames, [])
            finally:
                h.service.connection_lock.release()
                worker.join(1)


class ServiceTests(unittest.TestCase):
    def test_positive_int32_options_above_256_are_lazy(self):
        for value in (257, 400, 1000, 2147483647):
            with self.subTest(value=value), Fixture(connectionsPerSecond=value, concurrency=value) as h:
                self.assertEqual(h.service.rate, value)
                self.assertEqual(h.service.concurrency, value)
                self.assertEqual(h.service.max_pending, max(512, value + 2))
                self.assertEqual(len(h.service.executor._threads), 0)
                self.assertEqual(h.service.jobs, {})
                self.assertEqual(h.capture.call_count, 0)

    def test_option_limits_reject_nonpositive_fractional_boolean_and_above_int32(self):
        for key in ("connectionsPerSecond", "concurrency"):
            for value in (0, -1, True, False, 1.5, "1000", float("inf"), 2147483648):
                options = {"connectionsPerSecond": 1, "concurrency": 1, key: value}
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    service.ClaimsService(options, lambda _: None, claims_bridge.parse_context, HELPERS / "p2c_roots_v1.pem")

    def test_configured_1000_requests_and_two_dns_slots_do_not_hit_legacy_512_limit(self):
        with patch.object(service.ClaimsService, "_schedule"), Fixture(concurrency=1000) as h:
            for identifier in range(1, 1001):
                h.attempt(identifier, connection_work_target="00" * 32)
            for identifier in (1001, 1002):
                h.service.command({"type": "resolve", "id": identifier, "domain": "example.com"})
            self.assertEqual(len(h.service.jobs), 1002)
            self.assertEqual(len(h.service.executor._threads), 0)
            with self.assertRaisesRegex(ValueError, "pending request"):
                h.attempt(1003, connection_work_target="00" * 32)
            h.service.command({"type": "cancel", "id": 500})
            self.assertTrue(h.wait("attempt", 500)["cancelled"])
            h.attempt(1003, connection_work_target="00" * 32)
            self.assertEqual(len(h.service.jobs), 1002)
            self.assertEqual(h.capture.call_count, 0)

    def test_worker_creation_exhaustion_emits_error_and_cancels_without_dead_scheduler(self):
        for error in (RuntimeError("cannot start new thread"), MemoryError()):
            with self.subTest(error=type(error).__name__), Fixture(concurrency=1000) as h:
                h.resolve_domain()
                with patch.object(h.service.executor, "submit", side_effect=error):
                    h.attempt(2)
                    failure = h.wait("error", None)
                    h.service.scheduler.join(1)
                self.assertFalse(h.service.scheduler.is_alive())
                self.assertTrue(h.service.closed)
                self.assertEqual(failure["message"], "Claims helper could not create a connection worker")
                self.assertTrue(all(job.control.cancelled() for job in h.service.jobs.values()))
                self.assertEqual(h.capture.call_count, 0)

    def test_failed_thread_growth_cancels_even_the_job_enqueued_before_submit_raised(self):
        entered = threading.Event()
        with Fixture(concurrency=1000) as h:
            h.resolve_domain()
            def blocked_capture(*args, **kwargs):
                fake_capture(*args, **kwargs)
                entered.set()
                kwargs["control"]._event.wait(3)
                raise CaptureCancelled("cancelled")
            h.capture.side_effect = blocked_capture
            h.attempt(2, connection_work_target="00" * 32)
            self.assertTrue(entered.wait(1))
            # Real ThreadPoolExecutor.submit enqueues before growing its pool;
            # failure must never cause a duplicate retry or an orphaned job.
            with patch.object(threading.Thread, "start", side_effect=RuntimeError("cannot start new thread")):
                h.attempt(3, connection_work_target="00" * 32)
                h.wait("error", None)
                h.service.scheduler.join(1)
            self.assertTrue(h.wait("attempt", 2)["cancelled"])
            queued = h.wait("attempt", 3)
            self.assertTrue(queued["cancelled"])
            self.assertFalse(queued["started"])
            h.service.executor.shutdown(wait=True)
            self.assertEqual(h.capture.call_count, 1)
            self.assertEqual(h.service.jobs, {})
            self.assertEqual(h.service.active_tls, 0)
            self.assertTrue(all(budget.users == 0 for budget in h.service.budgets.values()))

    def test_protocol_start_frame_and_clean_shutdown(self):
        frames = []
        payload = [{"type": "start", "protocol": 4, "options": {"connectionsPerSecond": 100, "concurrency": 100}}, {"type": "shutdown"}]
        stream = io.BytesIO(b"".join(json.dumps(frame).encode() + b"\n" for frame in payload))
        self.assertEqual(service.run_service(stream, frames.append, claims_bridge.parse_context, HELPERS / "p2c_roots_v1.pem"), 0)
        self.assertEqual(frames, [{"type": "ready", "protocol": 4, "roots": 1,
                                   "security": {"rsaPublicExponentMaxBits": 64}}])

    def test_earlier_protocols_are_rejected_before_creating_service(self):
        for protocol in (1, 2, 3, True, "4"):
            with self.subTest(protocol=protocol), patch.object(service, "ClaimsService") as constructor:
                frame = {"type": "start", "protocol": protocol, "options": {}}
                with self.assertRaisesRegex(ValueError, "protocol 4"):
                    service.run_service(io.BytesIO(json.dumps(frame).encode() + b"\n"),
                                        lambda _: None, claims_bridge.parse_context, "unused")
                constructor.assert_not_called()

    def test_frames_options_and_secret_fields_fail_closed(self):
        for raw in (b"{}", b"x" * 16385 + b"\n", b'{"x":NaN}\n', b'{"x":Infinity}\n', b'{"type":"cancel","type":"attempt"}\n'):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError): service.read_frame(io.BytesIO(raw))
        self.assertIsNone(service.read_frame(io.BytesIO()))
        for options in ({"connectionsPerSecond": 0, "concurrency": 1}, {"connectionsPerSecond": 1, "concurrency": 2147483648},
                        {"connectionsPerSecond": True, "concurrency": 1}, {"connectionsPerSecond": 1, "concurrency": 1, "maxAttempts": 1000}):
            with self.assertRaises(ValueError): service.ClaimsService(options, lambda _: None, claims_bridge.parse_context, HELPERS / "p2c_roots_v1.pem")
        with Fixture() as h:
            for changes in ({"privateKey": "secret"}, {"domain": "wallet.local"}, {"root_certificates_version": 2}, {"validation_time": 253402300800}):
                with self.assertRaises(ValueError): h.attempt(1, **changes)

    def test_request_ids_and_budget_seeds_are_strict(self):
        with Fixture() as h:
            h.resolve_domain()
            for identifier in (True, 0, -1, 1, (1 << 53), "2"):
                with self.assertRaises(ValueError): h.service.command({"type": "resolve", "id": identifier, "domain": "example.com"})
            for successes in ("-1", "1\n", "01", "", str(1 << 64), 0, True):
                with self.assertRaises(ValueError): h.attempt(2, successes=successes)
            h.attempt(2)
            h.wait("attempt", 2)
            with self.assertRaises(ValueError): h.attempt(3, connection_work_target="7f" + "ff" * 31)

    def test_verified_proof_has_started_capture_then_single_terminal(self):
        with Fixture() as h:
            self.assertTrue(h.resolve_domain()["ok"])
            h.attempt(2)
            result = h.wait("attempt", 2)
            self.assertEqual([frame["type"] for frame in h.frames if frame.get("id") == 2], ["started", "capture", "attempt"])
            self.assertEqual(result["context"], public_context())
            self.assertTrue(result["started"] and result["captured"] and result["verified"])
            self.assertIs(result["validationPassed"], True)
            self.assertEqual(result["proof"], "0201")
            self.assertEqual(result["successfulConnections"], "1")
            self.assertFalse(result["cancelled"])
            self.assertGreaterEqual(result["seconds"], 0)

    def test_hash_miss_and_invalid_certificate_still_count_capture_success(self):
        for reason in ("work", "certificate"):
            with self.subTest(reason=reason), Fixture() as h:
                h.resolve_domain()
                if reason == "work": h.meets.return_value = False
                else: h.verify.side_effect = ProofVerificationError("secret remote certificate details")
                h.attempt(2)
                result = h.wait("attempt", 2)
                self.assertTrue(result["captured"])
                self.assertFalse(result["verified"])
                self.assertIsNone(result["proof"])
                self.assertEqual(result["successfulConnections"], "1")
                self.assertIs(result["validationPassed"], reason == "work")
                self.assertIs(h.capture.call_args.kwargs["complete_handshake"], False)
                h.verify.assert_called_once()
                h.verify.assert_called_once()
                self.assertEqual(h.verify.call_args.args[0].connection_work_target, "f" * 64)
                self.assertNotIn("secret", json.dumps(h.frames))

    def test_real_certificate_and_signature_validation_including_target_misses(self):
        root = certificate(80, "Outcome test root", ca=True)
        leaf = certificate(81, "Outcome test leaf", issuer=root, dns_name="example.com")
        wrong_name = certificate(82, "Wrong domain leaf", issuer=root, dns_name="wrong.example")
        valid = signed_proof("example.com", leaf, [])
        wrong_signature = replace(valid, proof=valid.proof[:-1] + bytes([valid.proof[-1] ^ 1]))
        invalid_certificate = signed_proof("example.com", wrong_name, [])
        cases = ((valid, True), (wrong_signature, False), (invalid_certificate, False))
        for envelope, expected in cases:
            with self.subTest(expected=expected, proof=envelope.proof[-8:]), Fixture() as h:
                h.resolve_domain()
                def capture(*args, **kwargs):
                    fake_capture(*args, **kwargs)
                    return SimpleNamespace(encoded_proof=envelope.proof)
                h.capture.side_effect = capture
                h.parse.side_effect = parse_proof
                h.meets.side_effect = None
                h.meets.return_value = False
                # This fixture alone substitutes its generated test trust root;
                # all path, name, proof, and cryptographic checks remain real.
                h.verify.side_effect = lambda candidate, _roots: verify_fixture(candidate, root[1])
                h.attempt(2, connection_work_target="00" * 32)
                result = h.wait("attempt", 2)
                self.assertIs(result["validationPassed"], expected)
                self.assertTrue(result["captured"])
                self.assertFalse(result["verified"])
                self.assertIsNone(result["proof"])
                self.assertEqual(result["successfulConnections"], "1")
                h.verify.assert_called_once()
                if expected:
                    h.meets.assert_called_once()
                else:
                    h.meets.assert_not_called()

    def test_malformed_proof_is_validation_failure_after_full_capture(self):
        with Fixture() as h:
            h.resolve_domain()
            h.parse.side_effect = ValueError("invalid encoded proof")
            h.attempt(2)
            result = h.wait("attempt", 2)
            self.assertTrue(result["captured"])
            self.assertIs(result["validationPassed"], False)
            h.verify.assert_not_called()

    def test_cancellation_before_verification_has_no_validated_observation(self):
        with Fixture() as h:
            h.resolve_domain()
            original_emit = h.service.emit_callback
            def emit(frame):
                if frame["type"] == "capture":
                    h.service.command({"type": "cancel", "id": frame["id"]})
                original_emit(frame)
            h.service.emit_callback = emit
            h.attempt(2)
            result = h.wait("attempt", 2)
            self.assertTrue(result["captured"] and result["cancelled"])
            self.assertIsNone(result["validationPassed"])
            self.assertEqual(result["successfulConnections"], "1")
            h.verify.assert_not_called()

    def test_conclusive_connection_failure_survives_late_cancellation(self):
        with Fixture() as h:
            h.resolve_domain()
            def fails(*args, **kwargs):
                fake_capture(*args, **kwargs)
                raise OSError("connection failed")
            h.capture.side_effect = fails
            original_emit = h.service.emit_callback
            def emit(frame):
                if frame["type"] == "capture":
                    h.service.command({"type": "cancel", "id": frame["id"]})
                original_emit(frame)
            h.service.emit_callback = emit
            h.attempt(2)
            result = h.wait("attempt", 2)
            self.assertIs(result["validationPassed"], False)
            self.assertTrue(result["started"] and result["cancelled"])
            self.assertFalse(result["captured"])

    def test_cancellation_during_verification_preserves_known_outcome_once(self):
        for valid in (True, False):
            with self.subTest(valid=valid), Fixture() as h:
                h.resolve_domain()
                entered, release = threading.Event(), threading.Event()
                def verify(*_):
                    entered.set()
                    if not release.wait(3): raise AssertionError("verification release timed out")
                    if not valid: raise ProofVerificationError("invalid proof signature")
                h.verify.side_effect = verify
                h.attempt(2)
                try:
                    self.assertTrue(entered.wait(3))
                    h.service.command({"type": "cancel", "id": 2})
                    h.service.command({"type": "cancel", "id": 2})
                finally:
                    release.set()
                result = h.wait("attempt", 2)
                self.assertIs(result["validationPassed"], valid)
                self.assertTrue(result["cancelled"])
                self.assertFalse(result["verified"])
                self.assertIsNone(result["proof"])
                self.assertEqual(result["seconds"], h.wait("capture", 2)["seconds"])
                terminal = [frame for frame in h.frames if "validationPassed" in frame]
                self.assertEqual(terminal, [result])

    def test_cancellation_racing_verified_result_cannot_emit_cancelled_proof(self):
        with Fixture() as h:
            h.resolve_domain()
            original = h.service._fields
            def race(job):
                if job.captured and h.verify.call_count:
                    job.control.cancel()
                return original(job)
            h.service._fields = race
            h.attempt(2)
            result = h.wait("attempt", 2)
            self.assertTrue(result["captured"])
            self.assertTrue(result["cancelled"])
            self.assertIs(result["validationPassed"], True)
            self.assertFalse(result["verified"])
            self.assertIsNone(result["proof"])

    def test_capture_event_precedes_slow_verification_and_keeps_completion_order(self):
        release, entered = threading.Event(), threading.Event()
        with Fixture() as h:
            h.resolve_domain()
            def verify(*_args, **_kwargs):
                entered.set()
                if not release.wait(3): raise AssertionError("test verification timed out")
            h.verify.side_effect = verify
            h.attempt(2)
            try:
                first = h.wait("capture", 2)
                self.assertTrue(first["captured"])
                self.assertTrue(entered.wait(3))
                self.assertFalse(any(frame["type"] == "attempt" for frame in h.frames))
                h.attempt(3, bounty=2)
                h.wait("capture", 3)
                self.assertEqual([frame["id"] for frame in h.frames if frame["type"] == "capture"], [2, 3])
            finally:
                release.set()
            self.assertEqual(h.wait("attempt", 2)["seconds"], first["seconds"])
            h.wait("attempt", 3)

    def test_terminal_repeats_own_capture_count_despite_later_completions(self):
        release, verifying = threading.Event(), threading.Event()
        with Fixture() as h:
            h.resolve_domain()
            count = 0
            def verify(*_args, **_kwargs):
                nonlocal count
                count += 1
                if count == 1:
                    verifying.set()
                    if not release.wait(3): raise AssertionError("test timed out")
            h.verify.side_effect = verify
            h.attempt(2)
            try:
                self.assertTrue(verifying.wait(3))
                h.attempt(3)
                self.assertEqual(h.wait("attempt", 3)["successfulConnections"], "2")
            finally:
                release.set()
            self.assertEqual(h.wait("attempt", 2)["successfulConnections"], "1")

    def test_dns_failure_and_expiry_never_start_tcp(self):
        with Fixture() as h:
            h.resolve.side_effect = OSError("private resolver details")
            self.assertFalse(h.resolve_domain()["ok"])
            h.attempt(2)
            result = h.wait("attempt", 2)
            self.assertFalse(result["started"] or result["captured"])
            self.assertIsNone(result["validationPassed"])
            self.assertEqual(result["seconds"], 0)
            self.assertFalse(any(frame["type"] == "capture" for frame in h.frames))
            h.capture.assert_not_called()
            self.assertFalse(h.resolve_domain(3)["ok"])
            self.assertEqual(h.resolve.call_count, 1)  # Negative DNS cache: two seconds.
            h.service.dns["example.com"]["expires"] = 0
            h.resolve.side_effect = None
            self.assertTrue(h.resolve_domain(4)["ok"])
            self.assertEqual(h.resolve.call_count, 2)
            h.service.dns["example.com"]["expires"] = 0
            h.attempt(5)
            self.assertFalse(h.wait("attempt", 5)["started"])
            h.capture.assert_not_called()

    def test_dns_cache_is_reused_and_endpoints_rotate(self):
        with Fixture() as h:
            h.resolve.return_value = (endpoint(), endpoint("1.1.1.1"))
            h.resolve_domain()
            expires = h.service.dns["example.com"]["expires"]
            self.assertAlmostEqual(expires - time.monotonic(), 60, delta=1)
            for identifier in (2, 3, 4):
                h.attempt(identifier)
                h.wait("attempt", identifier)
            h.resolve_domain(5)
            self.assertEqual(h.resolve.call_count, 1)
            self.assertEqual([call.args[0].ip for call in h.capture.call_args_list], ["8.8.8.8", "1.1.1.1", "8.8.8.8"])

    def test_failed_endpoint_does_not_block_new_attempts_or_reduce_configured_concurrency(self):
        release = threading.Event()
        with Fixture(concurrency=12) as h:
            h.resolve_domain()
            def fails(*args, **kwargs):
                fake_capture(*args, **kwargs)
                raise TimeoutError("simulated endpoint failure")
            h.capture.side_effect = fails
            h.attempt(2)
            self.assertFalse(h.wait("attempt", 2)["captured"])

            def simultaneous_failures(*args, **kwargs):
                fake_capture(*args, **kwargs)
                if not release.wait(3): raise AssertionError("test release timed out")
                raise TimeoutError("same endpoint still unreachable")
            h.capture.side_effect = simultaneous_failures
            identifiers = range(3, 15)
            try:
                for identifier in identifiers:
                    h.attempt(identifier)
                for identifier in identifiers:
                    h.wait("started", identifier)
                self.assertEqual(h.service.active_tls, 12)
                self.assertEqual(h.capture.call_count, 13)
            finally:
                release.set()
            for identifier in identifiers:
                result = h.wait("attempt", identifier)
                self.assertTrue(result["started"])
                self.assertFalse(result["captured"])
                self.assertFalse(result["validationPassed"])
                self.assertEqual(result["successfulConnections"], "0")
                self.assertNotIn("blocked", result)
                self.assertNotIn("retryAfterMs", result)
            self.assertEqual(h.resolve.call_count, 1)

    def test_failed_ipv4_and_ipv6_endpoints_remain_available_across_dns_refresh(self):
        ipv6 = Endpoint(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                        ("2001:4860:4860::8888", 443, 0, 0), "2001:4860:4860::8888")
        endpoints = (endpoint(), ipv6, endpoint("1.1.1.1"))
        with Fixture() as h:
            h.resolve.return_value = endpoints
            h.resolve_domain()
            def fails(*args, **kwargs):
                fake_capture(*args, **kwargs)
                raise TimeoutError("simulated address failure")
            h.capture.side_effect = fails
            h.attempt(2)
            self.assertTrue(h.wait("attempt", 2)["started"])
            h.service.dns["example.com"]["expires"] = 0
            h.resolve_domain(3)
            for identifier in range(4, 9):
                h.attempt(identifier)
                result = h.wait("attempt", identifier)
                self.assertTrue(result["started"])
                self.assertFalse(result["captured"])
                self.assertNotIn("blocked", result)
                self.assertNotIn("retryAfterMs", result)
            self.assertEqual(set(call.args[0] for call in h.capture.call_args_list), set(endpoints))
            self.assertEqual(h.resolve.call_count, 2)

    def test_actual_tcp_start_gate_recovers_delayed_start_reports(self):
        with Fixture(connectionsPerSecond=10) as h, PacingClock() as clock:
            h.service.budgets["fixture"] = service.Budget(0, 0)
            jobs = [service.Job(index, "attempt", bounty_id="fixture") for index in range(3)]
            h.service._connecting(jobs[0])
            # Reports delayed behind IPC retain the shared phase; they do not
            # each add another complete interval once the pipe is available.
            clock.now += 0.25
            for job in jobs[1:]: h.service._connecting(job)
            self.assertEqual([job.started_at for job in jobs], [100.0, 100.25, 100.25])
            self.assertAlmostEqual(h.service.next_connection, 100.3, places=11)
            self.assertEqual(clock.sleeps, [])
            phase = h.service.next_connection
            cancelled = service.Job(4, "attempt", bounty_id="fixture")
            cancelled.control.cancel()
            with self.assertRaises(CaptureCancelled): h.service._connecting(cancelled)
            self.assertEqual(h.service.next_connection, phase)

    def test_service_captures_through_certificate_verify_and_measures_after_start_acknowledgement(self):
        with Fixture() as h:
            h.resolve_domain()
            clock = [100.0]
            emit = h.service.emit_callback
            def blocked_emit(frame):
                if frame["type"] == "started": clock[0] += 11
                emit(frame)
            h.service.emit_callback = blocked_emit
            with patch.object(service.time, "monotonic", side_effect=lambda: clock[0]):
                h.attempt(2)
                result = h.wait("attempt", 2)
            self.assertTrue(result["captured"])
            self.assertEqual(result["seconds"], 0)
            self.assertIs(h.capture.call_args.kwargs["complete_handshake"], False)
            h.verify.assert_called_once()
            self.assertTrue(result["validationPassed"])

    def test_exact_two_expected_gate_is_strict_and_counts_only_success(self):
        with Fixture() as h:
            h.resolve_domain()
            h.meets.return_value = False
            for identifier in (2, 3, 4):
                h.attempt(identifier)
                self.assertTrue(h.wait("attempt", identifier)["captured"])
            h.attempt(5)
            result = h.wait("attempt", 5)
            self.assertEqual(result["blocked"], "budget")
            self.assertFalse(result["started"])
            self.assertEqual(result["successfulConnections"], "3")
            self.assertEqual(h.capture.call_count, 4)  # Last call reaches gate before TCP.
            self.assertEqual(sum(frame["type"] == "started" for frame in h.frames), 3)

    def test_seed_never_decreases_and_large_integer_gate_is_exact(self):
        with Fixture() as h:
            h.resolve_domain()
            h.attempt(2, successes="3")
            self.assertEqual(h.wait("attempt", 2)["blocked"], "budget")
            h.attempt(3, successes="0")
            self.assertEqual(h.wait("attempt", 3)["successfulConnections"], "3")
            h.attempt(4, bounty=2, successes=str(service.MAX_UINT64), connection_work_target="00" * 32)
            self.assertEqual(h.wait("attempt", 4)["blocked"], "budget")
            # 2^257/(target+1) = 2^54: above JS safe-integer precision.
            target = ((1 << 203) - 1).to_bytes(32, "big").hex()
            h.attempt(5, bounty=3, successes=str((1 << 54) + 1), connection_work_target=target)
            self.assertEqual(h.wait("attempt", 5)["blocked"], "budget")
            h.attempt(6, bounty=4, successes=str(1 << 54), connection_work_target=target)
            self.assertTrue(h.wait("attempt", 6)["started"])

    def test_capture_failures_do_not_exhaust_success_budget(self):
        with Fixture() as h:
            h.resolve_domain()
            def fails(*args, **kwargs):
                fake_capture(*args, **kwargs)
                raise OSError("connection failed")
            h.capture.side_effect = fails
            for identifier in (2, 3, 4, 5):
                h.attempt(identifier)
                result = h.wait("attempt", identifier)
                self.assertTrue(result["started"])
                self.assertFalse(result["captured"])
                self.assertIs(result["validationPassed"], False)
                self.assertEqual(result["successfulConnections"], "0")

    def test_capture_failure_messages_are_fixed_and_timeouts_preserve_budget(self):
        for error, expected in (
            (TimeoutError("private socket details"), "TLS connection timed out"),
            (TLSGenerationError("TLS handshake exceeded the connection timeout"), "TLS connection timed out"),
            (TLSGenerationError("private peer timed out"), "TLS capture or proof validation failed"),
            (OSError("private peer timed out"), "TLS capture or proof validation failed"),
        ):
            with self.subTest(error=type(error).__name__, expected=expected), Fixture() as h:
                h.resolve_domain()
                def fails(*args, **kwargs):
                    fake_capture(*args, **kwargs)
                    raise error
                h.capture.side_effect = fails
                h.attempt(2, successes="2")
                result = h.wait("attempt", 2)
                self.assertEqual(result["message"], expected)
                self.assertTrue(result["started"])
                self.assertFalse(result["captured"] or result["cancelled"] or result["verified"])
                self.assertIs(result["validationPassed"], False)
                self.assertIsNone(result["proof"])
                self.assertEqual(result["successfulConnections"], "2")
                self.assertNotIn("private", json.dumps(h.frames))
                h.capture.side_effect = fake_capture
                h.attempt(3, successes="2")
                retry = h.wait("attempt", 3)
                self.assertTrue(retry["verified"])
                self.assertEqual(retry["successfulConnections"], "3")

    def test_real_tls_deadline_is_reported_as_timeout_without_remote_text(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(3)
        address = listener.getsockname()
        received, release = threading.Event(), threading.Event()
        def peer():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    connection.recv(4096)
                    received.set()
                    release.wait(3)
            finally:
                listener.close()
        server_thread = threading.Thread(target=peer)
        server_thread.start()
        try:
            with patch.object(service, "CONNECTION_TIMEOUT", 0.1), Fixture() as h:
                h.resolve.return_value = (Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, address, "127.0.0.1"),)
                h.capture.side_effect = capture_tls13_proof
                h.resolve_domain()
                h.attempt(2)
                result = h.wait("attempt", 2)
                self.assertTrue(received.is_set())
                self.assertEqual(result["message"], "TLS connection timed out")
                self.assertEqual([frame["type"] for frame in h.frames if frame.get("id") == 2], ["started", "capture", "attempt"])
                self.assertFalse(result["captured"] or result["cancelled"] or result["verified"])
                self.assertEqual(result["successfulConnections"], "0")
                self.assertGreaterEqual(result["seconds"], 0.1)
                self.assertLess(result["seconds"], 2)
        finally:
            release.set(); server_thread.join(4)

    def test_global_start_rate_is_shared_across_domains(self):
        rate = 20
        # Drive the real attempt/capture hooks in a deterministic worker order.
        # Host preemption must not turn this into an adjacent-wall-time-gap test:
        # bounded catch-up intentionally permits gaps shorter than 1 / rate.
        with patch.object(service.ClaimsService, "_schedule"), \
             Fixture(connectionsPerSecond=rate, concurrency=2) as h, \
             PacingClock(quantum=0.015625) as clock:
            for identifier, domain in enumerate(("example.com", "other.example"), 1):
                h.service._resolve(service.Job(identifier, "resolve", domain=domain))
            identifiers = list(range(3, 2 * rate + 6))
            for identifier in identifiers:
                h.attempt(identifier, bounty=identifier,
                          domain="other.example" if identifier % 2 == 0 else "example.com")
            permits = []
            connecting = h.service._connecting
            def connect(job):
                previous, idle = h.service.next_connection, h.service.connection_idle
                connecting(job)
                permits.append((job.domain, job.started_at, previous, idle, h.service.next_connection))
                if len(permits) == 1:
                    clock.now += 0.25  # Preemption after the permit was granted.
            original_emit = h.service.emit_callback
            def emit(frame):
                if frame["type"] == "started" and frame["id"] == 4:
                    clock.now += 2.25  # Delayed IPC exceeds the one-second debt cap.
                original_emit(frame)
            h.service.emit_callback = emit
            with patch.object(h.service, "_connecting", side_effect=connect):
                while h.service.pending:
                    job = h.service.pending.popleft()
                    job.running = True
                    h.service.active_tls += 1
                    h.service._run(job)
            results = [frame for frame in h.frames if frame["type"] == "attempt"]
            self.assertEqual([frame["id"] for frame in results], identifiers)
            self.assertTrue(all(frame["verified"] for frame in results))
            self.assertEqual(h.capture.call_count, len(identifiers))
            for observations in (permits,):
                self.assertEqual(len(observations), len(identifiers))
                self.assertEqual({row[0] for row in observations}, {"example.com", "other.example"})
                self.assertEqual([row[3] for row in observations], [True] + [False] * (len(identifiers) - 1))
                for _, now, previous, idle, phase in observations:
                    expected = max((max(previous, now) if idle else previous) + 1.0 / rate, now - 1.0)
                    self.assertAlmostEqual(phase, expected, places=11)
            times = [row[1] for row in permits]
            self.assertTrue(any(right == left for left, right in zip(times, times[1:])))
            self.assertTrue(any(sum(then + 1.0 > now for then in times[:index + 1]) > rate
                                for index, now in enumerate(times)))
            self.assertTrue(clock.sleeps)

    def test_global_concurrency_and_cancellation_are_per_attempt(self):
        release = threading.Event()
        lock = threading.Lock()
        active = maximum = 0
        with Fixture(concurrency=2) as h:
            h.resolve_domain()
            def blocks(*args, **kwargs):
                nonlocal active, maximum
                result = fake_capture(*args, **kwargs)
                with lock:
                    active += 1
                    maximum = max(maximum, active)
                try:
                    until = time.monotonic() + 3
                    while not release.wait(0.005):
                        if kwargs["control"].cancelled(): raise CaptureCancelled("cancelled")
                        if time.monotonic() > until: raise AssertionError("test timed out")
                    return result
                finally:
                    with lock: active -= 1
            h.capture.side_effect = blocks
            for identifier in (2, 3, 4): h.attempt(identifier, bounty=identifier)
            try:
                h.wait("started", 2); h.wait("started", 3)
                self.assertFalse(any(frame.get("id") == 4 for frame in h.frames))
                h.service.command({"type": "cancel", "id": 2})
                self.assertTrue(h.wait("attempt", 2)["cancelled"])
                h.wait("started", 4)
                self.assertEqual(maximum, 2)
            finally:
                release.set()
            self.assertTrue(h.wait("attempt", 3)["verified"])
            self.assertTrue(h.wait("attempt", 4)["verified"])
            self.assertFalse(h.wait("attempt", 3)["cancelled"])

    def test_dns_cache_is_bounded_and_does_not_retain_old_domains(self):
        with patch.object(service, "MAX_DNS_CACHE", 3), Fixture() as h:
            for identifier in range(1, 6): h.resolve_domain(identifier, f"d{identifier}.example")
            self.assertEqual(list(h.service.dns), ["d3.example", "d4.example", "d5.example"])

    def test_budget_cache_never_evicts_active_or_queued_bounties(self):
        entered = threading.Event()
        with patch.object(service, "MAX_BUDGETS", 2), Fixture(concurrency=1) as h:
            h.resolve_domain()
            def blocks(*args, **kwargs):
                fake_capture(*args, **kwargs)
                entered.set()
                kwargs["control"]._event.wait(3)
                raise CaptureCancelled("cancelled")
            h.capture.side_effect = blocks
            h.attempt(2, bounty=1)
            self.assertTrue(entered.wait(3))
            h.attempt(3, bounty=2)
            with self.assertRaisesRegex(ValueError, "budget cache"): h.attempt(4, bounty=3)
            h.service.command({"type": "cancel", "id": 3})
            h.wait("attempt", 3)
            h.attempt(4, bounty=3)
            self.assertIn(f"{1:064x}:0", h.service.budgets)
            self.assertNotIn(f"{2:064x}:0", h.service.budgets)
            h.service.command({"type": "cancel", "id": 2})

    def test_pending_limit_and_queued_cancel_never_dial(self):
        entered = threading.Event()
        with Fixture(concurrency=1) as h:
            h.resolve_domain()
            def blocks(*args, **kwargs):
                fake_capture(*args, **kwargs)
                entered.set()
                kwargs["control"]._event.wait(3)
                raise CaptureCancelled("cancelled test connection")
            h.capture.side_effect = blocks
            h.attempt(2)
            self.assertTrue(entered.wait(3))
            for identifier in range(3, service.MAX_PENDING + 2): h.attempt(identifier, bounty=identifier)
            with self.assertRaisesRegex(ValueError, "pending request"): h.attempt(service.MAX_PENDING + 2)
            h.service.command({"type": "cancel", "id": 3})
            cancelled = h.wait("attempt", 3)
            self.assertTrue(cancelled["cancelled"])
            self.assertFalse(cancelled["started"])
            self.assertIsNone(cancelled["validationPassed"])
            self.assertEqual(h.capture.call_count, 1)
            h.service.command({"type": "cancel", "id": 2})
            self.assertTrue(h.wait("attempt", 2)["cancelled"])

    def test_one_executor_survives_more_than_one_thousand_attempts_and_bounds_budget_cache(self):
        with Fixture(concurrency=1) as h:
            h.resolve_domain()
            executor = h.service.executor
            threads = set()
            def recorded(*args, **kwargs):
                threads.add(threading.get_ident())
                return fake_capture(*args, **kwargs)
            h.capture.side_effect = recorded
            for identifier in range(2, 1102):
                # This checks executor longevity and bounded caches, not wall
                # clock rate accuracy. Expire the previous synthetic slot so
                # OS sleep granularity cannot add 4-16 seconds to 1,100 mocks.
                # Keep the real start hook (including budget/cancel checks);
                # the cross-domain test checks deterministic shared pacing.
                with h.service.condition:
                    h.service.next_connection = 0
                h.attempt(identifier, bounty=identifier)
                self.assertTrue(h.wait("attempt", identifier)["captured"])
            self.assertIs(h.service.executor, executor)
            self.assertLessEqual(len(threads), 3)
            self.assertEqual(h.capture.call_count, 1100)
            self.assertLessEqual(len(h.service.budgets), service.MAX_BUDGETS)
            self.assertLessEqual(len(h.service.jobs), 1)

    def test_real_loopback_socket_cancellation_interrupts_receive(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0)); listener.listen(1); listener.settimeout(3)
        address = listener.getsockname()
        received, release = threading.Event(), threading.Event()
        control = CaptureControl()
        failures = []
        def peer():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    connection.recv(4096)
                    received.set()
                    release.wait(3)
            finally:
                listener.close()
        def client():
            try:
                proof = claims_bridge.parse_context(public_context())
                capture_tls13_proof(Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, address, "127.0.0.1"),
                    proof.domain, proof.challenge, signature_algorithms_mask=1, timeout=10, control=control)
            except (OSError, ValueError) as error:
                failures.append(error)
        server_thread, client_thread = threading.Thread(target=peer), threading.Thread(target=client)
        server_thread.start(); client_thread.start()
        try:
            self.assertTrue(received.wait(3))
            started = time.monotonic(); control.cancel(); client_thread.join(2)
            self.assertFalse(client_thread.is_alive())
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(failures)
        finally:
            control.cancel(); release.set(); server_thread.join(4); client_thread.join(4)

    def test_cancelled_before_capture_opens_no_socket(self):
        control = CaptureControl(); control.cancel()
        proof = claims_bridge.parse_context(public_context())
        with patch("connectcoin_p2c_tools.tls13.socket.socket") as new_socket:
            with self.assertRaises(CaptureCancelled):
                capture_tls13_proof(endpoint(), proof.domain, proof.challenge,
                    signature_algorithms_mask=1, control=control)
        new_socket.assert_not_called()


class EndpointSelectionTests(unittest.TestCase):
    def test_equal_priors_rotate_ipv4_ipv6_and_ties_have_independent_policy_cursors(self):
        ipv6 = Endpoint(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                        ("2001:4860:4860::8888", 443, 0, 0), "2001:4860:4860::8888")
        endpoints = (endpoint(), ipv6, endpoint("1.1.1.1"))
        with Fixture() as h:
            h.resolve.return_value = endpoints
            h.resolve_domain()
            self.assertTrue(all(not policies for policies in h.service.dns["example.com"]["scores"].values()))
            selected = [h.service._select_endpoint("example.com", 1)[0] for _ in range(9)]
            self.assertEqual(selected, list(endpoints) * 3)
            h.service._select_endpoint("example.com", 1)
            self.assertEqual(h.service._select_endpoint("example.com", 2)[0], endpoints[0])
            self.assertEqual(h.service._select_endpoint("example.com", 1)[0], endpoints[1])

    def test_weighted_selection_prefers_fast_valid_ip_and_keeps_uniform_exploration(self):
        endpoints = (endpoint(), endpoint("1.1.1.1"))
        with Fixture() as h:
            h.resolve.return_value = endpoints
            h.resolve_domain()
            h.service._select_endpoint("example.com", 1)
            good, bad = [h.service.dns["example.com"]["scores"][item][1] for item in endpoints]
            for _ in range(1000):
                h.service._observe_endpoint(good, True, 0.02)
                h.service._observe_endpoint(bad, False, 1.5)
            self.assertAlmostEqual(good.connections, 1 - 0.9 * 0.999 ** 1000)
            self.assertAlmostEqual(bad.connections, 0.1 * 0.999 ** 1000)
            self.assertAlmostEqual(bad.total_time, 1.5 - 1.48 * 0.999 ** 1000)
            samples = 10000
            selected = [h.service._select_endpoint("example.com", 1)[0] for _ in range(samples)]
            expected_bad_share = 0.01 / 2 + 0.99 * bad.rate() / (good.rate() + bad.rate())
            self.assertLess(abs(selected.count(endpoints[1]) - samples * expected_bad_share), 2)
            self.assertGreater(selected.count(endpoints[0]), 9900)
            self.assertGreaterEqual(selected.count(endpoints[1]), 49)
            self.assertEqual(service.ENDPOINT_EXPLORATION, 0.01)

    def test_extreme_finite_rates_and_zero_successes_keep_finite_credits_and_exploration(self):
        endpoints = (endpoint(), endpoint("1.1.1.1"), endpoint("9.9.9.9"))
        with Fixture() as h:
            h.resolve.return_value = endpoints
            h.resolve_domain()
            h.service._select_endpoint("example.com", 1)
            scores = [h.service.dns["example.com"]["scores"][item][1] for item in endpoints]
            for score in scores:
                score.connections = 0
                score.credit = 0
            self.assertTrue(all(math.isfinite(score.rate()) and score.rate() > 0 for score in scores))
            selected = [h.service._select_endpoint("example.com", 1)[0] for _ in range(30)]
            self.assertTrue(all(selected.count(item) == 10 for item in endpoints))
            scores[0].connections, scores[0].total_time = 1, math.ulp(0.0)
            scores[1].connections, scores[1].total_time = math.ulp(0.0), sys.float_info.max
            scores[2].connections, scores[2].total_time = 1, 0
            self.assertTrue(all(math.isfinite(score.rate()) and score.rate() > 0 for score in scores))
            selected = [h.service._select_endpoint("example.com", 1)[0] for _ in range(10000)]
            self.assertGreaterEqual(selected.count(endpoints[1]), 32)
            self.assertTrue(all(math.isfinite(score.credit) and abs(score.credit) < 2 for score in scores))
            # Reversing the preferences must not leave unbounded historical debt.
            scores[0].connections, scores[0].total_time = 0, 1
            scores[1].connections, scores[1].total_time = 1, 0.02
            scores[2].connections, scores[2].total_time = 0, 1
            selected = [h.service._select_endpoint("example.com", 1)[0] for _ in range(10000)]
            self.assertGreater(selected.count(endpoints[1]), 9900)
            self.assertTrue(all(math.isfinite(score.credit) and abs(score.credit) < 2 for score in scores))

    def test_only_terminal_validation_updates_ema_once_before_emit_and_excludes_local_waits(self):
        for valid in (True, False):
            with self.subTest(valid=valid), Fixture() as h:
                h.resolve_domain()
                clock = [time.monotonic()]
                snapshots = []
                original_emit = h.service.emit_callback
                def emit(frame):
                    if frame["type"] == "started": clock[0] += 11
                    if frame["type"] in ("capture", "attempt"):
                        score = h.service.dns["example.com"]["scores"][endpoint()][1]
                        snapshots.append((frame["type"], score.connections, score.total_time))
                    original_emit(frame)
                h.service.emit_callback = emit
                def capture(*args, **kwargs):
                    result = fake_capture(*args, **kwargs)
                    clock[0] += 0.2
                    return result
                def verify(*_):
                    clock[0] += 20
                    if not valid: raise ProofVerificationError("invalid certificate")
                h.capture.side_effect = capture
                h.verify.side_effect = verify
                h.meets.return_value = False  # A target miss is still a valid connection.
                with patch.object(service.time, "monotonic", side_effect=lambda: clock[0]):
                    h.attempt(2)
                    result = h.wait("attempt", 2)
                self.assertEqual(result["seconds"], 0.2)
                self.assertIs(result["validationPassed"], valid)
                self.assertFalse(result["verified"])
                self.assertEqual(snapshots[0], ("capture", 0.1, 0.02))
                self.assertEqual(snapshots[1][0], "attempt")
                self.assertAlmostEqual(snapshots[1][1], 0.999 * 0.1 + 0.001 * int(valid))
                self.assertAlmostEqual(snapshots[1][2], 0.999 * 0.02 + 0.001 * 0.2)
                self.assertEqual(len(snapshots), 2)
                self.assertEqual(h.capture.call_args.kwargs["timeout"], 10.0)

    def test_inconclusive_cancellation_and_budget_refusal_do_not_update_ema(self):
        for reason in ("capture", "before_validation", "budget"):
            with self.subTest(reason=reason), Fixture() as h:
                h.resolve_domain()
                if reason == "capture":
                    def capture(*args, **kwargs):
                        fake_capture(*args, **kwargs)
                        kwargs["control"].cancel()
                        raise CaptureCancelled("cancelled during network")
                    h.capture.side_effect = capture
                elif reason == "before_validation":
                    emit = h.service.emit_callback
                    def cancel_at_capture(frame):
                        if frame["type"] == "capture": h.service.command({"type": "cancel", "id": frame["id"]})
                        emit(frame)
                    h.service.emit_callback = cancel_at_capture
                h.attempt(2, successes="3" if reason == "budget" else "0")
                result = h.wait("attempt", 2)
                self.assertIsNone(result["validationPassed"])
                score = h.service.dns["example.com"]["scores"][endpoint()][1]
                self.assertEqual((score.connections, score.total_time), (0.1, 0.02))

    def test_conclusive_outcome_still_updates_when_cancel_arrives_after_it(self):
        for valid in (True, False):
            with self.subTest(valid=valid), Fixture() as h:
                h.resolve_domain()
                def verify(*_):
                    h.service.command({"type": "cancel", "id": 2})
                    if not valid: raise ProofVerificationError("invalid certificate")
                h.verify.side_effect = verify
                h.attempt(2)
                result = h.wait("attempt", 2)
                self.assertTrue(result["cancelled"])
                score = h.service.dns["example.com"]["scores"][endpoint()][1]
                self.assertAlmostEqual(score.connections, 0.999 * 0.1 + 0.001 * int(valid))
                self.assertAlmostEqual(score.total_time, 0.999 * 0.02 + 0.001 * result["seconds"])

    def test_domain_and_signature_mask_scores_are_isolated(self):
        with Fixture() as h:
            h.resolve_domain()
            h.resolve_domain(2, "other.example")
            scores = [h.service._select_endpoint(domain, mask)[1]
                      for domain, mask in (("example.com", 1), ("example.com", 2), ("other.example", 1))]
            h.service._observe_endpoint(scores[0], False, 10)
            self.assertAlmostEqual(scores[0].connections, 0.0999)
            for score in scores[1:]: self.assertEqual((score.connections, score.total_time), (0.1, 0.02))
            self.assertEqual(len(set(map(id, scores))), 3)

    def test_dns_refresh_preserves_score_identity_for_validation_already_in_flight(self):
        entered, release = threading.Event(), threading.Event()
        with Fixture() as h:
            h.resolve_domain()
            def verify(*_):
                entered.set()
                if not release.wait(3): raise AssertionError("verification release timed out")
            h.verify.side_effect = verify
            h.attempt(2)
            try:
                self.assertTrue(entered.wait(3))
                score = h.service.dns["example.com"]["scores"][endpoint()][1]
                self.assertEqual(score.connections, 0.1)
                h.resolve.return_value = (endpoint(), endpoint("1.1.1.1"))
                h.service.dns["example.com"]["expires"] = 0
                h.resolve_domain(3)
                self.assertIs(h.service.dns["example.com"]["scores"][endpoint()][1], score)
            finally:
                release.set()
            self.assertIs(h.wait("attempt", 2)["validationPassed"], True)
            self.assertAlmostEqual(score.connections, 0.1009)

    def test_removed_then_readded_ip_does_not_inherit_late_validation(self):
        entered, release = threading.Event(), threading.Event()
        with Fixture() as h:
            h.resolve_domain()
            def verify(*_):
                entered.set()
                if not release.wait(3): raise AssertionError("verification release timed out")
            h.verify.side_effect = verify
            h.attempt(2)
            try:
                self.assertTrue(entered.wait(3))
                removed = h.service.dns["example.com"]["scores"][endpoint()][1]
                h.resolve.return_value = (endpoint("1.1.1.1"),)
                h.service.dns["example.com"]["expires"] = 0
                h.resolve_domain(3)
                self.assertNotIn(endpoint(), h.service.dns["example.com"]["scores"])
                h.resolve.return_value = (endpoint(),)
                h.service.dns["example.com"]["expires"] = 0
                h.resolve_domain(4)
                _, current = h.service._select_endpoint("example.com", 1)
                self.assertIsNot(current, removed)
            finally:
                release.set()
            self.assertIs(h.wait("attempt", 2)["validationPassed"], True)
            self.assertEqual((current.connections, current.total_time), (0.1, 0.02))
            self.assertEqual(set(h.service.dns["example.com"]["scores"]), {endpoint()})

    def test_dns_scores_are_bounded_by_domains_endpoints_and_lazy_masks(self):
        with patch.object(service, "MAX_DNS_CACHE", 3), Fixture() as h:
            h.resolve.return_value = tuple(endpoint(f"8.8.8.{index}") for index in range(1, 41))
            stale = None
            for identifier in range(1, 6):
                domain = f"d{identifier}.example"
                h.resolve_domain(identifier, domain)
                cached = h.service.dns[domain]
                self.assertEqual(len(cached["endpoints"]), 32)
                self.assertTrue(all(not policies for policies in cached["scores"].values()))
                for mask in range(1, 8):
                    _, score = h.service._select_endpoint(domain, mask)
                    if stale is None: stale = score
                self.assertEqual(sum(len(policies) for policies in cached["scores"].values()), 32 * 7)
                for mask in (0, 8, True):
                    with self.assertRaises(ValueError): h.service._select_endpoint(domain, mask)
            self.assertEqual(list(h.service.dns), ["d3.example", "d4.example", "d5.example"])
            h.service._observe_endpoint(stale, True, 0.1)
            self.assertNotIn("d1.example", h.service.dns)
            self.assertEqual(sum(len(policies) for cached in h.service.dns.values()
                                 for policies in cached["scores"].values()), 3 * 32 * 7)


if __name__ == "__main__":
    unittest.main()
