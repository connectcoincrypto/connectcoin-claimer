"""Bounded cancellation even when cross-thread socket closure does not wake recv."""

from __future__ import annotations

import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

HELPERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPERS))
import claims_bridge  # Sets only the trusted helper/provider import paths.
from connectcoin_p2c_tools import tls13


class TLSCancellationTests(unittest.TestCase):
    def test_blocked_start_reporting_does_not_consume_network_deadline(self):
        now = [100.0]
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.connect.side_effect = OSError("reached actual TCP connect")
        endpoint = tls13.Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                                  ("192.0.2.1", 443), "192.0.2.1")
        connecting = []

        def report_started():
            now[0] += 11.0  # Longer than the entire configured network budget.

        with patch.object(tls13.socket, "socket", return_value=connection), \
                patch.object(tls13.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(OSError, "actual TCP connect"):
                tls13.capture_tls13_proof(endpoint, "example.com", b"\x11" * 32,
                    signature_algorithms_mask=1, timeout=10, control=tls13.CaptureControl(),
                    on_started=report_started, on_connecting=lambda: connecting.append(now[0]))
        self.assertEqual(connecting, [111.0])
        connection.settimeout.assert_called_once_with(10.0)
        connection.connect.assert_called_once_with(endpoint.address)
        connection.__exit__.assert_called_once()

    def test_cancellation_can_close_socket_while_start_reporting_is_blocked(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        endpoint = tls13.Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                                  ("192.0.2.1", 443), "192.0.2.1")
        control = tls13.CaptureControl()
        reporting, release, cancelled = threading.Event(), threading.Event(), threading.Event()
        errors = []

        def report_started():
            reporting.set()
            if not release.wait(3):
                raise RuntimeError("reporting test did not release")

        def capture():
            try:
                tls13.capture_tls13_proof(endpoint, "example.com", b"\x11" * 32,
                    signature_algorithms_mask=1, control=control, on_started=report_started)
            except Exception as error:
                errors.append(error)

        def cancel():
            control.cancel()
            cancelled.set()

        with patch.object(tls13.socket, "socket", return_value=connection):
            worker = threading.Thread(target=capture)
            canceller = threading.Thread(target=cancel)
            worker.start()
            try:
                self.assertTrue(reporting.wait(2))
                canceller.start()
                self.assertTrue(cancelled.wait(1), "cancel must not wait for start reporting")
                connection.shutdown.assert_called_once_with(socket.SHUT_RDWR)
                connection.close.assert_called_once()
            finally:
                release.set()
                worker.join(4)
                if canceller.ident is not None:
                    canceller.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], tls13.CaptureCancelled)
        connection.connect.assert_not_called()

    def test_cancellation_at_connecting_hook_never_uses_closed_socket(self):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        endpoint = tls13.Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                                  ("192.0.2.1", 443), "192.0.2.1")
        control = tls13.CaptureControl()
        with patch.object(tls13.socket, "socket", return_value=connection):
            with self.assertRaises(tls13.CaptureCancelled):
                tls13.capture_tls13_proof(endpoint, "example.com", b"\x11" * 32,
                    signature_algorithms_mask=1, control=control, on_connecting=control.cancel)
        connection.connect.assert_not_called()
        connection.sendall.assert_not_called()

    def test_completed_handshake_close_has_a_bounded_independent_deadline(self):
        now = [100.0]
        connection = Mock()
        requested = []
        connection.settimeout.side_effect = requested.append

        def receive(_size):
            now[0] += requested[-1]
            raise TimeoutError("close response did not arrive")

        connection.recv.side_effect = receive
        with patch.object(tls13.time, "monotonic", side_effect=lambda: now[0]):
            # A close timeout is swallowed after a successful handshake.
            tls13._close_completed_handshake(connection, b"close", None)
        self.assertAlmostEqual(now[0], 100.0 + tls13.CLOSE_DRAIN_SECONDS)
        connection.sendall.assert_called_once_with(b"close")
        self.assertLessEqual(connection.recv.call_count, 3)

    def test_completed_handshake_close_bounds_bytes_and_preserves_cancellation(self):
        connection = Mock()
        connection.recv.side_effect = lambda size: b"x" * size
        with patch.object(tls13.time, "monotonic", return_value=100.0):
            tls13._close_completed_handshake(connection, b"close", None)
        self.assertEqual(sum(call.args[0] for call in connection.recv.call_args_list),
                         tls13.MAX_CLOSE_DRAIN_BYTES)

        control = tls13.CaptureControl()
        connection = Mock()
        def cancel_during_read(_size):
            control.cancel()
            return b""
        connection.recv.side_effect = cancel_during_read
        with self.assertRaises(tls13.CaptureCancelled):
            tls13._close_completed_handshake(connection, b"close", control)

    def test_cancelled_receive_never_reads_or_changes_socket_timeout(self):
        control = tls13.CaptureControl()
        control.cancel()
        connection = Mock()
        with self.assertRaises(tls13.CaptureCancelled):
            tls13._recv_exact(connection, 5, time.monotonic() + 10, control)
        connection.recv.assert_not_called()
        connection.settimeout.assert_not_called()

    def test_partial_record_header_and_body_check_cancellation(self):
        for prefix in ([b"\x16\x03"], [b"\x16\x03\x03\x00\x04", b"ab"]):
            with self.subTest(prefix=prefix):
                control = tls13.CaptureControl()
                connection = Mock()
                chunks = iter(prefix)

                def receive(_size):
                    try:
                        return next(chunks)
                    except StopIteration:
                        control.cancel()
                        raise TimeoutError("simulated poll expiry")

                connection.recv.side_effect = receive
                with self.assertRaises(tls13.CaptureCancelled):
                    tls13._recv_record(connection, time.monotonic() + 10, control)
                self.assertEqual(connection.recv.call_count, len(prefix) + 1)
                self.assertTrue(all(call.args[0] <= 0.1 for call in connection.settimeout.call_args_list))

    def test_cancellation_racing_successful_receive_discards_its_bytes(self):
        control = tls13.CaptureControl()
        connection = Mock()

        def receive(_size):
            control.cancel()
            return b"proof"

        connection.recv.side_effect = receive
        with self.assertRaises(tls13.CaptureCancelled):
            tls13._recv_exact(connection, 5, time.monotonic() + 10, control)

    def test_poll_timeouts_do_not_extend_the_absolute_deadline(self):
        now = [100.0]
        connection = Mock()
        requested = []
        connection.settimeout.side_effect = requested.append

        def receive(_size):
            now[0] += requested[-1]
            raise TimeoutError("simulated poll expiry")

        connection.recv.side_effect = receive
        with patch.object(tls13.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(tls13.TLSGenerationError, "connection timeout"):
                tls13._recv_exact(connection, 5, 100.25, tls13.CaptureControl())
        self.assertAlmostEqual(now[0], 100.25)
        self.assertEqual(connection.recv.call_count, 3)
        self.assertAlmostEqual(requested[-1], 0.05)

    def test_record_header_and_body_share_the_same_deadline(self):
        now = [100.0]
        connection = Mock()
        requested = []
        connection.settimeout.side_effect = requested.append

        def receive(_size):
            if connection.recv.call_count == 1:
                now[0] += 0.075
                return b"\x16\x03\x03\x00\x04"
            now[0] += requested[-1]
            raise TimeoutError("simulated body poll expiry")

        connection.recv.side_effect = receive
        with patch.object(tls13.time, "monotonic", side_effect=lambda: now[0]):
            with self.assertRaisesRegex(tls13.TLSGenerationError, "connection timeout"):
                tls13._recv_record(connection, 100.15, tls13.CaptureControl())
        self.assertAlmostEqual(now[0], 100.15)
        self.assertEqual(connection.recv.call_count, 2)
        self.assertAlmostEqual(requested[-1], 0.075)

    def test_uncancelled_eof_socket_error_and_record_bounds_still_fail(self):
        for outcome in (b"", ConnectionResetError("reset")):
            connection = Mock()
            connection.recv.side_effect = [outcome]
            with self.assertRaises((OSError, tls13.TLSGenerationError)):
                tls13._recv_exact(connection, 5, time.monotonic() + 10, tls13.CaptureControl())
            self.assertEqual(connection.recv.call_count, 1)
        connection = Mock()
        connection.recv.return_value = b"\x16\x03\x03\xff\xff"
        with self.assertRaisesRegex(tls13.TLSGenerationError, "ciphertext limit"):
            tls13._recv_record(connection, time.monotonic() + 10, tls13.CaptureControl())
        self.assertEqual(connection.recv.call_count, 1)

    def test_receive_without_control_keeps_original_socket_timeout_behavior(self):
        connection = Mock()
        connection.recv.side_effect = TimeoutError("original timeout")
        with patch.object(tls13.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(TimeoutError, "original timeout"):
                tls13._recv_exact(connection, 5, 110)
        connection.settimeout.assert_called_once_with(10)
        connection.recv.assert_called_once_with(5)

    def test_socket_owner_detaches_before_late_cancellation(self):
        connection = Mock()
        control = tls13.CaptureControl()
        with control:
            control.bind(connection)
        control.cancel()
        connection.shutdown.assert_not_called()
        connection.close.assert_not_called()

    def test_loopback_receive_cancels_even_if_shutdown_and_close_do_not_wake_it(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        received, release = threading.Event(), threading.Event()
        failures, peer_failures = [], []
        control = tls13.CaptureControl()
        client_socket = socket.create_connection(listener.getsockname(), timeout=3)
        connection = Mock(wraps=client_socket)
        # Reproduce an OS where cross-thread shutdown/close has no effect on a
        # pending receive. Only the receive's short timeout can wake the owner.
        connection.shutdown.side_effect = lambda *_: None
        connection.close.side_effect = lambda: None

        def receive(size):
            received.set()
            return client_socket.recv(size)

        connection.recv.side_effect = receive

        def peer():
            try:
                accepted, _ = listener.accept()
                with accepted:
                    release.wait(4)
            except OSError as error:
                peer_failures.append(error)
            finally:
                listener.close()

        def client():
            try:
                with control:
                    control.bind(connection)
                    tls13._recv_exact(connection, 5, time.monotonic() + 10, control)
            except (OSError, tls13.TLSGenerationError) as error:
                failures.append(error)
            finally:
                client_socket.close()

        server_thread = threading.Thread(target=peer)
        client_thread = threading.Thread(target=client)
        server_thread.start()
        client_thread.start()
        try:
            self.assertTrue(received.wait(3))
            started = time.monotonic()
            control.cancel()
            client_thread.join(2)
            self.assertFalse(client_thread.is_alive())
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], tls13.CaptureCancelled)
            self.assertEqual(client_socket.fileno(), -1)
            connection.shutdown.assert_called_once_with(socket.SHUT_RDWR)
            connection.close.assert_called_once_with()
        finally:
            control.cancel()
            release.set()
            server_thread.join(4)
            client_thread.join(4)
            client_socket.close()
        self.assertEqual(peer_failures, [])


if __name__ == "__main__":
    unittest.main()
