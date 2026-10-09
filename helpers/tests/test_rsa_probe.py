"""RSA discovery tests: synthetic inputs and controlled loopback TLS only."""

from __future__ import annotations

import io
import json
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

HELPERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPERS))
import claims_bridge
import rsa_probe
from connectcoin_p2c_tools import tls13
from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.verify import verify_connection_proof
from test_claims import identity


def request():
    return {"domain": "example.com", "rootVersion": 1, "validationTime": 1800000000}


PUBLIC = tls13.Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                        ("8.8.8.8", 443), "8.8.8.8")


class ProbeTests(unittest.TestCase):
    def invoke(self, value=None, *, raw=None, budget=1):
        frames = []
        if raw is None:
            raw = (json.dumps(request() if value is None else value) + "\n").encode()
        status = rsa_probe.run_probe(io.BytesIO(raw), frames.append, HELPERS / "p2c_roots_v1.pem",
                                     deadline=time.monotonic() + budget)
        self.assertEqual(len(frames), 1)
        return status, frames[0]

    def test_request_shape_and_dns_domain_policy(self):
        self.assertEqual(rsa_probe.parse_probe_request(request()), request())
        invalid = [None, [], {}, {**request(), "privateKey": "secret"}]
        for key, values in {
            "domain": [None, 123, "localhost", "wallet.local", "x.localhost", "x.internal",
                       "x.home.arpa", "https://example.com", "example.com:443", "Example.com",
                       "example.com.", "127.0.0.1", "8.8.8.8", "[::1]", "é.com", "a" * 254],
            "rootVersion": [True, 0, 2, "1"],
            "validationTime": [True, 0, -1, 1.5, "1800000000", 253402300800],
        }.items():
            invalid.extend({**request(), key: value} for value in values)
        with patch.object(rsa_probe, "probe_rsa") as probe:
            for value in invalid:
                with self.subTest(value=value):
                    with self.assertRaises((ValueError, TypeError)):
                        rsa_probe.parse_probe_request(value)
                    status, frame = self.invoke(value, raw=(json.dumps(value) + "\n").encode())
                    self.assertEqual(status, 1)
                    self.assertEqual(frame, {"type": "error", "message": "Invalid or incomplete RSA probe request."})
            probe.assert_not_called()

    def test_bounded_exact_single_json_frame(self):
        for raw in (b"{}", b"x" * 1025 + b"\n", b"\xff\n", b"{\n",
                    b'{"domain":"example.com","domain":"evil.example","rootVersion":1,"validationTime":1800000000}\n',
                    (json.dumps(request()) + "\n{}\n").encode()):
            with self.subTest(raw=raw[:80]), patch.object(rsa_probe, "probe_rsa") as probe:
                self.assertEqual(self.invoke(raw=raw)[0], 1)
                probe.assert_not_called()

    def test_one_rsa_handshake_pinned_roots_wall_time_and_random_challenge(self):
        captures = Mock(return_value=Mock(encoded_proof=b"fixture"))
        with patch.object(rsa_probe, "validate_root_bundle") as roots, \
                patch.object(rsa_probe, "resolve_endpoints", return_value=(PUBLIC, PUBLIC)) as resolver, \
                patch.object(rsa_probe, "capture_tls13_proof", captures), \
                patch.object(rsa_probe, "verify_connection_proof") as verify:
            for _ in range(2):
                status, frame = self.invoke()
                self.assertEqual(status, 0)
                self.assertEqual(frame, {"type": "rsa-probe", **request(), "verified": True})
            resolver.assert_called_with("example.com", 443, allow_private=False)
            roots.assert_called_with(HELPERS / "p2c_roots_v1.pem", 1, enforce_root_pin=True)
            self.assertEqual(captures.call_count, 2)
            self.assertNotEqual(captures.call_args_list[0].args[2], captures.call_args_list[1].args[2])
            for call in captures.call_args_list:
                self.assertEqual(call.args[:2], (PUBLIC, "example.com"))
                self.assertEqual(call.kwargs["signature_algorithms_mask"], 6)
                self.assertIs(call.kwargs["complete_handshake"], True)
                self.assertLessEqual(call.kwargs["timeout"], 1)
            envelope = verify.call_args.args[0]
            self.assertEqual(envelope.validation_time, request()["validationTime"])
            self.assertEqual(envelope.connection_work_target, "ff" * 32)
            self.assertEqual(envelope.signature_algorithms_mask, 6)
            self.assertEqual(verify.call_args.kwargs, {"enforce_root_pin": True})

    def test_private_addresses_never_reach_capture_and_mixed_dns_uses_one_public(self):
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "224.0.0.1",
                   "::1", "ff02::1", "64:ff9b::7f00:1", "2002:7f00:1::"):
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            address = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
            with self.subTest(ip=ip), patch("socket.getaddrinfo", return_value=[
                    (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)]), \
                    patch.object(rsa_probe, "capture_tls13_proof") as capture:
                self.assertEqual(self.invoke()[1], {"type": "rsa-probe", **request(), "verified": False})
                capture.assert_not_called()
        with patch("socket.getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))
                for ip in ("127.0.0.1", "8.8.8.8", "1.1.1.1")]), \
                patch.object(rsa_probe, "capture_tls13_proof", return_value=Mock(encoded_proof=b"test")) as capture, \
                patch.object(rsa_probe, "verify_connection_proof"):
            self.assertTrue(self.invoke()[1]["verified"])
            capture.assert_called_once()
            self.assertEqual(capture.call_args.args[0], PUBLIC)

    def test_root_failure_is_checked_before_dns(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(rsa_probe, "resolve_endpoints") as resolver:
            with self.assertRaises(ValueError):
                rsa_probe.probe_rsa(request(), Path(directory) / "missing.pem", time.monotonic() + 1,
                                    tls13.CaptureControl())
            resolver.assert_not_called()

    def test_failure_is_sanitized_and_not_retried(self):
        for phase in ("resolve_endpoints", "capture_tls13_proof", "verify_connection_proof"):
            with self.subTest(phase=phase), \
                    patch.object(rsa_probe, "resolve_endpoints", return_value=(PUBLIC, PUBLIC)), \
                    patch.object(rsa_probe, "capture_tls13_proof", return_value=Mock(encoded_proof=b"test")) as capture, \
                    patch.object(rsa_probe, "verify_connection_proof"), \
                    patch.object(rsa_probe, phase, side_effect=ValueError("untrusted remote secret")):
                self.assertEqual(self.invoke()[1], {"type": "rsa-probe", **request(), "verified": False})
                self.assertLessEqual(capture.call_count, 1)

    def test_deadline_includes_stuck_dns_and_prevents_late_connection(self):
        release, exited = threading.Event(), threading.Event()

        def stalled_resolver(*args, **kwargs):
            release.wait(2)
            exited.set()
            return (PUBLIC,)

        with patch.object(rsa_probe, "resolve_endpoints", stalled_resolver), \
                patch.object(rsa_probe, "capture_tls13_proof") as capture:
            try:
                started = time.monotonic()
                self.assertFalse(self.invoke(budget=0.05)[1]["verified"])
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                release.set()
            self.assertTrue(exited.wait(1))
            capture.assert_not_called()

    def test_verification_finishing_after_deadline_cannot_report_success(self):
        release = threading.Event()
        with patch.object(rsa_probe, "resolve_endpoints", return_value=(PUBLIC,)), \
                patch.object(rsa_probe, "capture_tls13_proof", return_value=Mock(encoded_proof=b"test")), \
                patch.object(rsa_probe, "verify_connection_proof", side_effect=lambda *a, **k: release.wait(1)):
            try:
                self.assertFalse(self.invoke(budget=0.05)[1]["verified"])
            finally:
                release.set()


class CompletedTLSProbeTests(unittest.TestCase):
    def capture(self, directory, *, rsa_leaf=True, leaf_domain="example.com", tamper_finished=False,
                only_cipher=None):
        root_pem, cert_pem, key_pem = identity(rsa_leaf=rsa_leaf, leaf_domain=leaf_domain)
        root, cert, key = (directory / name for name in ("root.pem", "cert.pem", "key.pem"))
        root.write_bytes(root_pem)
        cert.write_bytes(cert_pem)
        key.write_bytes(key_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.num_tickets = 0
        context.load_cert_chain(cert, key)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        endpoint = tls13.Endpoint(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                                 listener.getsockname(), "127.0.0.1")
        completed, negotiated_ciphers = [], []

        def server():
            try:
                peer, _ = listener.accept()
                with peer:
                    peer.settimeout(3)
                    with context.wrap_socket(peer, server_side=True) as encrypted:
                        completed.append(encrypted.version())
                        negotiated_ciphers.append(encrypted.cipher()[0])
            except (ssl.SSLError, OSError):
                pass
            finally:
                listener.close()

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        envelope = ConnectionProof(domain="example.com", txid="11" * 32, input_index=0,
                                   connection_work_target="ff" * 32, root_certificates_version=1,
                                   signature_algorithms_mask=6, validation_time=1800000000, proof=b"")
        real_verify = tls13._verify_server_finished
        real_client_hello = tls13.build_client_hello

        def client_hello(*args, **kwargs):
            message = real_client_hello(*args, **kwargs)
            if only_cipher is None:
                return message
            # Python 3.11 SSLContext cannot set TLS 1.3 suites. Offer exactly one
            # from the test client instead, retaining all other production bytes.
            body = message[4:]
            position = 35 + body[34]  # Version, random, session-id length/id.
            size = int.from_bytes(body[position:position + 2], "big")
            offered = body[position + 2:position + 2 + size]
            self.assertIn(only_cipher.to_bytes(2, "big"),
                          [offered[index:index + 2] for index in range(0, size, 2)])
            body = (body[:position] + b"\x00\x02" + only_cipher.to_bytes(2, "big")
                    + body[position + 2 + size:])
            return message[:1] + len(body).to_bytes(3, "big") + body

        def check_finished(message, secret, transcript):
            if tamper_finished:
                message = message[:-1] + bytes([message[-1] ^ 1])
            real_verify(message, secret, transcript)

        try:
            with patch.object(tls13, "_verify_server_finished", side_effect=check_finished), \
                    patch.object(tls13, "build_client_hello", side_effect=client_hello):
                capture = tls13.capture_tls13_proof(endpoint, envelope.domain, envelope.challenge,
                                                    signature_algorithms_mask=6, timeout=3,
                                                    complete_handshake=True)
        finally:
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(completed, ["TLSv1.3"])
        if only_cipher is not None:
            self.assertEqual(negotiated_ciphers, [{
                tls13.TLS_AES_128_GCM_SHA256: "TLS_AES_128_GCM_SHA256",
                tls13.TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",
            }[only_cipher]])
        return replace(envelope, proof=capture.encoded_proof), root

    def test_real_rsa_server_completes_both_finished_messages_and_authenticates(self):
        with tempfile.TemporaryDirectory() as directory:
            envelope, roots = self.capture(Path(directory), only_cipher=tls13.TLS_AES_128_GCM_SHA256)
            result = verify_connection_proof(envelope, roots, enforce_root_pin=False)
            self.assertEqual(result.certificate_verify_scheme, 0x0804)
            with self.assertRaises(ValueError):
                verify_connection_proof(envelope, roots)  # Production never accepts the fixture roots.
            for moment in (1600000000, 2200000000):
                with self.assertRaises(ValueError):
                    verify_connection_proof(replace(envelope, validation_time=moment), roots, enforce_root_pin=False)
            with self.assertRaises(ValueError):
                verify_connection_proof(replace(envelope, proof=envelope.proof[:-1] + bytes([envelope.proof[-1] ^ 1])),
                                        roots, enforce_root_pin=False)

    def test_real_chacha20_rsa_server_completes_both_finished_messages_and_authenticates(self):
        with tempfile.TemporaryDirectory() as directory:
            envelope, roots = self.capture(Path(directory), only_cipher=tls13.TLS_CHACHA20_POLY1305_SHA256)
            result = verify_connection_proof(envelope, roots, enforce_root_pin=False)
            self.assertEqual(result.certificate_verify_scheme, 0x0804)

    def test_ecdsa_only_server_cannot_pass_rsa_capture(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            self.capture(Path(directory), rsa_leaf=False)

    def test_wrong_hostname_certificate_cannot_authenticate(self):
        with tempfile.TemporaryDirectory() as directory:
            envelope, roots = self.capture(Path(directory), leaf_domain="other.example")
            with self.assertRaises(ValueError):
                verify_connection_proof(envelope, roots, enforce_root_pin=False)

    def test_tampered_finished_is_rejected_before_client_finished(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(ValueError, "Finished verification"):
            self.capture(Path(directory), tamper_finished=True)

    def test_missing_truncated_or_wrong_type_finished_is_rejected(self):
        secret, transcript = b"x" * 32, b"test transcript"
        valid = tls13._handshake(tls13.FINISHED, tls13._finished_verify_data(secret, transcript))
        tls13._verify_server_finished(valid, secret, transcript)
        for value in (b"", valid[:-1], bytes([15]) + valid[1:], valid + b"x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                tls13._verify_server_finished(value, secret, transcript)


if __name__ == "__main__":
    unittest.main()
