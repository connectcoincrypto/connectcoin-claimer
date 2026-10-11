"""Reuse immutable parsing work without reusing any proof's validation result."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from time import monotonic
from types import SimpleNamespace
from unittest.mock import patch

HELPERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPERS))
import claims_bridge  # Establish the same vendored import path as production.
import claims_service as service
from connectcoin_p2c_tools import protocol, verify
from connectcoin_p2c_tools.errors import P2CError, ProofVerificationError
from cryptography.hazmat.primitives import serialization
from test_claims_service import endpoint, fake_capture, public_context
from test_rsa_exponent_limits import LIMIT_ERROR, _rsa_certificate
from test_verifier_security import certificate, signed_proof

DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM
PINNED_ROOTS = HELPERS / "p2c_roots_v1.pem"


class VerificationReuseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="connectwallet-verification-reuse-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        for cached in (verify._parse_roots, verify._root_store,
                       verify._parse_certificate_chain, protocol.parse_proof):
            cached.cache_clear()
            self.addCleanup(cached.cache_clear)
        self.root = certificate(301, "Reuse fixture root", ca=True)
        self.leaf = certificate(302, "Reuse fixture leaf", issuer=self.root, dns_name="example.com")
        self.valid = signed_proof("example.com", self.leaf, [])
        self.roots_path = self.directory / "roots.pem"
        self.roots_path.write_bytes(self.root[1].public_bytes(PEM))

    def verify(self, envelope):
        return verify.verify_connection_proof(envelope, self.roots_path, enforce_root_pin=False)

    def test_warm_store_is_shared_but_every_concurrent_proof_is_authenticated(self):
        with patch.object(verify, "Store", wraps=verify.Store) as build_store, \
             patch.object(verify, "_verify_path", wraps=verify._verify_path) as path_check, \
             patch.object(verify, "_verify_certificate_signature",
                          wraps=verify._verify_certificate_signature) as signature_check:
            expected = self.verify(self.valid)
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(self.verify, [self.valid] * 32))
            self.assertTrue(all(result == expected for result in results))
            self.assertEqual(build_store.call_count, 1)
            self.assertEqual(path_check.call_count, 33)
            self.assertEqual(signature_check.call_count, 33)
            self.assertEqual(protocol.parse_proof.cache_info().misses, 1)
            self.assertEqual(verify._parse_certificate_chain.cache_info().misses, 1)

    def test_same_size_and_timestamp_replacement_cannot_reuse_trust(self):
        replacement = certificate(303, "Other fixture root", ca=True)
        original = self.root[1].public_bytes(PEM)
        changed = replacement[1].public_bytes(PEM)
        size = max(len(original), len(changed))
        self.roots_path.write_bytes(original.ljust(size, b"\n"))
        self.verify(self.valid)
        prior = self.roots_path.stat()
        self.roots_path.write_bytes(changed.ljust(size, b"\n"))
        os.utime(self.roots_path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        self.assertEqual(self.roots_path.stat().st_size, prior.st_size)
        self.assertEqual(self.roots_path.stat().st_mtime_ns, prior.st_mtime_ns)
        with self.assertRaisesRegex(ProofVerificationError, "certificate path or domain"):
            self.verify(self.valid)

        # A pinned bundle also must be authenticated again even if its file
        # metadata is indistinguishable from the previously accepted file.
        pinned_path = self.directory / "pinned.pem"
        encoded = PINNED_ROOTS.read_bytes()
        pinned_path.write_bytes(encoded)
        verify.validate_root_bundle(pinned_path, 1)
        prior = pinned_path.stat()
        pinned_path.write_bytes(bytes([encoded[0] ^ 1]) + encoded[1:])
        os.utime(pinned_path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        with self.assertRaisesRegex(ProofVerificationError, "SHA-256 pin"):
            verify.validate_root_bundle(pinned_path, 1)

    def test_cached_transcript_and_certificates_recheck_every_claim_context(self):
        accepted = self.verify(self.valid)
        invalid = (
            ("block time", replace(self.valid, validation_time=2_100_000_000)),
            ("signature policy", replace(self.valid, signature_algorithms_mask=2)),
            ("work target", replace(self.valid, connection_work_target="00" * 32)),
            ("root version", replace(self.valid, root_certificates_version=2)),
        )
        for label, envelope in invalid:
            with self.subTest(check=label), self.assertRaises(P2CError):
                self.verify(envelope)
        # These contexts share the exact transcript/domain/challenge and thus
        # reuse its structural parse, despite each independent rejection.
        self.assertEqual(protocol.parse_proof.cache_info().misses, 1)
        for label, envelope in (
            ("challenge", replace(self.valid, txid="ab" * 32)),
            ("domain", replace(self.valid, domain="other.example")),
            ("signature", replace(self.valid, proof=self.valid.proof[:-1]
                                   + bytes([self.valid.proof[-1] ^ 1]))),
        ):
            with self.subTest(check=label), self.assertRaises(P2CError):
                self.verify(envelope)
        self.assertEqual(self.verify(self.valid), accepted)

    def test_cached_certificate_tuples_do_not_expose_mutable_lists(self):
        parsed = protocol.parse_proof(self.valid.proof, self.valid.domain, self.valid.challenge)
        expected = verify._load_certificate_chain(parsed.certificate_chain)

        def load_and_mutate(_):
            certificates = verify._load_certificate_chain(parsed.certificate_chain)
            self.assertEqual(certificates, expected)
            certificates.clear()
            return certificates

        with ThreadPoolExecutor(max_workers=8) as executor:
            copies = list(executor.map(load_and_mutate, range(32)))
        self.assertEqual(len({id(certificates) for certificates in copies}), 32)
        self.assertEqual(verify._load_certificate_chain(parsed.certificate_chain), expected)
        self.assertEqual(verify._parse_certificate_chain.cache_info().misses, 1)

    def test_structural_parse_cache_is_bounded_and_eviction_preserves_verification(self):
        accepted = self.verify(self.valid)
        limit = protocol.parse_proof.cache_info().maxsize
        self.assertGreater(limit, 0)
        self.assertLessEqual(limit, 512)
        variants = 0
        for value in range(limit + 2):
            # CertificateVerify bytes may be structurally valid even when the
            # signature is invalid. Such entries cannot authenticate a proof.
            encoded = self.valid.proof[:-4] + value.to_bytes(4, "big")
            if encoded == self.valid.proof:
                continue
            protocol.parse_proof(encoded, self.valid.domain, self.valid.challenge)
            variants += 1
            if variants == limit:
                break
        info = protocol.parse_proof.cache_info()
        self.assertEqual(info.currsize, limit)
        self.assertEqual(self.verify(self.valid), accepted)
        self.assertEqual(protocol.parse_proof.cache_info().misses, info.misses + 1)
        self.assertEqual(protocol.parse_proof.cache_info().currsize, limit)
        with self.assertRaisesRegex(ProofVerificationError, "CertificateVerify signature"):
            self.verify(replace(self.valid, proof=encoded))

    def test_certificate_cache_is_bounded_and_eviction_reloads_valid_chain(self):
        accepted = self.verify(self.valid)
        limit = verify._parse_certificate_chain.cache_info().maxsize
        self.assertGreater(limit, 0)
        self.assertLessEqual(limit, 64)
        for index in range(limit):
            leaf = certificate(400 + index, "Eviction fixture leaf", issuer=self.root, dns_name="example.com")
            verify._load_certificate_chain((leaf[1].public_bytes(DER),))
        info = verify._parse_certificate_chain.cache_info()
        self.assertEqual(info.currsize, limit)
        self.assertEqual(self.verify(self.valid), accepted)
        self.assertEqual(verify._parse_certificate_chain.cache_info().misses, info.misses + 1)
        self.assertEqual(verify._parse_certificate_chain.cache_info().currsize, limit)

    def test_warm_certificate_cache_rejects_oversized_rsa_and_invalid_der_on_retry(self):
        accepted = self.verify(self.valid)
        for pss in (False, True):
            oversized = _rsa_certificate((1 << 64) + 1, pss=pss)
            envelope = signed_proof("example.com", self.leaf, [oversized])
            for retry in range(2):
                with self.subTest(pss=pss, retry=retry), self.assertRaisesRegex(
                    ProofVerificationError, LIMIT_ERROR
                ):
                    self.verify(envelope)
                self.assertEqual(verify._parse_certificate_chain.cache_info().currsize, 1)
        encoded_leaf = self.leaf[1].public_bytes(DER)
        self.assertEqual(self.valid.proof.count(encoded_leaf), 1)
        invalid_der = replace(self.valid, proof=self.valid.proof.replace(
            encoded_leaf, b"\x00" + encoded_leaf[1:]))
        for retry in range(2):
            with self.subTest(invalid_der_retry=retry), self.assertRaisesRegex(
                ProofVerificationError, "not a valid DER X.509 certificate"
            ):
                self.verify(invalid_der)
            self.assertEqual(verify._parse_certificate_chain.cache_info().currsize, 1)
        self.assertEqual(self.verify(self.valid), accepted)

    def test_service_reuses_one_parse_and_preserves_work_hash_boundaries(self):
        expected_hash = self.verify(self.valid).connection_work_hash
        self.assertGreater(int(expected_hash, 16), 0)
        below_hash = f"{int(expected_hash, 16) - 1:064x}"
        wrong_name = certificate(304, "Wrong hostname leaf", issuer=self.root, dns_name="wrong.example")
        cases = (
            ("equal target", self.valid, expected_hash, True, True),
            ("below target", self.valid, below_hash, True, False),
            ("bad signature", replace(self.valid, proof=self.valid.proof[:-1]
                                      + bytes([self.valid.proof[-1] ^ 1])), below_hash, False, False),
            ("wrong hostname", signed_proof("example.com", wrong_name, []), below_hash, False, False),
            ("malformed proof", replace(self.valid, proof=b"\x02\x01"), below_hash, False, False),
        )
        protocol.parse_proof.cache_clear()
        condition = threading.Condition()
        frames = []
        captured_proof = [self.valid.proof]

        def emit(encoded):
            frame = json.loads(encoded)
            with condition:
                frames.append(frame)
                condition.notify_all()

        def wait(kind, identifier):
            deadline = monotonic() + 5
            with condition:
                while True:
                    matching = next((frame for frame in frames
                                     if frame["type"] == kind and frame.get("id") == identifier), None)
                    if matching is not None:
                        return matching
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        self.fail(f"Missing {kind} frame for request {identifier}")
                    condition.wait(remaining)

        def capture(*args, **kwargs):
            fake_capture(*args, **kwargs)
            # Real capture structurally parses its transcript before returning;
            # reproduce that step to detect a second actual parse in the service.
            if captured_proof[0] != b"\x02\x01":
                protocol.parse_proof(captured_proof[0], args[1], args[2])
            return SimpleNamespace(encoded_proof=captured_proof[0])

        with ExitStack() as stack:
            stack.enter_context(patch.object(service, "resolve_endpoints", return_value=(endpoint(),)))
            stack.enter_context(patch.object(service, "capture_tls13_proof", side_effect=capture))
            # Only fixture trust is substituted: parsing, certificate checks,
            # signatures and work comparisons execute the production code.
            stack.enter_context(patch.object(service, "validate_root_bundle", side_effect=
                lambda path, version: verify.validate_root_bundle(path, version, enforce_root_pin=False)))
            stack.enter_context(patch.object(service, "verify_connection_proof", side_effect=
                lambda envelope, path: verify.verify_connection_proof(envelope, path, enforce_root_pin=False)))
            worker = service.ClaimsService({"connectionsPerSecond": 256, "concurrency": 1},
                                           emit, claims_bridge.parse_context, self.roots_path)
            try:
                worker.command({"type": "resolve", "id": 1, "domain": "example.com"})
                self.assertTrue(wait("resolved", 1)["ok"])
                for identifier, (label, envelope, target, validation_passed, verified) in enumerate(cases, 2):
                    with self.subTest(case=label):
                        captured_proof[0] = envelope.proof
                        before = protocol.parse_proof.cache_info()
                        worker.command({"type": "attempt", "id": identifier,
                                        "context": public_context(connection_work_target=target),
                                        "bountyId": f"{identifier:064x}:0", "successfulConnections": "0"})
                        result = wait("attempt", identifier)
                        self.assertTrue(result["captured"])
                        self.assertIs(result["validationPassed"], validation_passed)
                        self.assertIs(result["verified"], verified)
                        self.assertEqual(result["proof"], envelope.proof.hex() if verified else None)
                        self.assertEqual(result["successfulConnections"], "1")
                        after = protocol.parse_proof.cache_info()
                        self.assertEqual(after.misses - before.misses, 0 if label == "below target" else 1)
            finally:
                worker.close()
                worker.executor.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
