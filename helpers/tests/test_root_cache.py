"""Offline regressions for content-keyed trust-anchor parsing reuse."""

from __future__ import annotations

import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

HELPERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPERS))
import claims_bridge  # Establish the same vendored import path as production.
from connectcoin_p2c_tools import verify
from connectcoin_p2c_tools.errors import P2CError, ProofVerificationError
from cryptography.hazmat.primitives import serialization
from test_rsa_exponent_limits import LIMIT_ERROR, _rsa_certificate
from test_verifier_security import certificate, signed_proof

PEM = serialization.Encoding.PEM
PINNED_ROOTS = HELPERS / "p2c_roots_v1.pem"


class RootCacheTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="connectwallet-root-cache-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        verify._parse_roots.cache_clear()
        self.addCleanup(verify._parse_roots.cache_clear)

    def test_warm_cache_still_checks_current_file_pin_version_and_read_errors(self):
        path = self.directory / "roots.pem"
        encoded = PINNED_ROOTS.read_bytes()
        path.write_bytes(encoded)
        verify.validate_root_bundle(path, 1)
        with self.assertRaisesRegex(ProofVerificationError, "unsupported root_certificates_version"):
            verify.validate_root_bundle(path, 2)
        # Even a PEM-equivalent whitespace edit must fail the exact consensus pin.
        path.write_bytes(encoded + b"\n")
        with self.assertRaisesRegex(ProofVerificationError, "SHA-256 pin"):
            verify.validate_root_bundle(path, 1)
        path.unlink()
        with self.assertRaisesRegex(ProofVerificationError, "cannot read trusted root bundle"):
            verify.validate_root_bundle(path, 1)

    def test_changed_path_and_unpinned_fixture_cannot_reuse_or_poison_trust(self):
        verify.validate_root_bundle(PINNED_ROOTS, 1)
        root = certificate(201, "Cache fixture root", ca=True)
        leaf = certificate(202, "Cache fixture leaf", issuer=root, dns_name="example.com")
        proof = signed_proof("example.com", leaf, [])
        path = self.directory / "private-roots.pem"
        path.write_bytes(root[1].public_bytes(PEM))
        self.assertEqual(verify.verify_connection_proof(
            proof, path, enforce_root_pin=False).certificate_count, 1)
        # The same content is cached now, but the public API must still enforce pinning.
        with self.assertRaisesRegex(ProofVerificationError, "SHA-256 pin"):
            verify.verify_connection_proof(proof, path)
        with self.assertRaisesRegex(ProofVerificationError, "certificate path or domain"):
            verify.verify_connection_proof(proof, PINNED_ROOTS)
        verify.validate_root_bundle(PINNED_ROOTS, 1)

    def test_unpinned_file_replacement_changes_trust_even_at_same_path(self):
        root = certificate(211, "Original fixture root", ca=True)
        replacement = certificate(212, "Replacement fixture root", ca=True)
        leaf = certificate(213, "Cache fixture leaf", issuer=root, dns_name="example.com")
        proof = signed_proof("example.com", leaf, [])
        path = self.directory / "roots.pem"
        path.write_bytes(root[1].public_bytes(PEM))
        verify.verify_connection_proof(proof, path, enforce_root_pin=False)
        path.write_bytes(replacement[1].public_bytes(PEM))
        with self.assertRaisesRegex(ProofVerificationError, "certificate path or domain"):
            verify.verify_connection_proof(proof, path, enforce_root_pin=False)
        self.assertEqual(verify._load_roots(path, 1, False), [replacement[1]])

    def test_warm_roots_do_not_cache_proof_validation_outcomes(self):
        root = certificate(221, "Validation fixture root", ca=True)
        leaf = certificate(222, "Valid fixture leaf", issuer=root, dns_name="example.com")
        wrong_name = certificate(223, "Wrong fixture leaf", issuer=root, dns_name="wrong.example")
        valid = signed_proof("example.com", leaf, [])
        invalid = (
            signed_proof("example.com", wrong_name, []),
            replace(valid, proof=valid.proof[:-1] + bytes([valid.proof[-1] ^ 1])),
            replace(valid, validation_time=2_100_000_000),
            replace(valid, txid="ab" * 32),
            replace(valid, signature_algorithms_mask=2),
            replace(valid, connection_work_target="00" * 32),
        )
        path = self.directory / "roots.pem"
        path.write_bytes(root[1].public_bytes(PEM))
        verify.verify_connection_proof(valid, path, enforce_root_pin=False)
        for proof in invalid:
            with self.subTest(proof=proof), self.assertRaises(P2CError):
                verify.verify_connection_proof(proof, path, enforce_root_pin=False)
        self.assertEqual(verify.verify_connection_proof(
            valid, path, enforce_root_pin=False).challenge, valid.challenge.hex())

    def test_oversized_rsa_roots_are_rejected_after_cache_warmup_and_on_retry(self):
        root = certificate(231, "RSA guard fixture root", ca=True)
        path = self.directory / "roots.pem"
        path.write_bytes(root[1].public_bytes(PEM))
        verify.validate_root_bundle(path, 1, enforce_root_pin=False)
        for pss in (False, True):
            oversized = _rsa_certificate((1 << 64) + 1, pss=pss)
            path.write_bytes(root[1].public_bytes(PEM) + oversized.public_bytes(PEM))
            for _ in range(2):
                with self.subTest(pss=pss), self.assertRaisesRegex(ProofVerificationError, LIMIT_ERROR):
                    verify.validate_root_bundle(path, 1, enforce_root_pin=False)

    def test_concurrent_callers_cannot_mutate_shared_roots_and_parsing_is_reused(self):
        with patch.object(verify.x509, "load_pem_x509_certificates",
                          wraps=verify.x509.load_pem_x509_certificates) as parse:
            expected = verify._load_roots(PINNED_ROOTS, 1, True)

            def load_and_mutate(_):
                roots = verify._load_roots(PINNED_ROOTS, 1, True)
                self.assertEqual(roots, expected)
                roots.pop()
                return roots

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(load_and_mutate, range(64)))
            self.assertEqual(verify._load_roots(PINNED_ROOTS, 1, True), expected)
            self.assertEqual(len({id(roots) for roots in results}), len(results))
            self.assertEqual(parse.call_count, 1)

    def test_cache_retains_only_one_bundle(self):
        for serial in range(241, 245):
            root = certificate(serial, "Bounded cache fixture root", ca=True)
            path = self.directory / f"roots-{serial}.pem"
            path.write_bytes(root[1].public_bytes(PEM))
            verify.validate_root_bundle(path, 1, enforce_root_pin=False)
            self.assertEqual(verify._parse_roots.cache_info().currsize, 1)


if __name__ == "__main__":
    unittest.main()
