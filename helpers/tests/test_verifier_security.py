"""Offline regression proofs for the certificate provider security advisories.

The complete signed proofs traverse the wallet's vendored verifier and its real
certificate-depth limit. Only these tests opt out of the immutable root pin to
use private, generated trust anchors; no live TLS or DNS traffic is involved.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

HELPERS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HELPERS))
import claims_bridge  # Establish the same vendored import path as production.
from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.errors import ProofVerificationError
from connectcoin_p2c_tools.protocol import MAX_CERTIFICATES
from connectcoin_p2c_tools.verify import verify_connection_proof
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VALIDATION_TIME = 1_800_000_000


def certificate(serial, name, *, issuer=None, ca=False, dns_name=None, permitted=None):
    # Public fixture keys only. Fixed scalars/times make the cases reproducible.
    key = ec.derive_private_key(serial, ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_key, issuer_name = (issuer[0], issuer[1].subject) if issuer else (key, subject)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(datetime(2025, 1, 1, tzinfo=UTC))
               .not_valid_after(datetime(2035, 1, 1, tzinfo=UTC))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
               .add_extension(x509.KeyUsage(True, False, False, False, False,
                                            ca, ca, None, None), True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   issuer_key.public_key()), False))
    if dns_name is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]), False)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    if permitted is not None:
        builder = builder.add_extension(x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(permitted)], excluded_subtrees=None), True)
    return key, builder.sign(issuer_key, hashes.SHA256())


def signed_proof(domain, leaf, intermediates):
    """Encode a structurally valid P2C v2 transcript signed by the fixture leaf."""
    def u16(value):
        return value.to_bytes(2, "big")

    def u24(value):
        return value.to_bytes(3, "big")

    def extension(kind, body):
        return u16(kind) + u16(len(body)) + body

    def handshake(kind, body):
        return bytes([kind]) + u24(len(body)) + body

    envelope = ConnectionProof(
        domain=domain, txid="01" * 32, input_index=0,
        connection_work_target="ff" * 32, root_certificates_version=1,
        signature_algorithms_mask=1, validation_time=VALIDATION_TIME, proof=b"",
    )
    sni = b"\x00" + u16(len(domain)) + domain.encode("ascii")
    client_extensions = b"".join((
        extension(0, u16(len(sni)) + sni), extension(43, b"\x02\x03\x04"),
        extension(13, b"\x00\x02\x04\x03"),
        extension(51, u16(36) + b"\x00\x1d\x00\x20" + b"\x01" * 32),
    ))
    client = handshake(1, b"\x03\x03" + envelope.challenge + b"\x00\x00\x02\x13\x01\x01\x00"
                       + u16(len(client_extensions)) + client_extensions)
    server_extensions = extension(43, b"\x03\x04") + extension(
        51, b"\x00\x1d\x00\x20" + b"\x02" * 32)
    server = handshake(2, b"\x03\x03" + b"\x03" * 32 + b"\x00\x13\x01\x00"
                       + u16(len(server_extensions)) + server_extensions)
    encrypted_extensions = handshake(8, b"\x00\x00")
    chain = [leaf[1], *intermediates]
    entries = b""
    for item in chain:
        encoded = item.public_bytes(serialization.Encoding.DER)
        entries += u24(len(encoded)) + encoded + b"\x00\x00"
    cert_message = handshake(11, b"\x00" + u24(len(entries)) + entries)
    transcript = client + server + encrypted_extensions + cert_message
    message = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + hashlib.sha256(transcript).digest()
    signature = leaf[0].sign(message, ec.ECDSA(hashes.SHA256()))
    cert_verify = handshake(15, b"\x04\x03" + u16(len(signature)) + signature)
    return dataclasses.replace(envelope, proof=b"\x02" + transcript + cert_verify)


def verify_fixture(proof, root):
    with tempfile.TemporaryDirectory(prefix="connectwallet-verifier-security-") as directory:
        roots_path = Path(directory) / "roots.pem"
        roots_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        return verify_connection_proof(proof, roots_path, enforce_root_pin=False)


def duplicate_chain_case():
    """GHSA-jwv3-5hgf-82ww: repeated untrusted self-signed issuers must terminate."""
    looping = certificate(10, "Self-signed untrusted issuer", ca=True)
    unrelated = certificate(11, "Unrelated trust anchor", ca=True)
    leaf = certificate(12, "Duplicate-chain leaf", issuer=looping, dns_name="example.com")
    proof = signed_proof("example.com", leaf, [looping[1]] * (MAX_CERTIFICATES - 1))
    # The same duplicate chain must pass when its issuer actually is trusted.
    accepted = verify_fixture(proof, looping[1])
    try:
        verify_fixture(proof, unrelated[1])
    except ProofVerificationError as exc:
        if "certificate path or domain validation failed" not in str(exc):
            raise
        return {"rejected": True, "positiveCertificateCount": accepted.certificate_count}
    raise AssertionError("Untrusted duplicate issuer chain was accepted")


class VerifierSecurityTests(unittest.TestCase):
    def test_uses_wallet_vendored_verifier(self):
        self.assertEqual(Path(sys.modules[verify_connection_proof.__module__].__file__).resolve(),
                         (HELPERS / "vendor/connectcoin_p2c_tools/verify.py").resolve())

    def test_duplicate_untrusted_self_signed_issuers_are_bounded(self):
        # Kill/wait are handled by subprocess.run on timeout, even on providers
        # where the verifier holds the GIL. No vulnerable child can hang CI.
        result = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--duplicate-chain"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), {
            "rejected": True, "positiveCertificateCount": MAX_CERTIFICATES,
        })

    def test_wildcard_cannot_escape_intermediate_permitted_subtree(self):
        # GHSA-m2h6-j472-rp4c: the scope of the entire SAN must fit within
        # nameConstraints, even when the requested hostname itself is permitted.
        root = certificate(20, "Name constraints root", ca=True)
        intermediate = certificate(21, "Constrained intermediate", issuer=root,
                                   ca=True, permitted="foo.example.com")
        leaf = certificate(22, "Overbroad wildcard", issuer=intermediate,
                           dns_name="*.example.com")
        for domain in ("bar.example.com", "foo.example.com"):
            with self.subTest(domain=domain):
                proof = signed_proof(domain, leaf, [intermediate[1]])
                with self.assertRaisesRegex(ProofVerificationError, "certificate path or domain validation failed"):
                    verify_fixture(proof, root[1])

    def test_permitted_exact_and_wildcard_names_still_verify(self):
        root = certificate(30, "Permitted names root", ca=True)
        intermediate = certificate(31, "Permitted names intermediate", issuer=root,
                                   ca=True, permitted="foo.example.com")
        for san, domain in (("foo.example.com", "foo.example.com"),
                            ("*.foo.example.com", "bar.foo.example.com")):
            with self.subTest(san=san, domain=domain):
                leaf = certificate(32, "Permitted leaf", issuer=intermediate, dns_name=san)
                proof = signed_proof(domain, leaf, [intermediate[1]])
                result = verify_fixture(proof, root[1])
                self.assertEqual(result.certificate_count, 2)
                self.assertEqual(result.challenge, proof.challenge.hex())


if __name__ == "__main__":
    if sys.argv[1:] == ["--duplicate-chain"]:
        print(json.dumps(duplicate_chain_case()))
    else:
        unittest.main()
