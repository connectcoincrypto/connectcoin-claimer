from __future__ import annotations

import hashlib
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .envelope import ConnectionProof
from .errors import ProofVerificationError
from .hashes import internal_hash_to_display, meets_work_target
from .protocol import (
    ECDSA_SECP256R1_SHA256,
    MAX_CERTIFICATES,
    RSA_PSS_PSS_SHA256,
    RSA_PSS_RSAE_SHA256,
    ParsedProof,
    parse_certificate_message,
    parse_proof,
)
from .signatures import signature_scheme_allowed

ROOTS_V1_SHA256 = "f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9"
MAX_RSA_PUBLIC_EXPONENT_BITS = 64
OID_RSA_ENCRYPTION = ObjectIdentifier("1.2.840.113549.1.1.1")
OID_RSASSA_PSS = ObjectIdentifier("1.2.840.113549.1.1.10")
TLS13_SERVER_CERTIFICATE_VERIFY_CONTEXT = b"TLS 1.3, server CertificateVerify"
_SHA256_OID_DER = bytes.fromhex("608648016503040201")
_MGF1_OID_DER = bytes.fromhex("2a864886f70d010108")
_RSASSA_PSS_OID_DER = bytes.fromhex("2a864886f70d01010a")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    challenge: str
    transcript_hash: str
    connection_work_hash: str
    certificate_count: int
    certificate_verify_scheme: int
    signature_algorithms_mask: int


def _check_rsa_public_exponents(certificates: Iterable[x509.Certificate]) -> None:
    """Apply Core's bound to every RSA/RSA-PSS certificate, not just its leaf.

    Checking the integer is cheap and precedes path/signature verification.
    There is no small-modulus exemption; a DER sign-padding byte is not a bit
    of the mathematical exponent. PSS keys retain their original restrictions.
    """
    for certificate in certificates:
        if certificate.public_key_algorithm_oid not in {OID_RSA_ENCRYPTION, OID_RSASSA_PSS}:
            continue
        try:
            public_key = certificate.public_key()
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("RSA certificate did not contain an RSA public key")
            exponent = public_key.public_numbers().e
        except (UnsupportedAlgorithm, ValueError) as exc:
            raise ProofVerificationError(
                "invalid or unsupported certificate RSA public key"
            ) from exc
        if exponent.bit_length() > MAX_RSA_PUBLIC_EXPONENT_BITS:
            raise ProofVerificationError("P2C certificate RSA public exponent exceeds 64 bits")


def _load_certificate_chain(encoded_chain: tuple[bytes, ...]) -> list[x509.Certificate]:
    certificates: list[x509.Certificate] = []
    for position, encoded in enumerate(encoded_chain):
        try:
            certificates.append(x509.load_der_x509_certificate(encoded))
        except ValueError as exc:
            raise ProofVerificationError(
                f"certificate {position} is not a valid DER X.509 certificate"
            ) from exc
    _check_rsa_public_exponents(certificates)
    return certificates


def _load_certificates(parsed: ParsedProof) -> list[x509.Certificate]:
    return _load_certificate_chain(parsed.certificate_chain)


def validate_certificate_message(message: bytes) -> None:
    """Preflight captured certificates; this does not authenticate their path."""
    _load_certificate_chain(parse_certificate_message(message))


def _load_roots(path: str | Path, version: int, enforce_root_pin: bool) -> list[x509.Certificate]:
    try:
        encoded = Path(path).read_bytes()
    except OSError as exc:
        raise ProofVerificationError(f"cannot read trusted root bundle: {exc}") from exc
    if version != 1:
        raise ProofVerificationError(f"unsupported root_certificates_version {version}")
    if enforce_root_pin and hashlib.sha256(encoded).hexdigest() != ROOTS_V1_SHA256:
        raise ProofVerificationError(
            "root bundle version 1 does not match its consensus SHA-256 pin"
        )
    # Always read and authenticate the current file before reusing parsed roots.
    # Each caller owns its list; only immutable certificate objects are shared.
    return list(_parse_roots(encoded))


@lru_cache(maxsize=1)
def _parse_roots(encoded: bytes) -> tuple[x509.Certificate, ...]:
    """Reuse only root parsing/key checks, keyed by exact bytes, never proof validity."""
    try:
        # The immutable Mozilla-derived bundle contains legacy trust anchors
        # that modern WebPKI would not issue today. They remain parseable in
        # the version range pinned by this project and are consensus data.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            roots = x509.load_pem_x509_certificates(encoded)
    except ValueError as exc:
        raise ProofVerificationError("trusted root bundle is not valid PEM") from exc
    if not roots:
        raise ProofVerificationError("trusted root bundle contains no certificates")
    _check_rsa_public_exponents(roots)
    return tuple(roots)


def validate_root_bundle(
    roots_path: str | Path, root_certificates_version: int, *, enforce_root_pin: bool = True
) -> None:
    """Validate a root bundle before a potentially long proof search."""
    _load_roots(roots_path, root_certificates_version, enforce_root_pin)


def _check_supplied_certificate_times(
    certificates: list[x509.Certificate], validation_time: int
) -> None:
    try:
        moment = datetime.fromtimestamp(validation_time, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise ProofVerificationError("validation_time cannot be represented") from exc
    for position, certificate in enumerate(certificates):
        if moment < certificate.not_valid_before_utc or moment > certificate.not_valid_after_utc:
            raise ProofVerificationError(
                f"certificate {position} is not valid at the requested block median time"
            )


def _check_leaf_usage(leaf: x509.Certificate) -> None:
    try:
        key_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        pass
    else:
        if not key_usage.digital_signature:
            raise ProofVerificationError("leaf certificate does not permit digital signatures")
    try:
        extended_usage = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        pass
    else:
        any_usage = ObjectIdentifier("2.5.29.37.0")
        if (
            ExtendedKeyUsageOID.SERVER_AUTH not in extended_usage
            and any_usage not in extended_usage
        ):
            raise ProofVerificationError(
                "leaf certificate is not valid for TLS server authentication"
            )


def _verify_path(
    certificates: list[x509.Certificate],
    roots: list[x509.Certificate],
    domain: str,
    validation_time: int,
) -> None:
    try:
        moment = datetime.fromtimestamp(validation_time, UTC)
        verifier = (
            PolicyBuilder()
            .store(Store(roots))
            .time(moment)
            .max_chain_depth(MAX_CERTIFICATES - 1)
            .build_server_verifier(x509.DNSName(domain))
        )
        verifier.verify(certificates[0], certificates[1:])
    except (OSError, OverflowError, ValueError, VerificationError) as exc:
        raise ProofVerificationError(
            f"certificate path or domain validation failed: {exc}"
        ) from exc


def _certificate_verify_message(transcript_hash: bytes) -> bytes:
    return b"\x20" * 64 + TLS13_SERVER_CERTIFICATE_VERIFY_CONTEXT + b"\x00" + transcript_hash


def _der_elements(encoded: bytes) -> list[tuple[int, bytes]]:
    """Read bounded DER TLVs without reserializing away a PSS key's restrictions."""
    elements: list[tuple[int, bytes]] = []
    position = 0
    while position < len(encoded):
        if len(encoded) - position < 2:
            raise ValueError("truncated DER element")
        tag, length = encoded[position : position + 2]
        position += 2
        if tag & 0x1F == 0x1F:
            raise ValueError("unexpected high-tag-number DER element")
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4 or len(encoded) - position < count:
                raise ValueError("invalid DER length")
            length_bytes = encoded[position : position + count]
            position += count
            length = int.from_bytes(length_bytes, "big")
            if length_bytes[0] == 0 or length < 128:
                raise ValueError("noncanonical DER length")
        if length > len(encoded) - position:
            raise ValueError("truncated DER value")
        elements.append((tag, encoded[position : position + length]))
        position += length
    return elements


def _der_single(encoded: bytes, expected_tag: int) -> bytes:
    elements = _der_elements(encoded)
    if len(elements) != 1 or elements[0][0] != expected_tag:
        raise ValueError("unexpected DER element")
    return elements[0][1]


def _sha256_algorithm(encoded: bytes) -> bool:
    fields = _der_elements(encoded)
    return bool(
        fields
        and fields[0] == (0x06, _SHA256_OID_DER)
        and (len(fields) == 1 or (len(fields) == 2 and fields[1] == (0x05, b"")))
    )


def _der_nonnegative_integer(encoded: bytes) -> int:
    value = _der_single(encoded, 0x02)
    if (
        not value
        or len(value) > 4
        or value[0] & 0x80
        or (len(value) > 1 and value[0] == 0 and not value[1] & 0x80)
    ):
        raise ValueError("invalid nonnegative DER integer")
    return int.from_bytes(value, "big")


def _check_pss_key_restrictions(leaf: x509.Certificate) -> None:
    """Apply Core's RFC 4055 SPKI restrictions before generic RSA arithmetic.

    Cryptography exposes PSS public keys as RSAPublicKey; their original
    AlgorithmIdentifier parameters must not be lost by reserializing that key.
    Absent PSS parameters are unrestricted, but a present empty SEQUENCE means
    SHA-1 / MGF1-SHA-1 / minimum salt 20, not an unrestricted SHA-256 key.
    """
    try:
        tbs = _der_elements(_der_single(leaf.tbs_certificate_bytes, 0x30))
        # Optional version, serial, signature, issuer, validity, subject, SPKI.
        spki_index = 6 if tbs and tbs[0][0] == 0xA0 else 5
        if len(tbs) <= spki_index or tbs[spki_index][0] != 0x30:
            raise ValueError("missing SubjectPublicKeyInfo")
        spki = _der_elements(tbs[spki_index][1])
        if len(spki) != 2 or spki[0][0] != 0x30 or spki[1][0] != 0x03:
            raise ValueError("invalid SubjectPublicKeyInfo")
        algorithm = _der_elements(spki[0][1])
        if not algorithm or algorithm[0] != (0x06, _RSASSA_PSS_OID_DER):
            raise ValueError("not an id-RSASSA-PSS key")
        if len(algorithm) == 1:
            return  # RFC 4055: absent parameters impose no PSS restrictions.
        if len(algorithm) != 2 or algorithm[1][0] != 0x30:
            raise ValueError("invalid RSASSA-PSS parameters")
        hash_is_sha256 = False
        mgf1_is_sha256 = False
        minimum_salt = 20
        previous_tag = 0x9F
        for tag, value in _der_elements(algorithm[1][1]):
            if tag not in {0xA0, 0xA1, 0xA2, 0xA3} or tag <= previous_tag:
                raise ValueError("invalid RSASSA-PSS parameter order")
            if tag == 0xA0:
                hash_is_sha256 = _sha256_algorithm(_der_single(value, 0x30))
            elif tag == 0xA1:
                mgf = _der_elements(_der_single(value, 0x30))
                mgf1_is_sha256 = bool(
                    len(mgf) == 2
                    and mgf[0] == (0x06, _MGF1_OID_DER)
                    and mgf[1][0] == 0x30
                    and _sha256_algorithm(mgf[1][1])
                )
            elif tag == 0xA2:
                minimum_salt = _der_nonnegative_integer(value)
            elif _der_nonnegative_integer(value) != 1:
                raise ValueError("unsupported RSASSA-PSS trailer field")
            previous_tag = tag
        if not hash_is_sha256 or not mgf1_is_sha256 or minimum_salt > 32:
            raise ValueError("key does not permit SHA-256 / MGF1-SHA-256 / salt length 32")
    except ValueError as exc:
        raise ProofVerificationError(
            f"leaf RSA-PSS key restrictions do not permit CertificateVerify: {exc}"
        ) from exc


def _verify_certificate_signature(leaf: x509.Certificate, parsed: ParsedProof) -> None:
    _check_rsa_public_exponents((leaf,))
    message = _certificate_verify_message(parsed.transcript_hash)
    scheme = parsed.certificate_verify_scheme
    try:
        if scheme == RSA_PSS_PSS_SHA256 and leaf.public_key_algorithm_oid == OID_RSASSA_PSS:
            _check_pss_key_restrictions(leaf)
        public_key = leaf.public_key()
        if scheme == ECDSA_SECP256R1_SHA256:
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                public_key.curve, ec.SECP256R1
            ):
                raise ProofVerificationError(
                    "CertificateVerify ECDSA scheme does not match a P-256 leaf key"
                )
            public_key.verify(
                parsed.certificate_verify_signature, message, ec.ECDSA(hashes.SHA256())
            )
        elif scheme in {RSA_PSS_RSAE_SHA256, RSA_PSS_PSS_SHA256}:
            if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
                raise ProofVerificationError(
                    "CertificateVerify RSA-PSS scheme requires an RSA key of at least 2048 bits"
                )
            expected_oid = OID_RSA_ENCRYPTION if scheme == RSA_PSS_RSAE_SHA256 else OID_RSASSA_PSS
            if leaf.public_key_algorithm_oid != expected_oid:
                raise ProofVerificationError(
                    "CertificateVerify RSA-PSS scheme does not match the leaf key encoding"
                )
            public_key.verify(
                parsed.certificate_verify_signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        else:  # Protected by the structural parser.
            raise ProofVerificationError("unsupported CertificateVerify signature scheme")
    except InvalidSignature as exc:
        raise ProofVerificationError("invalid TLS 1.3 CertificateVerify signature") from exc
    except ProofVerificationError:
        raise
    except (UnsupportedAlgorithm, ValueError) as exc:
        raise ProofVerificationError("invalid or unsupported leaf public key") from exc


def verify_connection_proof(
    envelope: ConnectionProof,
    roots_path: str | Path,
    *,
    enforce_root_pin: bool = True,
) -> VerificationResult:
    parsed = parse_proof(envelope.proof, envelope.domain, envelope.challenge)
    if not signature_scheme_allowed(
        envelope.signature_algorithms_mask, parsed.certificate_verify_scheme
    ):
        raise ProofVerificationError(
            "CertificateVerify signature scheme is not allowed by the output "
            "signature_algorithms_mask"
        )
    if not meets_work_target(parsed.connection_work_hash, envelope.connection_work_target):
        raise ProofVerificationError("connection work hash exceeds the output target")
    certificates = _load_certificates(parsed)
    roots = _load_roots(roots_path, envelope.root_certificates_version, enforce_root_pin)
    _check_supplied_certificate_times(certificates, envelope.validation_time)
    _check_leaf_usage(certificates[0])
    _verify_path(certificates, roots, envelope.domain, envelope.validation_time)
    _verify_certificate_signature(certificates[0], parsed)
    return VerificationResult(
        challenge=envelope.challenge.hex(),
        transcript_hash=parsed.transcript_hash.hex(),
        connection_work_hash=internal_hash_to_display(parsed.connection_work_hash),
        certificate_count=len(parsed.certificate_chain),
        certificate_verify_scheme=parsed.certificate_verify_scheme,
        signature_algorithms_mask=envelope.signature_algorithms_mask,
    )
