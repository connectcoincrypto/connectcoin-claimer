from __future__ import annotations

from dataclasses import dataclass

from .errors import ProofFormatError


@dataclass(frozen=True, slots=True)
class SignatureAlgorithm:
    mask: int
    scheme: int
    name: str


SIGNATURE_ALGORITHMS = (
    SignatureAlgorithm(1, 0x0403, "ecdsa_secp256r1_sha256"),
    SignatureAlgorithm(2, 0x0804, "rsa_pss_rsae_sha256"),
    SignatureAlgorithm(4, 0x0809, "rsa_pss_pss_sha256"),
)


def validate_signature_algorithms_mask(value: object) -> int:
    """Require the exact on-chain policy; missing values never imply all schemes."""
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 7:
        raise ProofFormatError("signature_algorithms_mask must be an integer between 1 and 7")
    return value


def accepted_signature_algorithms(mask: int) -> tuple[SignatureAlgorithm, ...]:
    validate_signature_algorithms_mask(mask)
    return tuple(algorithm for algorithm in SIGNATURE_ALGORITHMS if mask & algorithm.mask)


def signature_scheme_allowed(mask: int, scheme: int) -> bool:
    """Compare the selected CertificateVerify scheme, not all ClientHello offers."""
    return any(algorithm.scheme == scheme for algorithm in accepted_signature_algorithms(mask))
