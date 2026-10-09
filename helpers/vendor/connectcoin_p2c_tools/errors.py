class P2CError(ValueError):
    """A malformed or invalid P2C value."""


class ProofFormatError(P2CError):
    """A proof or its context does not use the canonical P2C v2 encoding."""


class ProofVerificationError(P2CError):
    """A structurally valid proof fails a cryptographic or policy check."""
