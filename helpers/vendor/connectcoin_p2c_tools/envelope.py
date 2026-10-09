from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .domain import is_canonical_domain
from .errors import ProofFormatError
from .hashes import claim_challenge
from .signatures import validate_signature_algorithms_mask

FORMAT = "connectcoin-p2c-proof"
ENVELOPE_VERSION = 2


def _require_exact_keys(value: dict[str, Any]) -> None:
    expected = {
        "format",
        "version",
        "domain",
        "txid",
        "input_index",
        "connection_work_target",
        "root_certificates_version",
        "signature_algorithms_mask",
        "validation_time",
        "proof",
    }
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ProofFormatError(f"connection-proof.json is missing: {', '.join(sorted(missing))}")
    if extra:
        raise ProofFormatError(
            f"connection-proof.json has unknown fields: {', '.join(sorted(extra))}"
        )


def _require_hex(value: object, name: str, exact_size: int | None = None) -> str:
    if not isinstance(value, str) or value != value.lower() or not value:
        raise ProofFormatError(f"{name} must be non-empty lowercase hexadecimal")
    if len(value) % 2 != 0:
        raise ProofFormatError(f"{name} must contain whole bytes")
    if any(character not in "0123456789abcdef" for character in value):
        raise ProofFormatError(f"{name} must be non-empty lowercase hexadecimal")
    encoded = bytes.fromhex(value)
    if exact_size is not None and len(encoded) != exact_size:
        raise ProofFormatError(f"{name} must contain exactly {exact_size} bytes")
    return value


def _require_uint(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ProofFormatError(f"{name} must be an integer between 0 and {maximum}")
    return value


@dataclass(frozen=True, slots=True)
class ConnectionProof:
    domain: str
    txid: str
    input_index: int
    connection_work_target: str
    root_certificates_version: int
    signature_algorithms_mask: int
    validation_time: int
    proof: bytes
    version: int = ENVELOPE_VERSION

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != ENVELOPE_VERSION:
            raise ProofFormatError("only connection proof envelope version 2 is supported")
        if not isinstance(self.domain, str) or not is_canonical_domain(self.domain):
            raise ProofFormatError("domain is not canonical lower-case ASCII DNS form")
        _require_hex(self.txid, "txid", 32)
        _require_hex(self.connection_work_target, "connection_work_target", 32)
        _require_uint(self.input_index, "input_index", 0xFFFFFFFF)
        roots_version = _require_uint(
            self.root_certificates_version, "root_certificates_version", 0xFFFFFFFF
        )
        if roots_version == 0:
            raise ProofFormatError("root_certificates_version must not be zero")
        validate_signature_algorithms_mask(self.signature_algorithms_mask)
        validation_time = _require_uint(self.validation_time, "validation_time", 0x7FFFFFFFFFFFFFFF)
        if validation_time == 0:
            raise ProofFormatError("validation_time must be positive")
        if not isinstance(self.proof, bytes):
            raise ProofFormatError("proof must contain bytes")
        if len(self.proof) > 64 * 1024:
            raise ProofFormatError("proof exceeds the 64 KiB consensus limit")

    def _check_serialized_proof(self) -> None:
        # An empty proof is only allowed in an in-memory generation context.
        if not self.proof or self.proof[0] != 2:
            raise ProofFormatError("serialized proof must begin with P2C proof version 2")

    @classmethod
    def from_dict(cls, value: object) -> ConnectionProof:
        if not isinstance(value, dict):
            raise ProofFormatError("connection-proof.json must contain one JSON object")
        _require_exact_keys(value)
        if value["format"] != FORMAT:
            raise ProofFormatError(f"format must be {FORMAT!r}")
        if type(value["version"]) is not int or value["version"] != ENVELOPE_VERSION:
            raise ProofFormatError("only connection proof envelope version 2 is supported")
        domain = value["domain"]
        if not isinstance(domain, str) or not is_canonical_domain(domain):
            raise ProofFormatError("domain is not canonical lower-case ASCII DNS form")
        txid = _require_hex(value["txid"], "txid", 32)
        target = _require_hex(value["connection_work_target"], "connection_work_target", 32)
        input_index = _require_uint(value["input_index"], "input_index", 0xFFFFFFFF)
        roots_version = _require_uint(
            value["root_certificates_version"], "root_certificates_version", 0xFFFFFFFF
        )
        if roots_version == 0:
            raise ProofFormatError("root_certificates_version must not be zero")
        signature_mask = validate_signature_algorithms_mask(value["signature_algorithms_mask"])
        validation_time = _require_uint(
            value["validation_time"], "validation_time", 0x7FFFFFFFFFFFFFFF
        )
        if validation_time == 0:
            raise ProofFormatError("validation_time must be positive")
        proof_hex = _require_hex(value["proof"], "proof")
        proof = bytes.fromhex(proof_hex)
        if len(proof) > 64 * 1024:
            raise ProofFormatError("proof exceeds the 64 KiB consensus limit")
        result = cls(
            domain=domain,
            txid=txid,
            input_index=input_index,
            connection_work_target=target,
            root_certificates_version=roots_version,
            signature_algorithms_mask=signature_mask,
            validation_time=validation_time,
            proof=proof,
        )
        # Validate hash input spellings and ranges eagerly.
        claim_challenge(result.txid, result.input_index)
        result._check_serialized_proof()
        return result

    @classmethod
    def read(cls, path: str | Path) -> ConnectionProof:
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProofFormatError(f"cannot read connection proof: {exc}") from exc
        return cls.from_dict(value)

    def write(self, path: str | Path, *, overwrite: bool = False) -> None:
        destination = Path(path)
        if destination.exists() and not overwrite:
            raise ProofFormatError(f"refusing to overwrite existing file: {destination}")
        temporary = destination.with_name(destination.name + ".tmp")
        try:
            temporary.write_text(
                json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            temporary.replace(destination)
        except (OSError, UnicodeError) as exc:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise ProofFormatError(f"cannot write connection proof: {exc}") from exc

    def to_dict(self) -> dict[str, object]:
        self._check_serialized_proof()
        return {
            "format": FORMAT,
            "version": self.version,
            "domain": self.domain,
            "txid": self.txid,
            "input_index": self.input_index,
            "connection_work_target": self.connection_work_target,
            "root_certificates_version": self.root_certificates_version,
            "signature_algorithms_mask": self.signature_algorithms_mask,
            "validation_time": self.validation_time,
            "proof": self.proof.hex(),
        }

    @property
    def challenge(self) -> bytes:
        return claim_challenge(self.txid, self.input_index)
