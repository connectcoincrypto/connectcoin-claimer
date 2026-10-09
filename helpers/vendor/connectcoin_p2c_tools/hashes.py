from __future__ import annotations

import hashlib

CLAIM_TAG = b"ConnectCoin/P2C/claim/v1"
WORK_TAG = b"ConnectCoin/P2C/work/v2"


def tagged_hash(tag: bytes, message: bytes) -> bytes:
    """Return SHA256(SHA256(tag) || SHA256(tag) || message)."""
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _display_hash_to_internal(value: str, name: str) -> bytes:
    if len(value) != 64:
        raise ValueError(f"{name} must contain exactly 64 lowercase hexadecimal characters")
    if value != value.lower():
        raise ValueError(f"{name} must use lowercase hexadecimal")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{name} must contain exactly 64 lowercase hexadecimal characters")
    try:
        encoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"{name} must contain exactly 64 lowercase hexadecimal characters"
        ) from exc
    return encoded[::-1]


def internal_hash_to_display(value: bytes) -> str:
    if len(value) != 32:
        raise ValueError("an internal hash must contain exactly 32 bytes")
    return value[::-1].hex()


def claim_challenge(txid: str, input_index: int) -> bytes:
    """Calculate the raw bytes placed verbatim in TLS ClientHello.random."""
    if isinstance(input_index, bool) or not isinstance(input_index, int):
        raise ValueError("input_index must be an unsigned 32-bit integer")
    if not 0 <= input_index <= 0xFFFFFFFF:
        raise ValueError("input_index must fit in an unsigned 32-bit integer")
    internal_txid = _display_hash_to_internal(txid, "txid")
    return tagged_hash(CLAIM_TAG, internal_txid + input_index.to_bytes(4, "little"))


def connection_work_hash(messages: tuple[bytes, bytes, bytes, bytes]) -> bytes:
    """Hash full CH, SH, EE and Certificate messages, including handshake headers.

    The proof version byte and the entire CertificateVerify message are excluded.
    CertificateVerify must still be parsed and authenticated separately.
    """
    if len(messages) != 4:
        raise ValueError("P2C v2 work requires exactly four messages, excluding CertificateVerify")
    return tagged_hash(WORK_TAG, b"".join(messages))


def meets_work_target(work_hash: bytes, target: str) -> bool:
    """Match Core's uint256 numeric comparison (display hex is big-endian)."""
    if len(work_hash) != 32:
        raise ValueError("work hash must contain exactly 32 bytes")
    target_internal = _display_hash_to_internal(target, "connection_work_target")
    return int.from_bytes(work_hash, "little") <= int.from_bytes(target_internal, "little")
