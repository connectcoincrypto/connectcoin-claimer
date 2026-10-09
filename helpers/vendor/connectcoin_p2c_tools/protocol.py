from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .domain import is_canonical_domain
from .errors import ProofFormatError
from .hashes import connection_work_hash

PROOF_VERSION = 2
MAX_PROOF_SIZE = 64 * 1024
MAX_CERTIFICATE_MESSAGE_SIZE = 48 * 1024
MAX_CERTIFICATES = 8
MAX_CERTIFICATE_SIZE = 16 * 1024

CLIENT_HELLO = 1
SERVER_HELLO = 2
ENCRYPTED_EXTENSIONS = 8
CERTIFICATE = 11
CERTIFICATE_VERIFY = 15

EXT_SERVER_NAME = 0
EXT_SIGNATURE_ALGORITHMS = 13
EXT_COMPRESS_CERTIFICATE = 27
EXT_PRE_SHARED_KEY = 41
EXT_EARLY_DATA = 42
EXT_SUPPORTED_VERSIONS = 43
EXT_COOKIE = 44
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D

TLS_1_2 = 0x0303
TLS_1_3 = 0x0304
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_CHACHA20_POLY1305_SHA256 = 0x1303
ECDSA_SECP256R1_SHA256 = 0x0403
RSA_PSS_RSAE_SHA256 = 0x0804
RSA_PSS_PSS_SHA256 = 0x0809
GROUP_SECP256R1 = 0x0017
GROUP_X25519 = 0x001D

HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


class _Reader:
    __slots__ = ("_data", "position")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self.position

    @property
    def empty(self) -> bool:
        return self.position == len(self._data)

    def read(self, size: int, what: str) -> bytes:
        if size < 0 or self.remaining < size:
            raise ProofFormatError(f"truncated {what}")
        start = self.position
        self.position += size
        return self._data[start : self.position]

    def u8(self, what: str) -> int:
        return self.read(1, what)[0]

    def u16(self, what: str) -> int:
        return int.from_bytes(self.read(2, what), "big")

    def u24(self, what: str) -> int:
        return int.from_bytes(self.read(3, what), "big")


@dataclass(frozen=True, slots=True)
class ParsedProof:
    client_hello: bytes
    server_hello: bytes
    encrypted_extensions: bytes
    certificate: bytes
    certificate_verify: bytes
    certificate_chain: tuple[bytes, ...]
    certificate_verify_scheme: int
    certificate_verify_signature: bytes
    transcript_hash: bytes
    connection_work_hash: bytes

    @property
    def messages(self) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        return (
            self.client_hello,
            self.server_hello,
            self.encrypted_extensions,
            self.certificate,
            self.certificate_verify,
        )


@dataclass(frozen=True, slots=True)
class _ClientState:
    cipher_suites: tuple[int, ...]
    signature_algorithms: tuple[int, ...]
    key_share_groups: tuple[int, ...]
    legacy_session_id: bytes


def _read_handshake(
    reader: _Reader, expected_type: int, maximum_size: int, name: str
) -> tuple[bytes, bytes]:
    start = reader.position
    message_type = reader.u8("TLS handshake header")
    size = reader.u24("TLS handshake header")
    if message_type != expected_type:
        raise ProofFormatError(f"expected {name} as the next TLS handshake message")
    if size + 4 > maximum_size:
        raise ProofFormatError(f"{name} exceeds the P2C size limit")
    body = reader.read(size, name)
    return reader._data[start : reader.position], body


def _extensions(reader: _Reader) -> dict[int, bytes]:
    total_size = reader.u16("TLS extensions length")
    if reader.remaining != total_size:
        raise ProofFormatError("invalid TLS extensions length")
    encoded = _Reader(reader.read(total_size, "TLS extensions"))
    result: dict[int, bytes] = {}
    while not encoded.empty:
        extension_type = encoded.u16("TLS extension type")
        extension_size = encoded.u16("TLS extension length")
        extension = encoded.read(extension_size, "TLS extension")
        if extension_type in result:
            raise ProofFormatError("duplicate TLS extension")
        result[extension_type] = extension
    return result


def _parse_sni(encoded: bytes, expected_domain: str) -> None:
    reader = _Reader(encoded)
    list_size = reader.u16("server_name list length")
    if list_size != reader.remaining:
        raise ProofFormatError("invalid server_name list length")
    name_type = reader.u8("server_name type")
    name_size = reader.u16("server_name length")
    name = reader.read(name_size, "server_name")
    if name_type != 0 or not reader.empty:
        raise ProofFormatError("ClientHello must contain exactly one DNS server_name")
    if name != expected_domain.encode("ascii"):
        raise ProofFormatError("ClientHello server_name does not match the P2C domain")


def _valid_key_share(group: int, exchange: bytes) -> bool:
    if group == GROUP_X25519:
        return len(exchange) == 32
    return group == GROUP_SECP256R1 and len(exchange) == 65 and exchange[0] == 4


def _parse_client_hello(body: bytes, domain: str, challenge: bytes) -> _ClientState:
    reader = _Reader(body)
    if reader.u16("ClientHello legacy version") != TLS_1_2:
        raise ProofFormatError("ClientHello legacy version must be TLS 1.2")
    if reader.read(32, "ClientHello.random") != challenge:
        raise ProofFormatError("ClientHello.random does not match the P2C claim challenge")
    session_size = reader.u8("ClientHello session id length")
    if session_size > 32:
        raise ProofFormatError("ClientHello session id exceeds 32 bytes")
    session_id = reader.read(session_size, "ClientHello session id")
    cipher_size = reader.u16("ClientHello cipher suites length")
    if cipher_size < 2 or cipher_size % 2:
        raise ProofFormatError("invalid ClientHello cipher suites length")
    encoded_ciphers = reader.read(cipher_size, "ClientHello cipher suites")
    cipher_suites = tuple(
        int.from_bytes(encoded_ciphers[offset : offset + 2], "big")
        for offset in range(0, len(encoded_ciphers), 2)
    )
    compression_size = reader.u8("ClientHello compression methods length")
    compression = reader.read(compression_size, "ClientHello compression methods")
    if compression_size != 1 or compression != b"\x00":
        raise ProofFormatError("ClientHello must offer only null compression")
    extensions = _extensions(reader)
    if not reader.empty:
        raise ProofFormatError("trailing bytes in ClientHello")

    required = {EXT_SERVER_NAME, EXT_SUPPORTED_VERSIONS, EXT_SIGNATURE_ALGORITHMS, EXT_KEY_SHARE}
    if not required.issubset(extensions):
        raise ProofFormatError("ClientHello is missing a required TLS 1.3 extension")
    _parse_sni(extensions[EXT_SERVER_NAME], domain)
    forbidden = {
        EXT_COMPRESS_CERTIFICATE,
        EXT_PRE_SHARED_KEY,
        EXT_EARLY_DATA,
        EXT_COOKIE,
        EXT_PSK_KEY_EXCHANGE_MODES,
        EXT_ENCRYPTED_CLIENT_HELLO,
    }
    if forbidden.intersection(extensions):
        raise ProofFormatError("ClientHello contains an extension forbidden by P2C v2")

    versions_reader = _Reader(extensions[EXT_SUPPORTED_VERSIONS])
    versions_size = versions_reader.u8("supported_versions length")
    if versions_size < 2 or versions_size % 2:
        raise ProofFormatError("invalid supported_versions extension")
    versions = versions_reader.read(versions_size, "supported_versions")
    if not versions_reader.empty:
        raise ProofFormatError("trailing bytes in supported_versions")
    offered_versions = {
        int.from_bytes(versions[offset : offset + 2], "big")
        for offset in range(0, len(versions), 2)
    }
    if TLS_1_3 not in offered_versions:
        raise ProofFormatError("ClientHello does not offer TLS 1.3")

    signatures_reader = _Reader(extensions[EXT_SIGNATURE_ALGORITHMS])
    signatures_size = signatures_reader.u16("signature_algorithms length")
    if signatures_size < 2 or signatures_size % 2:
        raise ProofFormatError("invalid signature_algorithms extension")
    signatures = signatures_reader.read(signatures_size, "signature_algorithms")
    if not signatures_reader.empty:
        raise ProofFormatError("trailing bytes in signature_algorithms")
    signature_algorithms = tuple(
        int.from_bytes(signatures[offset : offset + 2], "big")
        for offset in range(0, len(signatures), 2)
    )

    shares_reader = _Reader(extensions[EXT_KEY_SHARE])
    shares_size = shares_reader.u16("ClientHello key_share length")
    if shares_size == 0:
        raise ProofFormatError("ClientHello key_share list is empty")
    encoded_shares = _Reader(shares_reader.read(shares_size, "ClientHello key shares"))
    if not shares_reader.empty:
        raise ProofFormatError("trailing bytes in ClientHello key_share")
    groups: list[int] = []
    while not encoded_shares.empty:
        group = encoded_shares.u16("ClientHello key share group")
        exchange_size = encoded_shares.u16("ClientHello key share length")
        if exchange_size == 0:
            raise ProofFormatError("ClientHello key share is empty")
        exchange = encoded_shares.read(exchange_size, "ClientHello key share")
        if not _valid_key_share(group, exchange) or group in groups:
            raise ProofFormatError("invalid or duplicate ClientHello key share")
        groups.append(group)
    return _ClientState(cipher_suites, signature_algorithms, tuple(groups), session_id)


def _parse_server_hello(body: bytes, client: _ClientState) -> None:
    reader = _Reader(body)
    if reader.u16("ServerHello legacy version") != TLS_1_2:
        raise ProofFormatError("ServerHello legacy version must be TLS 1.2")
    random = reader.read(32, "ServerHello.random")
    if random == HELLO_RETRY_REQUEST_RANDOM:
        raise ProofFormatError("HelloRetryRequest is forbidden in P2C v2")
    session_size = reader.u8("ServerHello session id length")
    if session_size > 32:
        raise ProofFormatError("ServerHello session id exceeds 32 bytes")
    if reader.read(session_size, "ServerHello session id") != client.legacy_session_id:
        raise ProofFormatError("ServerHello session id does not match ClientHello")
    cipher_suite = reader.u16("ServerHello cipher suite")
    if cipher_suite not in {TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256}:
        raise ProofFormatError("P2C v2 requires a SHA-256 TLS 1.3 cipher suite")
    if cipher_suite not in client.cipher_suites:
        raise ProofFormatError("ServerHello selected an unoffered cipher suite")
    if reader.u8("ServerHello compression method") != 0:
        raise ProofFormatError("ServerHello compression method must be null")
    extensions = _extensions(reader)
    if not reader.empty:
        raise ProofFormatError("trailing bytes in ServerHello")
    if set(extensions) != {EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE}:
        raise ProofFormatError("ServerHello must contain only supported_versions and key_share")
    if extensions[EXT_SUPPORTED_VERSIONS] != TLS_1_3.to_bytes(2, "big"):
        raise ProofFormatError("ServerHello did not select TLS 1.3")
    key_share = _Reader(extensions[EXT_KEY_SHARE])
    group = key_share.u16("ServerHello key share group")
    exchange_size = key_share.u16("ServerHello key share length")
    if exchange_size == 0:
        raise ProofFormatError("ServerHello key share is empty")
    exchange = key_share.read(exchange_size, "ServerHello key share")
    if (
        not key_share.empty
        or not _valid_key_share(group, exchange)
        or group not in client.key_share_groups
    ):
        raise ProofFormatError("invalid or unoffered ServerHello key share")


def _parse_encrypted_extensions(body: bytes) -> None:
    reader = _Reader(body)
    extensions = _extensions(reader)
    if not reader.empty:
        raise ProofFormatError("trailing bytes in EncryptedExtensions")
    if EXT_EARLY_DATA in extensions:
        raise ProofFormatError("TLS early_data is forbidden in P2C v2")


def _parse_certificate(body: bytes) -> tuple[bytes, ...]:
    reader = _Reader(body)
    context_size = reader.u8("Certificate request context length")
    context = reader.read(context_size, "Certificate request context")
    if context:
        raise ProofFormatError("P2C Certificate request context must be empty")
    list_size = reader.u24("Certificate list length")
    if list_size == 0 or list_size != reader.remaining:
        raise ProofFormatError("invalid P2C Certificate list length")
    certificates_reader = _Reader(reader.read(list_size, "Certificate list"))
    result: list[bytes] = []
    while not certificates_reader.empty:
        certificate_size = certificates_reader.u24("certificate length")
        if not 1 <= certificate_size <= MAX_CERTIFICATE_SIZE:
            raise ProofFormatError("certificate entry exceeds the P2C size limit")
        certificate = certificates_reader.read(certificate_size, "certificate")
        extension_size = certificates_reader.u16("certificate extensions length")
        certificates_reader.read(extension_size, "certificate extensions")
        result.append(certificate)
        if len(result) > MAX_CERTIFICATES:
            raise ProofFormatError("P2C proof contains too many certificates")
    return tuple(result)


def parse_certificate_message(message: bytes) -> tuple[bytes, ...]:
    """Parse one bounded TLS Certificate before waiting for CertificateVerify."""
    reader = _Reader(message)
    _, body = _read_handshake(reader, CERTIFICATE, MAX_CERTIFICATE_MESSAGE_SIZE, "Certificate")
    if not reader.empty:
        raise ProofFormatError("trailing bytes after P2C Certificate")
    return _parse_certificate(body)


def _parse_certificate_verify(body: bytes, client: _ClientState) -> tuple[int, bytes]:
    reader = _Reader(body)
    scheme = reader.u16("CertificateVerify signature scheme")
    signature_size = reader.u16("CertificateVerify signature length")
    if signature_size == 0:
        raise ProofFormatError("CertificateVerify signature is empty")
    signature = reader.read(signature_size, "CertificateVerify signature")
    if not reader.empty:
        raise ProofFormatError("trailing bytes in CertificateVerify")
    if scheme not in {ECDSA_SECP256R1_SHA256, RSA_PSS_RSAE_SHA256, RSA_PSS_PSS_SHA256}:
        raise ProofFormatError("unsupported P2C CertificateVerify signature scheme")
    if scheme not in client.signature_algorithms:
        raise ProofFormatError("CertificateVerify used an unoffered signature scheme")
    return scheme, signature


def parse_proof(encoded: bytes, expected_domain: str, expected_challenge: bytes) -> ParsedProof:
    if not is_canonical_domain(expected_domain):
        raise ProofFormatError("expected domain is not canonical lower-case ASCII DNS form")
    if len(expected_challenge) != 32:
        raise ProofFormatError("expected challenge must contain exactly 32 bytes")
    if not encoded or len(encoded) > MAX_PROOF_SIZE:
        raise ProofFormatError("invalid P2C proof size")
    reader = _Reader(encoded)
    if reader.u8("P2C proof version") != PROOF_VERSION:
        raise ProofFormatError("unsupported P2C proof version")
    client_full, client_body = _read_handshake(reader, CLIENT_HELLO, 4096, "ClientHello")
    server_full, server_body = _read_handshake(reader, SERVER_HELLO, 2048, "ServerHello")
    encrypted_full, encrypted_body = _read_handshake(
        reader, ENCRYPTED_EXTENSIONS, 4096, "EncryptedExtensions"
    )
    certificate_full, certificate_body = _read_handshake(
        reader, CERTIFICATE, MAX_CERTIFICATE_MESSAGE_SIZE, "Certificate"
    )
    verify_full, verify_body = _read_handshake(
        reader, CERTIFICATE_VERIFY, 8192, "CertificateVerify"
    )
    if not reader.empty:
        raise ProofFormatError("trailing bytes after P2C CertificateVerify")

    client = _parse_client_hello(client_body, expected_domain, expected_challenge)
    _parse_server_hello(server_body, client)
    _parse_encrypted_extensions(encrypted_body)
    certificate_chain = _parse_certificate(certificate_body)
    scheme, signature = _parse_certificate_verify(verify_body, client)
    transcript_hash = hashlib.sha256(
        client_full + server_full + encrypted_full + certificate_full
    ).digest()
    work_messages = (client_full, server_full, encrypted_full, certificate_full)
    return ParsedProof(
        client_hello=client_full,
        server_hello=server_full,
        encrypted_extensions=encrypted_full,
        certificate=certificate_full,
        certificate_verify=verify_full,
        certificate_chain=certificate_chain,
        certificate_verify_scheme=scheme,
        certificate_verify_signature=signature,
        transcript_hash=transcript_hash,
        connection_work_hash=connection_work_hash(work_messages),
    )
