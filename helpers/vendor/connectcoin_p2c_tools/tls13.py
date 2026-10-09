from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import socket
import time
from dataclasses import dataclass
from threading import Event, Lock
from collections.abc import Callable
from contextlib import nullcontext
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .domain import is_canonical_domain
from .errors import P2CError
from .protocol import (
    CERTIFICATE,
    CERTIFICATE_VERIFY,
    ENCRYPTED_EXTENSIONS,
    HELLO_RETRY_REQUEST_RANDOM,
    PROOF_VERSION,
    SERVER_HELLO,
    TLS_AES_128_GCM_SHA256,
    TLS_CHACHA20_POLY1305_SHA256,
    parse_proof,
)
from .signatures import (
    accepted_signature_algorithms,
    signature_scheme_allowed,
    validate_signature_algorithms_mask,
)
from .verify import validate_certificate_message

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23
FINISHED = 20

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SIGNATURE_ALGORITHMS_CERT = 50
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
GROUP_X25519 = 0x001D
TLS_1_2 = 0x0303
TLS_1_3 = 0x0304
MAX_TLS_CIPHERTEXT = (1 << 14) + 256
MAX_CAPTURED_HANDSHAKE = 64 * 1024
# Closing a socket from another thread does not reliably wake an in-progress
# select/recv on every OS. Poll only cancellable receives; the handshake still
# has one absolute deadline, not a fresh timeout for each poll or TLS record.
CANCEL_POLL_SECONDS = 0.1
# Teardown is best effort and cannot turn a completed proof into a timeout.
# Bound both time and bytes, even if a peer sends endless post-handshake data.
CLOSE_DRAIN_SECONDS = 0.2
MAX_CLOSE_DRAIN_BYTES = 64 * 1024


class TLSGenerationError(P2CError):
    """A server did not complete the narrow TLS 1.3 profile required by P2C."""


class CaptureCancelled(TLSGenerationError):
    """The wallet cancelled this individual connection attempt."""


class CaptureControl:
    """Cancellation owns the socket, so blocked connect/receive can be interrupted."""

    def __init__(self) -> None:
        self._event = Event()
        self._lock = Lock()
        self._socket: socket.socket | None = None

    def cancelled(self) -> bool:
        return self._event.is_set()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.detach()

    def begin(self, connection: socket.socket, on_started: Callable[[], None] | None) -> None:
        with self._lock:
            if self.cancelled():
                raise CaptureCancelled("TLS capture cancelled")
            self._socket = connection
        # Reporting may block on the parent's output pipe. Never make socket
        # cancellation wait for reporting, and recheck before any network use.
        if on_started is not None:
            on_started()
        if self.cancelled():
            raise CaptureCancelled("TLS capture cancelled")

    def bind(self, connection: socket.socket) -> None:
        self.begin(connection, None)

    def detach(self) -> None:
        with self._lock:
            self._socket = None

    def cancel(self) -> None:
        with self._lock:
            self._event.set()
            if self._socket is not None:
                try:
                    self._socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self._socket.close()
                except OSError:
                    pass


@dataclass(frozen=True, slots=True)
class Endpoint:
    family: int
    socket_type: int
    protocol: int
    address: Any
    ip: str


@dataclass(frozen=True, slots=True)
class TLSProofMessages:
    client_hello: bytes
    server_hello: bytes
    encrypted_extensions: bytes
    certificate: bytes
    certificate_verify: bytes
    peer_ip: str

    @property
    def encoded_proof(self) -> bytes:
        return bytes([PROOF_VERSION]) + b"".join(
            (
                self.client_hello,
                self.server_hello,
                self.encrypted_extensions,
                self.certificate,
                self.certificate_verify,
            )
        )


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _extension(extension_type: int, data: bytes) -> bytes:
    return _u16(extension_type) + _u16(len(data)) + data


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _record(content_type: int, body: bytes, legacy_version: int = 0x0301) -> bytes:
    return bytes([content_type]) + _u16(legacy_version) + _u16(len(body)) + body


def build_client_hello(
    domain: str,
    challenge: bytes,
    public_key: bytes,
    session_id: bytes,
    *,
    signature_algorithms_mask: int,
) -> bytes:
    validate_signature_algorithms_mask(signature_algorithms_mask)
    if not is_canonical_domain(domain):
        raise TLSGenerationError("domain is not canonical lower-case ASCII DNS form")
    if len(challenge) != 32:
        raise TLSGenerationError("claim challenge must contain exactly 32 bytes")
    if len(public_key) != 32:
        raise TLSGenerationError("X25519 public key must contain exactly 32 bytes")
    if not 1 <= len(session_id) <= 32:
        raise TLSGenerationError("legacy session id must contain between 1 and 32 bytes")

    encoded_domain = domain.encode("ascii")
    server_name = b"\x00" + _u16(len(encoded_domain)) + encoded_domain
    signature_schemes = b"".join(
        _u16(algorithm.scheme)
        for algorithm in accepted_signature_algorithms(signature_algorithms_mask)
    )
    # The output mask constrains CertificateVerify, not signatures made by
    # certificate issuers. Keep that separate TLS extension independent.
    certificate_signature_schemes = b"".join(
        _u16(value)
        for value in (
            0x0403,  # ecdsa_secp256r1_sha256
            0x0503,  # ecdsa_secp384r1_sha384
            0x0603,  # ecdsa_secp521r1_sha512
            0x0804,  # rsa_pss_rsae_sha256
            0x0805,  # rsa_pss_rsae_sha384
            0x0806,  # rsa_pss_rsae_sha512
            0x0809,  # rsa_pss_pss_sha256
            0x080A,  # rsa_pss_pss_sha384
            0x080B,  # rsa_pss_pss_sha512
            0x0401,  # rsa_pkcs1_sha256 (certificate signatures only)
            0x0501,  # rsa_pkcs1_sha384 (certificate signatures only)
            0x0601,  # rsa_pkcs1_sha512 (certificate signatures only)
        )
    )
    key_share_entry = _u16(GROUP_X25519) + _u16(len(public_key)) + public_key
    extensions = b"".join(
        (
            _extension(EXT_SERVER_NAME, _u16(len(server_name)) + server_name),
            _extension(EXT_SUPPORTED_GROUPS, b"\x00\x02" + _u16(GROUP_X25519)),
            _extension(EXT_SIGNATURE_ALGORITHMS, _u16(len(signature_schemes)) + signature_schemes),
            _extension(
                EXT_SIGNATURE_ALGORITHMS_CERT,
                _u16(len(certificate_signature_schemes)) + certificate_signature_schemes,
            ),
            _extension(EXT_SUPPORTED_VERSIONS, b"\x02" + _u16(TLS_1_3)),
            _extension(EXT_KEY_SHARE, _u16(len(key_share_entry)) + key_share_entry),
        )
    )
    cipher_suites = _u16(TLS_AES_128_GCM_SHA256) + _u16(TLS_CHACHA20_POLY1305_SHA256)
    body = b"".join(
        (
            _u16(TLS_1_2),
            challenge,
            bytes([len(session_id)]),
            session_id,
            _u16(len(cipher_suites)),
            cipher_suites,
            b"\x01\x00",
            _u16(len(extensions)),
            extensions,
        )
    )
    return _handshake(1, body)


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(secret: bytes, info: bytes, length: int) -> bytes:
    if not 0 <= length <= 255 * hashlib.sha256().digest_size:
        raise TLSGenerationError("invalid HKDF output length")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(secret, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    full_label = b"tls13 " + label
    if not 7 <= len(full_label) <= 255 or len(context) > 255 or length > 0xFFFF:
        raise TLSGenerationError("invalid TLS 1.3 HKDF label")
    info = _u16(length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


def derive_secret(secret: bytes, label: bytes, transcript: bytes) -> bytes:
    return hkdf_expand_label(secret, label, hashlib.sha256(transcript).digest(), 32)


def _handshake_secret(shared_secret: bytes) -> bytes:
    zeroes = b"\x00" * 32
    early_secret = hkdf_extract(zeroes, zeroes)
    derived_secret = derive_secret(early_secret, b"derived", b"")
    return hkdf_extract(derived_secret, shared_secret)


def _handshake_traffic_secret(shared_secret: bytes, transcript: bytes, label: bytes) -> bytes:
    return derive_secret(_handshake_secret(shared_secret), label, transcript)


def _handshake_keys(traffic_secret: bytes, cipher_suite: int) -> tuple[bytes, bytes]:
    if cipher_suite == TLS_AES_128_GCM_SHA256:
        key_length = 16
    elif cipher_suite == TLS_CHACHA20_POLY1305_SHA256:
        key_length = 32
    else:
        raise TLSGenerationError("server selected an unsupported cipher suite")
    return (
        hkdf_expand_label(traffic_secret, b"key", b"", key_length),
        hkdf_expand_label(traffic_secret, b"iv", b"", 12),
    )


def derive_server_handshake_keys(
    shared_secret: bytes, transcript: bytes, cipher_suite: int
) -> tuple[bytes, bytes]:
    return _handshake_keys(
        _handshake_traffic_secret(shared_secret, transcript, b"s hs traffic"), cipher_suite
    )


def _finished_verify_data(traffic_secret: bytes, transcript: bytes) -> bytes:
    finished_key = hkdf_expand_label(traffic_secret, b"finished", b"", 32)
    return hmac.new(finished_key, hashlib.sha256(transcript).digest(), hashlib.sha256).digest()


def _verify_server_finished(message: bytes, traffic_secret: bytes, transcript: bytes) -> None:
    expected = _handshake(FINISHED, _finished_verify_data(traffic_secret, transcript))
    if not hmac.compare_digest(message, expected):
        raise TLSGenerationError("TLS 1.3 server Finished verification failed")


def _client_finished_record(
    traffic_secret: bytes, transcript: bytes, cipher_suite: int
) -> bytes:
    # Client handshake sequence starts at zero; no application data is sent.
    plaintext = _handshake(FINISHED, _finished_verify_data(traffic_secret, transcript))
    plaintext += bytes([CONTENT_HANDSHAKE])
    header = bytes([CONTENT_APPLICATION_DATA]) + _u16(TLS_1_2) + _u16(len(plaintext) + 16)
    key, iv = _handshake_keys(traffic_secret, cipher_suite)
    cipher = AESGCM(key) if cipher_suite == TLS_AES_128_GCM_SHA256 else ChaCha20Poly1305(key)
    return header + cipher.encrypt(_record_nonce(iv, 0), plaintext, header)


def _client_close_notify_record(
    shared_secret: bytes, server_finished_transcript: bytes, cipher_suite: int
) -> bytes:
    # Application traffic keys use the transcript through server Finished,
    # unlike the client Finished verify_data, which uses handshake keys.
    derived = derive_secret(_handshake_secret(shared_secret), b"derived", b"")
    master_secret = hkdf_extract(derived, b"\x00" * 32)
    traffic_secret = derive_secret(master_secret, b"c ap traffic", server_finished_transcript)
    key, iv = _handshake_keys(traffic_secret, cipher_suite)
    plaintext = b"\x01\x00" + bytes([CONTENT_ALERT])
    header = bytes([CONTENT_APPLICATION_DATA]) + _u16(TLS_1_2) + _u16(len(plaintext) + 16)
    cipher = AESGCM(key) if cipher_suite == TLS_AES_128_GCM_SHA256 else ChaCha20Poly1305(key)
    return header + cipher.encrypt(_record_nonce(iv, 0), plaintext, header)


def _close_completed_handshake(
    connection: socket.socket,
    close_notify: bytes,
    control: CaptureControl | None,
) -> None:
    # Let servers finish sending session tickets and observe close_notify.
    # Immediately closing with unread tickets can reset an otherwise valid
    # connection on Windows. No application data is sent or retained here.
    deadline = time.monotonic() + CLOSE_DRAIN_SECONDS
    drained = 0
    try:
        if control is not None and control.cancelled():
            raise CaptureCancelled("TLS capture cancelled")
        connection.settimeout(_remaining_timeout(deadline))
        connection.sendall(close_notify)
        while drained < MAX_CLOSE_DRAIN_BYTES:
            if control is not None and control.cancelled():
                raise CaptureCancelled("TLS capture cancelled")
            remaining = _remaining_timeout(deadline)
            connection.settimeout(min(remaining, CANCEL_POLL_SECONDS))
            try:
                chunk = connection.recv(min(4096, MAX_CLOSE_DRAIN_BYTES - drained))
            except TimeoutError:
                continue
            if not chunk:
                return
            drained += len(chunk)
    except CaptureCancelled:
        raise
    except (OSError, TLSGenerationError):
        # The server Finished was authenticated and client Finished sent;
        # failure to finish closing cannot invalidate that completed capture.
        pass
    finally:
        if control is not None and control.cancelled():
            raise CaptureCancelled("TLS capture cancelled")


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TLSGenerationError("TLS handshake exceeded the connection timeout")
    return remaining


def _recv_exact(
    connection: socket.socket,
    size: int,
    deadline: float,
    control: CaptureControl | None = None,
) -> bytes:
    result = bytearray()
    while len(result) < size:
        if control is not None and control.cancelled():
            raise CaptureCancelled("TLS capture cancelled")
        remaining = _remaining_timeout(deadline)
        try:
            connection.settimeout(min(remaining, CANCEL_POLL_SECONDS) if control is not None else remaining)
            chunk = connection.recv(size - len(result))
        except OSError as error:
            if control is not None and control.cancelled():
                raise CaptureCancelled("TLS capture cancelled") from error
            if control is not None and isinstance(error, TimeoutError):
                continue
            raise
        if control is not None and control.cancelled():
            raise CaptureCancelled("TLS capture cancelled")
        if not chunk:
            raise TLSGenerationError("TLS peer closed the connection during the handshake")
        result.extend(chunk)
    return bytes(result)


def _recv_record(
    connection: socket.socket,
    deadline: float,
    control: CaptureControl | None = None,
) -> tuple[int, bytes, bytes]:
    header = _recv_exact(connection, 5, deadline, control)
    content_type = header[0]
    version = int.from_bytes(header[1:3], "big")
    size = int.from_bytes(header[3:5], "big")
    if version < 0x0300:
        raise TLSGenerationError("TLS peer used an invalid record version")
    if size > MAX_TLS_CIPHERTEXT:
        raise TLSGenerationError("TLS record exceeds the TLS 1.3 ciphertext limit")
    return content_type, header, _recv_exact(connection, size, deadline, control)


def _pop_handshake(buffer: bytearray) -> bytes | None:
    if len(buffer) < 4:
        return None
    size = int.from_bytes(buffer[1:4], "big") + 4
    if size > MAX_CAPTURED_HANDSHAKE:
        raise TLSGenerationError("TLS handshake message exceeds the P2C proof limit")
    if len(buffer) < size:
        return None
    result = bytes(buffer[:size])
    del buffer[:size]
    return result


def _parse_extensions(encoded: bytes) -> dict[int, bytes]:
    position = 0
    result: dict[int, bytes] = {}
    while position < len(encoded):
        if len(encoded) - position < 4:
            raise TLSGenerationError("truncated ServerHello extension")
        extension_type = int.from_bytes(encoded[position : position + 2], "big")
        size = int.from_bytes(encoded[position + 2 : position + 4], "big")
        position += 4
        if len(encoded) - position < size:
            raise TLSGenerationError("truncated ServerHello extension data")
        if extension_type in result:
            raise TLSGenerationError("duplicate ServerHello extension")
        result[extension_type] = encoded[position : position + size]
        position += size
    return result


def parse_server_hello(message: bytes, expected_session_id: bytes) -> tuple[int, bytes]:
    if len(message) < 4 or message[0] != SERVER_HELLO:
        raise TLSGenerationError("TLS peer did not return ServerHello")
    if int.from_bytes(message[1:4], "big") != len(message) - 4:
        raise TLSGenerationError("invalid ServerHello length")
    body = message[4:]
    if len(body) < 38 or body[:2] != _u16(TLS_1_2):
        raise TLSGenerationError("invalid TLS 1.3 ServerHello")
    if body[2:34] == HELLO_RETRY_REQUEST_RANDOM:
        raise TLSGenerationError("HelloRetryRequest is not supported by P2C v2")
    position = 34
    session_size = body[position]
    position += 1
    if session_size > 32 or len(body) - position < session_size + 5:
        raise TLSGenerationError("invalid ServerHello session id")
    if body[position : position + session_size] != expected_session_id:
        raise TLSGenerationError("ServerHello did not echo the ClientHello session id")
    position += session_size
    cipher_suite = int.from_bytes(body[position : position + 2], "big")
    position += 2
    if cipher_suite not in {TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256}:
        raise TLSGenerationError("server selected a cipher suite outside the P2C profile")
    if body[position] != 0:
        raise TLSGenerationError("ServerHello selected non-null compression")
    position += 1
    extension_size = int.from_bytes(body[position : position + 2], "big")
    position += 2
    if len(body) - position != extension_size:
        raise TLSGenerationError("invalid ServerHello extensions length")
    extensions = _parse_extensions(body[position:])
    if set(extensions) != {EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE}:
        raise TLSGenerationError(
            "P2C ServerHello must contain only supported_versions and key_share"
        )
    if extensions[EXT_SUPPORTED_VERSIONS] != _u16(TLS_1_3):
        raise TLSGenerationError("server did not select TLS 1.3")
    key_share = extensions[EXT_KEY_SHARE]
    if len(key_share) < 4 or int.from_bytes(key_share[:2], "big") != GROUP_X25519:
        raise TLSGenerationError("server did not select the offered X25519 key share")
    key_size = int.from_bytes(key_share[2:4], "big")
    if key_size != 32 or len(key_share) != key_size + 4:
        raise TLSGenerationError("invalid ServerHello X25519 key share")
    return cipher_suite, key_share[4:]


def _record_nonce(iv: bytes, sequence: int) -> bytes:
    if not 0 <= sequence < 1 << 64:
        raise TLSGenerationError("TLS record sequence overflow")
    padded_sequence = sequence.to_bytes(len(iv), "big")
    return bytes(left ^ right for left, right in zip(iv, padded_sequence, strict=True))


def _decrypt_record(
    cipher_suite: int, key: bytes, iv: bytes, sequence: int, header: bytes, ciphertext: bytes
) -> tuple[int, bytes]:
    nonce = _record_nonce(iv, sequence)
    try:
        if cipher_suite == TLS_AES_128_GCM_SHA256:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
        else:
            plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise TLSGenerationError("TLS 1.3 server handshake record authentication failed") from exc
    unpadded = plaintext.rstrip(b"\x00")
    if not unpadded:
        raise TLSGenerationError("TLS 1.3 inner plaintext has no content type")
    return unpadded[-1], unpadded[:-1]


def _raise_alert(alert: bytes) -> None:
    if len(alert) >= 2:
        raise TLSGenerationError(f"TLS peer returned alert level={alert[0]} description={alert[1]}")
    raise TLSGenerationError("TLS peer returned a truncated alert")


def capture_tls13_proof(
    endpoint: Endpoint,
    domain: str,
    challenge: bytes,
    *,
    signature_algorithms_mask: int,
    timeout: float = 10.0,
    control: CaptureControl | None = None,
    on_started: Callable[[], None] | None = None,
    before_start: Callable[[], None] | None = None,
    on_connecting: Callable[[], None] | None = None,
    complete_handshake: bool = False,
) -> TLSProofMessages:
    validate_signature_algorithms_mask(signature_algorithms_mask)
    if not math.isfinite(timeout) or timeout <= 0:
        raise TLSGenerationError("connection timeout must be finite and positive")
    if control is not None and control.cancelled():
        raise CaptureCancelled("TLS capture cancelled")
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    session_id = secrets.token_bytes(32)
    client_hello = build_client_hello(
        domain,
        challenge,
        public_key,
        session_id,
        signature_algorithms_mask=signature_algorithms_mask,
    )
    with socket.socket(endpoint.family, endpoint.socket_type, endpoint.protocol) as connection, (control if control is not None else nullcontext()):
        if control is not None:
            control.bind(connection)
        if before_start is not None:
            before_start()
        if control is not None:
            control.begin(connection, on_started)
        elif on_started is not None:
            on_started()
        # Queue/rate waits and potentially blocking start reporting do not
        # consume the network budget. This cheap hook marks actual TCP timing.
        if on_connecting is not None:
            on_connecting()
        if control is not None and control.cancelled():
            raise CaptureCancelled("TLS capture cancelled")
        deadline = time.monotonic() + timeout
        connection.settimeout(_remaining_timeout(deadline))
        connection.connect(endpoint.address)
        connection.settimeout(_remaining_timeout(deadline))
        connection.sendall(_record(CONTENT_HANDSHAKE, client_hello))

        plaintext_handshake = bytearray()
        server_hello: bytes | None = None
        while server_hello is None:
            content_type, _, fragment = _recv_record(connection, deadline, control)
            if content_type == CONTENT_CHANGE_CIPHER_SPEC and fragment == b"\x01":
                continue
            if content_type == CONTENT_ALERT:
                _raise_alert(fragment)
            if content_type != CONTENT_HANDSHAKE:
                raise TLSGenerationError("unexpected TLS record before ServerHello")
            plaintext_handshake.extend(fragment)
            server_hello = _pop_handshake(plaintext_handshake)
        if plaintext_handshake:
            raise TLSGenerationError("unexpected plaintext handshake data after ServerHello")

        cipher_suite, server_public_bytes = parse_server_hello(server_hello, session_id)
        try:
            server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_bytes)
            shared_secret = private_key.exchange(server_public_key)
        except ValueError as exc:
            raise TLSGenerationError("invalid ServerHello X25519 public key") from exc
        key, iv = derive_server_handshake_keys(
            shared_secret, client_hello + server_hello, cipher_suite
        )

        encrypted_handshake = bytearray()
        expected_messages = (ENCRYPTED_EXTENSIONS, CERTIFICATE, CERTIFICATE_VERIFY)
        if complete_handshake:
            expected_messages += (FINISHED,)
        captured: list[bytes] = []
        sequence = 0
        while len(captured) < len(expected_messages):
            content_type, header, fragment = _recv_record(connection, deadline, control)
            if content_type == CONTENT_CHANGE_CIPHER_SPEC and fragment == b"\x01":
                continue
            if content_type == CONTENT_ALERT:
                _raise_alert(fragment)
            if content_type != CONTENT_APPLICATION_DATA:
                raise TLSGenerationError(
                    "unexpected plaintext record in encrypted server handshake"
                )
            inner_type, inner_fragment = _decrypt_record(
                cipher_suite, key, iv, sequence, header, fragment
            )
            sequence += 1
            if inner_type == CONTENT_ALERT:
                _raise_alert(inner_fragment)
            if inner_type != CONTENT_HANDSHAKE:
                raise TLSGenerationError("unexpected TLS inner content during server handshake")
            encrypted_handshake.extend(inner_fragment)
            if len(encrypted_handshake) > MAX_CAPTURED_HANDSHAKE:
                raise TLSGenerationError("captured TLS handshake exceeds the P2C proof limit")
            while len(captured) < len(expected_messages):
                message = _pop_handshake(encrypted_handshake)
                if message is None:
                    break
                expected_type = expected_messages[len(captured)]
                if message[0] != expected_type:
                    raise TLSGenerationError(
                        f"expected TLS handshake type {expected_type}, received {message[0]}"
                    )
                if expected_type == CERTIFICATE:
                    try:
                        validate_certificate_message(message)
                    except P2CError as exc:
                        raise TLSGenerationError(str(exc)) from exc
                captured.append(message)

        if complete_handshake:
            if encrypted_handshake:
                raise TLSGenerationError("unexpected handshake data after server Finished")
            hello_transcript = client_hello + server_hello
            transcript = hello_transcript + b"".join(captured[:3])
            server_secret = _handshake_traffic_secret(shared_secret, hello_transcript, b"s hs traffic")
            _verify_server_finished(captured[3], server_secret, transcript)
            client_secret = _handshake_traffic_secret(shared_secret, hello_transcript, b"c hs traffic")
            if control is not None and control.cancelled():
                raise CaptureCancelled("TLS capture cancelled")
            connection.settimeout(_remaining_timeout(deadline))
            connection.sendall(_client_finished_record(client_secret, transcript + captured[3], cipher_suite))
            _remaining_timeout(deadline)
            _close_completed_handshake(connection,
                _client_close_notify_record(shared_secret, transcript + captured[3], cipher_suite),
                control)

    result = TLSProofMessages(
        client_hello=client_hello,
        server_hello=server_hello,
        encrypted_extensions=captured[0],
        certificate=captured[1],
        certificate_verify=captured[2],
        peer_ip=endpoint.ip,
    )
    # Retain all five messages in the v2 proof, while the parser computes work
    # from only the first four. The caller still must verify the certificate
    # chain and CertificateVerify signature before accepting a claim.
    parsed = parse_proof(result.encoded_proof, domain, challenge)
    if not signature_scheme_allowed(signature_algorithms_mask, parsed.certificate_verify_scheme):
        raise TLSGenerationError("TLS server used a disallowed P2C signature scheme")
    return result
