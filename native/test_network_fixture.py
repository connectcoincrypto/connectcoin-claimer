"""Offline native capture/Python differential tests; loopback sockets only.

Requires the separately compiled claimer-network-tests binary. Neither the
loopback entry point nor the generated-root verifier exists in production.
"""
from __future__ import annotations

import argparse
import dataclasses
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

HELPERS = Path(__file__).resolve().parents[1] / "helpers"
sys.path.insert(0, str(HELPERS / "tests"))
from test_claims import identity
from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.protocol import parse_proof
from connectcoin_p2c_tools.verify import verify_connection_proof
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


def large_identity():
    """Valid ~21KiB Certificate message split across ordinary TLS records."""
    root_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Large fixture root")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    def builder(subject, issuer, public_key, serial, ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
                .serial_number(serial).not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
                .not_valid_after(datetime(2040, 1, 1, tzinfo=UTC))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, None, None), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False)
                .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"x" * 10000), False))
    root = builder(root_name, root_name, root_key.public_key(), 10, True).sign(root_key, hashes.SHA256())
    leaf = (builder(leaf_name, root_name, leaf_key.public_key(), 11, False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(root_key, hashes.SHA256()))
    root_pem = root.public_bytes(serialization.Encoding.PEM)
    return root_pem, leaf.public_bytes(serialization.Encoding.PEM) + root_pem, leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class Fixture:
    def __init__(self, tls_context: ssl.SSLContext | None, mode: str, count: int = 1, *, actions=None):
        self.tls_context = tls_context
        self.mode = mode
        self.count = count
        self.actions = actions
        self.accepted = 0
        self.completed = 0
        self.received: list[bytes] = []
        self.errors: list[BaseException] = []
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.workers: list[threading.Thread] = []

    def __enter__(self):
        self.thread = threading.Thread(target=self.run, name="loopback-fixture")
        self.thread.start()
        return self

    def run(self):
        deadline = time.monotonic() + 8
        while self.accepted < self.count and not self.stop.is_set() and time.monotonic() < deadline:
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            action = self.actions[self.accepted] if self.actions is not None else self.mode
            self.accepted += 1
            worker = threading.Thread(target=self.handle, args=(connection, action))
            self.workers.append(worker)
            worker.start()

    def handle(self, connection: socket.socket, action: str):
        try:
            with connection:
                connection.settimeout(2)
                if self.tls_context is not None and action not in ("idle", "bad-record"):
                    with self.tls_context.wrap_socket(connection, server_side=True) as secured:
                        self.completed += 1
                        # No HTTP is ever expected. A complete handshake sends
                        # only close_notify, while ordinary capture stops at CV.
                        application = secured.recv(1)
                        if application:
                            raise AssertionError("Native capture transmitted application data")
                else:
                    first = connection.recv(16384)
                    # Read the complete first record so failed/cancelled reuse
                    # attempts also expose their fresh ephemeral key share.
                    while first and len(first) < 5:
                        part = connection.recv(5 - len(first))
                        if not part:
                            break
                        first += part
                    if len(first) >= 5:
                        record_size = 5 + int.from_bytes(first[3:5], "big")
                        while len(first) < record_size:
                            part = connection.recv(record_size - len(first))
                            if not part:
                                break
                            first += part
                    self.received.append(first)
                    if action == "bad-record":
                        connection.sendall(b"\x16\x03\x03\xff\xff" + b"x" * 128)
                    elif action == "oversized-plaintext":
                        connection.sendall(b"\x16\x03\x03\x40\x01" + b"\x02\x00\x3f\xfd" + b"x" * (16385 - 4))
                    elif action == "bad-handshake":
                        connection.sendall(b"\x16\x03\x03\x00\x04\x02\xff\xff\xff")
                    elif action == "ccs-flood":
                        connection.sendall(b"\x14\x03\x03\x00\x01\x01" * 12000)
                    else:
                        connection.settimeout(0.1)
                        while not self.stop.is_set():
                            try:
                                if not connection.recv(1024):
                                    break
                            except TimeoutError:
                                pass
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError):
            # Expected for captures deliberately stopping before client Finished.
            pass
        except BaseException as error:
            self.errors.append(error)

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(3)
        self.listener.close()
        for worker in self.workers:
            worker.join(3)
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            raise AssertionError("Loopback fixture did not stop")
        if self.errors:
            raise AssertionError(self.errors)


def run(binary: Path, mode: str, fixture: Fixture, timeout: int = 1500, roots: Path | None = None):
    command = [str(binary), mode, str(fixture.port), str(timeout)]
    if roots is not None:
        command.append(str(roots))
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    return result, time.monotonic() - started


def require(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def hello_fields(hello: bytes):
    """Inspect the actual ClientHello key share, SNI and offered policy."""
    require(hello[0] == 1 and len(hello) == 4 + int.from_bytes(hello[1:4], "big"), "Invalid fixture ClientHello")
    body = hello[4:]
    offset = 34
    session_size = body[offset]
    session_id = body[offset + 1:offset + 1 + session_size]
    offset += 1 + session_size
    offset += 2 + int.from_bytes(body[offset:offset + 2], "big")
    offset += 1 + body[offset]
    end = offset + 2 + int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    extensions = {}
    while offset < end:
        kind = int.from_bytes(body[offset:offset + 2], "big")
        size = int.from_bytes(body[offset + 2:offset + 4], "big")
        extensions[kind] = body[offset + 4:offset + 4 + size]
        offset += 4 + size
    require(offset == end == len(body), "Invalid fixture extension bounds")
    require(not ({41, 42, 45} & extensions.keys()), "Reused TLS session offered PSK/resumption/early data")
    shares = extensions[51][2:]
    require(len(shares) >= 36, "Missing ephemeral TLS key share")
    signatures = extensions[13][2:]
    return extensions[0][5:].decode("ascii"), signatures, shares, session_id


def reuse_sequence(binary: Path, directory: Path, context: ssl.SSLContext, root_pem: bytes, rsa: bool):
    alternate_root, alternate_cert, alternate_key = identity(rsa_leaf=rsa, leaf_domain="alternate.example.com")
    cert_path, key_path, roots_path = (directory / name for name in ("reuse-alternate.pem", "reuse-alternate.key", "reuse-roots.pem"))
    cert_path.write_bytes(alternate_cert)
    key_path.write_bytes(alternate_key)
    roots_path.write_bytes(root_pem + alternate_root)
    alternate = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    alternate.minimum_version = alternate.maximum_version = ssl.TLSVersion.TLSv1_3
    alternate.load_cert_chain(cert_path, key_path)
    alternate.num_tickets = 0
    names = []
    def select_context(connection, name, _initial):
        names.append(name)
        if name == "alternate.example.com":
            connection.context = alternate
    context.sni_callback = select_context
    actions = ("tls", "bad-record", "tls", "idle", "tls", "idle", "tls")
    mask = 2 if rsa else 1
    with Fixture(context, "reuse", len(actions), actions=actions) as fixture:
        result, _ = run(binary, f"reuse-sequence-{mask}", fixture, roots=roots_path)
    require(result.returncode == 0, f"TLS reuse recovery failed: {result.stderr}")
    require(fixture.accepted == 7 and fixture.completed == 2, "TLS reuse did not exercise all outcomes/full handshakes")
    require(names == ["example.com", "alternate.example.com", "alternate.example.com", "example.com"], "Reused TLS hostname leaked")
    shares, sessions = set(), set()
    indexes = []
    for line in result.stdout.splitlines():
        index_text, encoded = line.split()
        index = int(index_text)
        indexes.append(index)
        proof = bytes.fromhex(encoded)
        domain = "alternate.example.com" if index in (2, 4) else "example.com"
        offer_mask = mask if index in (2, 4) else 7
        envelope = ConnectionProof(domain, "11" * 32, index, "ff" * 32, 1, offer_mask, 1800000000, proof)
        verify_connection_proof(envelope, roots_path, enforce_root_pin=False)
        hello = proof[1:5 + int.from_bytes(proof[2:5], "big")]
        name, signatures, key_share, session = hello_fields(hello)
        expected_signatures = b"".join(value.to_bytes(2, "big") for bit, value in ((1, 0x0403), (2, 0x0804), (4, 0x0809)) if offer_mask & bit)
        require(name == domain and signatures == expected_signatures, "Reused ClientHello kept prior domain/signature mask")
        require(hello[6:38] == envelope.challenge, "Reused ClientHello kept prior challenge")
        shares.add(key_share)
        sessions.add(session)
    require(indexes == [0, 2, 4, 6], "Reuse success/failure sequence changed")
    require(len(fixture.received) == 3, "Missing failure/cancel/timeout ClientHello")
    for record in fixture.received:
        _, _, key_share, session = hello_fields(record[5:5 + int.from_bytes(record[3:5], "big")])
        shares.add(key_share)
        sessions.add(session)
    require(len(shares) == len(sessions) == 7, "TLS reuse repeated an ephemeral key share/session nonce")


def certificate_parser_cases(binary: Path, directory: Path, cert_pem: bytes) -> int:
    """Old TLS handler versus abbreviated+owned-DER-cache admission, offline.

    Neither side here authenticates a proof. The live loopback cases below
    exercise both full proof verifiers, including wrong name/time/mask/CV.
    """
    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)
    def u24(value):
        return value.to_bytes(3, "big")
    def ext(kind, data=b""):
        return kind.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data
    def entry(certificate=der, extensions=b""):
        return u24(len(certificate)) + certificate + len(extensions).to_bytes(2, "big") + extensions
    def message(entries, *, length=None, context=0, trailing=b""):
        body = bytes([context]) + u24(len(entries) if length is None else length) + entries + trailing
        return b"\x0b" + u24(len(body)) + body
    good = entry()
    cases = [
        ("leaf", message(good), 0, True, True),
        ("eight-certs", message(good * 8), 0, True, True),
        ("nine-certs", message(good * 9), 0, False, True),
        ("empty-chain", message(b""), 0, False, True),
        ("nonempty-request-context", message(good, context=1), 0, False, True),
        ("trailing-message", message(good, trailing=b"x"), 0, False, True),
        ("short-list", message(good, length=len(good) - 1), 0, False, True),
        ("long-list", message(good, length=len(good) + 1), 0, False, True),
        ("oversized-list", message(good, length=65536), 0, False, True),
        ("empty-der", message(entry(b"")), 0, False, True),
        ("under-128-der", message(entry(bytes(127))), 0, False, True),
        ("invalid-der", message(entry(bytes(128))), 0, False, False),
        ("invalid-der-prefix", message(entry(b"\x31" + der[1:])), 0, False, False),
        ("oversized-der", message(u24(65536) + b"x"), 0, False, True),
        ("over-p2c-der-limit", message(entry(bytes(16385))), 0, False, False),
        ("missing-extension-length", message(good[:-2]), 0, False, True),
        ("truncated-extension-block", message(good[:-2] + b"\x00\x01"), 0, False, True),
        ("truncated-extension-payload", message(entry(extensions=b"\x00\x05\x00\x01")), 0xffffffff, False, True),
        ("unknown-extension", message(entry(extensions=ext(0xfffe))), 0xffffffff, False, True),
        ("duplicate-unknown-extension", message(entry(extensions=ext(0xfffe) * 2)), 0xffffffff, False, True),
        ("forbidden-sni-extension", message(entry(extensions=ext(0))), 0xffffffff, False, True),
        ("unsolicited-status", message(entry(extensions=ext(5))), 0, False, True),
        ("duplicate-unsolicited-status", message(entry(extensions=ext(5) * 2)), 0, False, True),
        ("unsolicited-sct", message(entry(extensions=ext(18))), 0, False, True),
        ("offered-status", message(entry(extensions=ext(5))), 0xffffffff, True, True),
        ("offered-sct", message(entry(extensions=ext(18))), 0xffffffff, True, True),
        # Preserve the exact pinned handler's behavior: it checks allowed/sent
        # masks but does not separately reject duplicates of offered extensions.
        ("offered-duplicate-status", message(entry(extensions=ext(5) * 2)), 0xffffffff, True, True),
        ("per-entry-mask-reset", message(entry(extensions=ext(5)) + good), 0xffffffff, True, True),
    ]
    for length in range(4):
        body = bytes(length)
        cases.append((f"short-body-{length}", b"\x0b" + u24(length) + body, 0, False, True))
    for length in range(1, 4):
        cases.append((f"short-extension-header-{length}", message(entry(extensions=bytes(length))), 0xffffffff, False, True))
    path = directory / "certificate-message.bin"
    for name, encoded, sent, expected, exact_status in cases:
        path.write_bytes(encoded)
        result = subprocess.run([str(binary), "certificate-message", str(path), str(sent)],
                                capture_output=True, text=True, timeout=10)
        require(result.returncode == 0, f"{name}: parser fixture failed: {result.stderr}")
        rows = [[int(value) for value in line.split()] for line in result.stdout.splitlines()]
        require(len(rows) == 2 and all(len(row) == 4 for row in rows), f"{name}: malformed differential result")
        old, new = rows
        require(bool(old[1]) == expected and bool(new[1]) == expected, f"{name}: old/new acceptance differs: {rows}")
        if exact_status:
            require(old[0] == new[0], f"{name}: TLS structural error changed: {rows}")
        if expected:
            require(old[2] == new[2], f"{name}: extension mask changed: {rows}")
            require(old[3] == 1 and new[3] == 0, f"{name}: abbreviated TLS path reparsed DER: {rows}")
    return len(cases)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--large-chain-only", action="store_true", help="Run only the mandatory fragmented >16KiB certificate regression")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    baseline = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    require(baseline.returncode == 0, baseline.stderr)
    checks = 1
    with tempfile.TemporaryDirectory(prefix="claimer-native-loopback-") as directory:
        root = Path(directory)
        roots, cert, key = (root / name for name in ("root.pem", "leaf.pem", "leaf.key"))
        root_pem, cert_pem, key_pem = large_identity()
        roots.write_bytes(root_pem)
        cert.write_bytes(cert_pem)
        key.write_bytes(key_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert, key)
        with Fixture(context, "capture") as fixture:
            result, _ = run(binary, "capture", fixture, roots=roots)
        require(result.returncode == 0, f"Large valid certificate capture failed: {result.stderr}")
        proof = bytes.fromhex(result.stdout.strip())
        require(len(proof) > 16384, "Large-certificate fixture did not cross record boundary")
        envelope = ConnectionProof("example.com", "11" * 32, 0, "ff" * 32, 1, 7, 1800000000, proof)
        verify_connection_proof(envelope, roots, enforce_root_pin=False)
        checks += 1
        if options.large_chain_only:
            print("PASS: fragmented large-certificate capture and native/Python verification")
            return
        for rsa in (False, True):
            root_pem, cert_pem, key_pem = identity(rsa_leaf=rsa)
            checks += certificate_parser_cases(binary, root, cert_pem)
            roots.write_bytes(root_pem)
            cert.write_bytes(cert_pem)
            key.write_bytes(key_pem)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(cert, key)
            context.num_tickets = 0
            for mode in ("capture", "complete", "slow-start", "parallel", "repeat", f"capture-mask-{2 if rsa else 1}"):
                count = 16 if mode == "parallel" else 2 if mode == "repeat" else 1
                with Fixture(context, mode, count) as fixture:
                    result, elapsed = run(binary, mode, fixture, roots=roots)
                require(result.returncode == 0, f"{mode} failed: {result.stderr}")
                proofs = [bytes.fromhex(line) for line in result.stdout.splitlines()]
                require(len(proofs) == count and fixture.accepted == count, "Capture count mismatch")
                hellos = set()
                key_shares = set()
                for proof in proofs:
                    mask = int(mode.removeprefix("capture-mask-")) if mode.startswith("capture-mask-") else 7
                    envelope = ConnectionProof("example.com", "11" * 32, 0, "ff" * 32, 1, mask, 1800000000, proof)
                    parsed = parse_proof(proof, envelope.domain, envelope.challenge)
                    verify_connection_proof(envelope, roots, enforce_root_pin=False)
                    # Challenge is fixed but fresh session/key-share randomness
                    # must make simultaneously emitted ClientHellos distinct.
                    size = int.from_bytes(proof[2:5], "big") + 4
                    hello = proof[1:1 + size]
                    require(hello[6:38] == envelope.challenge, "Wrong exact ClientHello challenge")
                    hellos.add(hello)
                    key_shares.add(hello_fields(hello)[2])
                    tampered = bytearray(proof)
                    tampered[-1] ^= 1
                    try:
                        verify_connection_proof(dataclasses.replace(envelope, proof=bytes(tampered)), roots, enforce_root_pin=False)
                    except Exception:
                        pass
                    else:
                        raise AssertionError("Python reference accepted tampered CV")
                    require(parsed.certificate_verify_scheme == (0x0804 if rsa else 0x0403), "Unexpected TLS signature scheme")
                require(len(hellos) == count, "Ephemeral ClientHello randomness was reused")
                require(len(key_shares) == count, "Ephemeral ClientHello key share was reused")
                if mode == "complete":
                    require(fixture.completed == 1, "Full TLS handshake was not completed")
                if mode == "slow-start":
                    require(elapsed > 1.5, "Slow start fixture did not delay callback")
                checks += 1
            with Fixture(context, "capture") as fixture:
                result, _ = run(binary, f"capture-mask-{1 if rsa else 2}", fixture, roots=roots)
            require(result.returncode == 1, "Incompatible signature policy was accepted")
            checks += 1
            reuse_sequence(binary, root, context, root_pem, rsa)
            checks += 1

        for mode in ("cancel", "cancel-start", "reject-start"):
            with Fixture(None, "idle") as fixture:
                result, elapsed = run(binary, mode, fixture)
            require(elapsed < 2.5, f"{mode} did not terminate promptly")
            require(result.returncode == (1 if mode == "reject-start" else 0), f"{mode}: {result.stderr}")
            require(fixture.accepted == (1 if mode == "cancel" else 0), f"{mode} connected outside start/cancel ordering")
            checks += 1
        with Fixture(None, "idle") as fixture:
            result, elapsed = run(binary, "capture", fixture, 150)
        require(result.returncode == 1 and "timed out" in result.stderr and elapsed < 2, "Absolute network deadline failed")
        require(fixture.received and fixture.received[0][0] == 22, "Expected ClientHello, never HTTP")
        checks += 1
        for mode in ("bad-record", "bad-handshake", "ccs-flood", "oversized-plaintext"):
            with Fixture(None, mode) as fixture:
                result, elapsed = run(binary, "capture", fixture, 500)
            require(result.returncode == 1 and elapsed < 2, f"Malformed wire input not bounded: {mode}")
            if mode == "oversized-plaintext":
                require("invalid ssl record" in result.stderr.lower(), "Record limit must reject at record layer, not a later parser")
            checks += 1

        # TLS capture itself accepts an untrusted/wrong-name certificate; only
        # the separate native and Python pinned-root verifiers may authorize it.
        root_pem, cert_pem, key_pem = identity(leaf_domain="wrong.example.com")
        roots.write_bytes(root_pem)
        cert.write_bytes(cert_pem)
        key.write_bytes(key_pem)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(cert, key)
        with Fixture(context, "capture") as fixture:
            result, _ = run(binary, "capture", fixture)
        require(result.returncode == 0, "Capture incorrectly substituted platform certificate trust")
        with Fixture(context, "capture") as fixture:
            result, _ = run(binary, "capture", fixture, roots=roots)
        require(result.returncode == 1, "Separate native verification accepted wrong hostname")
        checks += 1
    print(f"PASS: {checks} offline native network scenarios, ECDSA/RSA differential verification and 32 parallel captures")


if __name__ == "__main__":
    main()
