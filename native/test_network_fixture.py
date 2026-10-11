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
    def __init__(self, tls_context: ssl.SSLContext | None, mode: str, count: int = 1):
        self.tls_context = tls_context
        self.mode = mode
        self.count = count
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
            self.accepted += 1
            worker = threading.Thread(target=self.handle, args=(connection,))
            self.workers.append(worker)
            worker.start()

    def handle(self, connection: socket.socket):
        try:
            with connection:
                connection.settimeout(2)
                if self.tls_context is not None:
                    with self.tls_context.wrap_socket(connection, server_side=True) as secured:
                        self.completed += 1
                        # No HTTP is ever expected. A complete handshake sends
                        # only close_notify, while ordinary capture stops at CV.
                        application = secured.recv(1)
                        if application:
                            raise AssertionError("Native capture transmitted application data")
                else:
                    first = connection.recv(16384)
                    self.received.append(first)
                    if self.mode == "bad-record":
                        connection.sendall(b"\x16\x03\x03\xff\xff" + b"x" * 128)
                    elif self.mode == "oversized-plaintext":
                        connection.sendall(b"\x16\x03\x03\x40\x01" + b"\x02\x00\x3f\xfd" + b"x" * (16385 - 4))
                    elif self.mode == "bad-handshake":
                        connection.sendall(b"\x16\x03\x03\x00\x04\x02\xff\xff\xff")
                    elif self.mode == "ccs-flood":
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
            roots.write_bytes(root_pem)
            cert.write_bytes(cert_pem)
            key.write_bytes(key_pem)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(cert, key)
            context.num_tickets = 0
            for mode in ("capture", "complete", "slow-start", "parallel"):
                count = 8 if mode == "parallel" else 1
                with Fixture(context, mode, count) as fixture:
                    result, elapsed = run(binary, mode, fixture, roots=roots)
                require(result.returncode == 0, f"{mode} failed: {result.stderr}")
                proofs = [bytes.fromhex(line) for line in result.stdout.splitlines()]
                require(len(proofs) == count and fixture.accepted == count, "Capture count mismatch")
                hellos = set()
                for proof in proofs:
                    envelope = ConnectionProof("example.com", "11" * 32, 0, "ff" * 32, 1, 7, 1800000000, proof)
                    parsed = parse_proof(proof, envelope.domain, envelope.challenge)
                    verify_connection_proof(envelope, roots, enforce_root_pin=False)
                    # Challenge is fixed but fresh session/key-share randomness
                    # must make simultaneously emitted ClientHellos distinct.
                    size = int.from_bytes(proof[2:5], "big") + 4
                    hello = proof[1:1 + size]
                    require(hello[6:38] == envelope.challenge, "Wrong exact ClientHello challenge")
                    hellos.add(hello)
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
                if mode == "complete":
                    require(fixture.completed == 1, "Full TLS handshake was not completed")
                if mode == "slow-start":
                    require(elapsed > 1.5, "Slow start fixture did not delay callback")
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
    print(f"PASS: {checks} offline native network scenarios, ECDSA/RSA differential verification and 16 parallel captures")


if __name__ == "__main__":
    main()
