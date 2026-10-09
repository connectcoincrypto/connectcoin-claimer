"""Bounded, key-free NDJSON bridge between Electron main and the TLS worker."""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Isolated Python (-I) deliberately omits the script directory. Restore only
# this trusted, absolute directory so --service can import its sibling module;
# never restore the working directory or caller-supplied PYTHONPATH.
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

from connectcoin_p2c_tools.envelope import ConnectionProof  # noqa: E402
from connectcoin_p2c_tools.generator import (  # noqa: E402
    MAX_CONNECTION_LIMIT,
    GenerationOptions,
    GenerationProgress,
    generate_connection_proof,
)
from connectcoin_p2c_tools.verify import (  # noqa: E402
    MAX_RSA_PUBLIC_EXPONENT_BITS,
    verify_connection_proof,
)

CONTEXT_KEYS = {
    "domain", "txid", "input_index", "connection_work_target",
    "root_certificates_version", "signature_algorithms_mask", "validation_time",
}
OPTION_KEYS = {"connectionsPerSecond", "concurrency", "overallTimeout", "maxAttempts"}
MINIMUM_CRYPTOGRAPHY_VERSION = (50, 0, 1)


def security_provider_versions() -> dict[str, str | int]:
    """Report the loaded certificate provider and reject unsupported builds.

    This release floor includes the fixes for GHSA-jwv3-5hgf-82ww and
    GHSA-m2h6-j472-rp4c. Read the imported package and its own OpenSSL backend;
    distribution metadata or Python's ssl module can describe another runtime.
    """
    import cryptography

    version = cryptography.__version__
    minimum = ".".join(map(str, MINIMUM_CRYPTOGRAPHY_VERSION))
    if (
        re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
        or tuple(map(int, version.split("."))) < MINIMUM_CRYPTOGRAPHY_VERSION
    ):
        raise RuntimeError(
            f"cryptography {minimum} or newer stable release is required; loaded {version}"
        )
    from cryptography.hazmat.backends.openssl.backend import backend

    return {"cryptographyVersion": version, "minimumCryptographyVersion": minimum,
            "opensslVersion": backend.openssl_version_text(),
            "rsaPublicExponentMaxBits": MAX_RSA_PUBLIC_EXPONENT_BITS}


def emit(value: dict) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n")
    sys.stdout.flush()


def bounded_int(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def parse_request(request: object) -> tuple[ConnectionProof, GenerationOptions]:
    if not isinstance(request, dict) or set(request) != {"context", "options"}:
        raise ValueError("request must contain only context and options")
    context = request["context"]
    options = request["options"]
    if not isinstance(options, dict) or set(options) != OPTION_KEYS:
        raise ValueError("invalid generation options")
    proof = parse_context(context)
    generation = GenerationOptions(
        connections_per_second=bounded_int(options["connectionsPerSecond"], "rate", 1, MAX_CONNECTION_LIMIT),
        concurrency=bounded_int(options["concurrency"], "concurrency", 1, MAX_CONNECTION_LIMIT),
        overall_timeout=bounded_int(options["overallTimeout"], "timeout", 1, 600),
        max_attempts=bounded_int(options["maxAttempts"], "attempts", 1, 100000),
        connection_timeout=10.0,
        port=443,
        allow_private_addresses=False,
        enforce_root_pin=True,
    )
    return proof, generation


def parse_context(context: object) -> ConnectionProof:
    if not isinstance(context, dict) or set(context) != CONTEXT_KEYS:
        raise ValueError("invalid public claim context")
    proof = ConnectionProof(**context, proof=b"")
    if "." not in proof.domain or proof.domain.endswith((".localhost", ".local", ".internal")):
        raise ValueError("only public DNS domains are supported")
    if proof.root_certificates_version != 1:
        raise ValueError("unsupported root bundle version")
    bounded_int(proof.validation_time, "chain median time", 1, 253402300799)
    return proof


class ProgressReporter:
    """At most one bounded snapshot per second, plus a mandatory final one."""

    def __init__(self) -> None:
        self.last_update: float | None = None
        self.finished = False

    def __call__(self, update: GenerationProgress) -> None:
        if self.finished:
            return
        now = time.monotonic()
        if update.finished or self.last_update is None or now - self.last_update >= 1:
            self.last_update = now
            self.finished = update.finished
            emit({"type": "progress", "attempts": update.attempt_stats.completed,
                  "elapsed": round(update.elapsed, 3),
                  "bestWorkHash": update.best_work_hash,
                  "attemptStats": {"validation": "certificate-proof-v1",
                                   "completed": update.attempt_stats.completed,
                                   "recent": update.attempt_stats.recent}})


def helper_mode(arguments: list[str]) -> str:
    # Older helpers reject this unknown suffix before reading a request or
    # accessing the network. Require it from the one-shot/probe launchers so
    # a stale native helper cannot silently bypass the source verifier update.
    if arguments[-1:] == ["--require-rsa-exponent-64"]:
        if MAX_RSA_PUBLIC_EXPONENT_BITS != 64:
            raise ValueError("Automatic Claims helper must enforce the 64-bit RSA exponent limit; rebuild it")
        arguments = arguments[:-1]
    if not arguments:
        return "generate"
    if len(arguments) == 1 and arguments[0] in {"--probe-rsa", "--service", "--self-test"}:
        return arguments[0]
    raise ValueError("unknown helper arguments")


def main() -> int:
    mode = helper_mode(sys.argv[1:])
    if mode == "--probe-rsa":
        deadline = time.monotonic() + 3.0
        from rsa_probe import run_probe
        return run_probe(sys.stdin.buffer, emit, ROOT / "p2c_roots_v1.pem", deadline=deadline)
    if mode == "--service":
        from claims_service import run_service
        return run_service(sys.stdin.buffer, emit, parse_context, ROOT / "p2c_roots_v1.pem")
    if mode == "--self-test":
        from connectcoin_p2c_tools.verify import validate_root_bundle
        security = security_provider_versions()
        validate_root_bundle(ROOT / "p2c_roots_v1.pem", 1)
        emit({"type": "ready", "protocol": 4, "roots": 1, "security": security})
        return 0
    line = sys.stdin.buffer.readline(16385)
    if len(line) > 16384 or not line.endswith(b"\n"):
        raise ValueError("request exceeds the 16 KiB limit or is incomplete")
    context, options = parse_request(json.loads(line))
    result = generate_connection_proof(context, ROOT / "p2c_roots_v1.pem", options, ProgressReporter())
    verified = verify_connection_proof(result.envelope, ROOT / "p2c_roots_v1.pem")
    emit({"type": "result", "verified": True, "proof": result.envelope.proof.hex(),
          "context": {key: getattr(context, key) for key in sorted(CONTEXT_KEYS)},
          "attempts": result.attempts, "verification": asdict(verified)})
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError) as exc:
        emit({"type": "error", "message": str(exc)[:500]})
        raise SystemExit(1) from None
