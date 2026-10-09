from __future__ import annotations

import ipaddress
import math
import socket
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from .envelope import ConnectionProof
from .errors import P2CError, ProofFormatError, ProofVerificationError
from .hashes import internal_hash_to_display, meets_work_target
from .protocol import parse_proof
from .signatures import validate_signature_algorithms_mask
from .tls13 import Endpoint, TLSGenerationError, TLSProofMessages, capture_tls13_proof
from .verify import validate_root_bundle, verify_connection_proof


class GenerationError(P2CError):
    """A P2C proof could not be generated under the requested limits."""


@dataclass(frozen=True, slots=True)
class GenerationOptions:
    port: int = 443
    connections_per_second: int = 1
    concurrency: int = 1
    connection_timeout: float = 10.0
    overall_timeout: float = 0.0
    max_attempts: int = 0
    allow_private_addresses: bool = False
    enforce_root_pin: bool = True


@dataclass(frozen=True, slots=True)
class AttemptStats:
    """Last 100 validated outcomes, oldest first, with a per-run sequence count."""

    completed: int = 0
    recent: tuple[tuple[bool, float], ...] = ()


class _AttemptRecorder:
    def __init__(self) -> None:
        self._lock = Lock()
        self._completed = 0
        self._recent: deque[tuple[bool, float]] = deque(maxlen=100)

    def record(self, success: bool, seconds: float) -> None:
        # Ignore invalid clock observations. Success requires certificate and
        # proof-signature validation; the work-target test is independent.
        if type(success) is not bool or not math.isfinite(seconds) or seconds < 0:
            return
        with self._lock:
            self._completed += 1
            self._recent.append((success, round(seconds, 6)))

    def snapshot(self) -> AttemptStats:
        with self._lock:
            return AttemptStats(self._completed, tuple(self._recent))


@dataclass(frozen=True, slots=True)
class GenerationProgress:
    attempts: int
    elapsed: float
    attempts_per_second: float
    best_work_hash: str | None
    last_error: str | None
    attempt_stats: AttemptStats = AttemptStats()
    finished: bool = False


@dataclass(frozen=True, slots=True)
class GenerationResult:
    envelope: ConnectionProof
    attempts: int
    elapsed: float
    peer_ip: str


ProgressCallback = Callable[[GenerationProgress], None]
MAX_CONNECTION_LIMIT = 2147483647
MAX_CONCURRENCY = MAX_CONNECTION_LIMIT


def _is_public_endpoint(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # is_global alone includes multicast and some address-translation prefixes.
    # A DNS-controlled target must never turn a proof attempt into local traffic.
    if not address.is_global or any((address.is_multicast, address.is_reserved,
                                    address.is_unspecified, address.is_loopback,
                                    address.is_link_local)):
        return False
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return _is_public_endpoint(address.ipv4_mapped)
        for prefix in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"):
            if address in ipaddress.IPv6Network(prefix):
                return False
    return True


def _validate_options(options: GenerationOptions) -> None:
    if not 1 <= options.port <= 65535:
        raise GenerationError("port must be between 1 and 65535")
    if type(options.connections_per_second) is not int or not -1 <= options.connections_per_second <= MAX_CONNECTION_LIMIT:
        raise GenerationError(f"connections_per_second must be -1, 0, or a positive integer up to {MAX_CONNECTION_LIMIT}")
    if options.connections_per_second == 0:
        raise GenerationError("TLS proof generation is disabled by connections_per_second=0")
    if type(options.concurrency) is not int or not 1 <= options.concurrency <= MAX_CONCURRENCY:
        raise GenerationError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    if not math.isfinite(options.connection_timeout) or options.connection_timeout <= 0:
        raise GenerationError("connection_timeout must be finite and positive")
    if not math.isfinite(options.overall_timeout) or options.overall_timeout < 0:
        raise GenerationError("overall_timeout must be finite and non-negative")
    if options.max_attempts < 0:
        raise GenerationError("max_attempts must not be negative")


def resolve_endpoints(
    domain: str, port: int, *, allow_private: bool = False
) -> tuple[Endpoint, ...]:
    try:
        addresses = socket.getaddrinfo(
            domain,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise GenerationError(f"DNS resolution failed for {domain}: {exc}") from exc
    result: list[Endpoint] = []
    seen: set[tuple[int, str]] = set()
    rejected: list[str] = []
    for family, socket_type, protocol, _, address in addresses:
        ip_text = str(address[0]).split("%", maxsplit=1)[0]
        try:
            parsed_ip = ipaddress.ip_address(ip_text)
        except ValueError:
            rejected.append(ip_text)
            continue
        if not allow_private and not _is_public_endpoint(parsed_ip):
            rejected.append(ip_text)
            continue
        identity = (family, str(address))
        if identity in seen:
            continue
        seen.add(identity)
        result.append(Endpoint(family, socket_type, protocol, address, ip_text))
    if not result:
        detail = f"; rejected addresses: {', '.join(sorted(set(rejected)))}" if rejected else ""
        raise GenerationError(f"domain resolved to no permitted TCP addresses{detail}")
    return tuple(result)


def _capture(
    endpoint: Endpoint,
    envelope: ConnectionProof,
    connection_timeout: float,
) -> TLSProofMessages:
    return capture_tls13_proof(
        endpoint,
        envelope.domain,
        envelope.challenge,
        signature_algorithms_mask=envelope.signature_algorithms_mask,
        timeout=connection_timeout,
    )


def generate_connection_proof(
    context: ConnectionProof,
    roots_path: str | Path,
    options: GenerationOptions | None = None,
    progress: ProgressCallback | None = None,
) -> GenerationResult:
    """Search real TLS connections until one satisfies the P2C work target."""
    recorder = _AttemptRecorder()
    started_at = time.monotonic()
    last_update: GenerationProgress | None = None

    def observe(update: GenerationProgress) -> None:
        nonlocal last_update
        last_update = update
        if progress is not None:
            progress(update)

    try:
        result = _generate_connection_proof(context, roots_path, options, observe, recorder)
    finally:
        # The inner function has already joined running captures. Include their
        # real outcomes even when an earlier capture won or the budget expired.
        # DNS/root failures and queued futures cancelled before starting do not
        # create synthetic failed TLS attempts.
        stats = recorder.snapshot()
        elapsed = time.monotonic() - started_at
        if progress is not None:
            progress(GenerationProgress(
                attempts=stats.completed,
                elapsed=elapsed,
                attempts_per_second=stats.completed / elapsed if elapsed else 0.0,
                best_work_hash=last_update.best_work_hash if last_update else None,
                last_error=last_update.last_error if last_update else None,
                attempt_stats=stats,
                finished=True,
            ))
    return replace(result, attempts=stats.completed, elapsed=elapsed)


def _capture_observed(
    endpoint: Endpoint,
    context: ConnectionProof,
    timeout: float,
    recorder: _AttemptRecorder,
    roots_path: str | Path,
    *,
    enforce_root_pin: bool = True,
) -> TLSProofMessages:
    # Begin inside the worker: executor queue time is not connection latency.
    started_at = time.monotonic()
    success = False
    seconds = None
    try:
        captured = _capture(endpoint, context, timeout)
        seconds = time.monotonic() - started_at
        preflight = replace(context, proof=captured.encoded_proof, connection_work_target="f" * 64)
        verify_connection_proof(preflight, roots_path, enforce_root_pin=enforce_root_pin)
        success = True
        return captured
    finally:
        # Verification may finish after a different connection wins. Keep that
        # real outcome once, in validation-completion order, while latency still
        # measures only TCP/TLS rather than local cryptographic work.
        if seconds is None:
            seconds = time.monotonic() - started_at
        recorder.record(success, seconds)


def _generate_connection_proof(
    context: ConnectionProof,
    roots_path: str | Path,
    options: GenerationOptions | None,
    progress: ProgressCallback,
    recorder: _AttemptRecorder,
) -> GenerationResult:
    if options is None:
        options = GenerationOptions()
    _validate_options(options)
    validate_signature_algorithms_mask(context.signature_algorithms_mask)
    if type(context.version) is not int or context.version != 2:
        raise GenerationError("only connection proof envelope version 2 is supported")
    if context.proof:
        raise GenerationError("generation context must have an empty proof field")
    try:
        datetime.fromtimestamp(context.validation_time, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise GenerationError("validation_time cannot be represented") from exc
    validate_root_bundle(
        roots_path,
        context.root_certificates_version,
        enforce_root_pin=options.enforce_root_pin,
    )
    endpoints = resolve_endpoints(
        context.domain, options.port, allow_private=options.allow_private_addresses
    )
    started_at = time.monotonic()
    next_start = started_at
    attempts_started = 0
    attempts_completed = 0
    next_endpoint = 0
    best_value: int | None = None
    best_hash: str | None = None
    last_error: str | None = None
    pending: dict[Future[TLSProofMessages], int] = {}

    executor = ThreadPoolExecutor(max_workers=options.concurrency, thread_name_prefix="p2c-tls")
    try:
        while True:
            now = time.monotonic()
            elapsed = now - started_at
            if options.overall_timeout and elapsed >= options.overall_timeout:
                raise GenerationError(
                    f"generation timed out after {attempts_completed} completed attempts"
                )
            if options.max_attempts and attempts_started >= options.max_attempts and not pending:
                detail = f"; last error: {last_error}" if last_error else ""
                raise GenerationError(
                    f"no proof met the target in {attempts_completed} attempts{detail}"
                )

            while len(pending) < options.concurrency:
                if options.max_attempts and attempts_started >= options.max_attempts:
                    break
                now = time.monotonic()
                if options.connections_per_second != -1 and now < next_start:
                    break
                endpoint = endpoints[next_endpoint % len(endpoints)]
                next_endpoint += 1
                attempts_started += 1
                attempt_timeout = options.connection_timeout
                if options.overall_timeout:
                    attempt_timeout = min(
                        attempt_timeout,
                        options.overall_timeout - (now - started_at),
                    )
                future = executor.submit(_capture_observed, endpoint, context, attempt_timeout, recorder,
                                         roots_path, enforce_root_pin=options.enforce_root_pin)
                pending[future] = attempts_started
                if options.connections_per_second != -1:
                    interval = 1.0 / options.connections_per_second
                    # Retain Core's bounded catch-up phase through timer and
                    # worker delays instead of adding a new interval to now.
                    next_start = max(next_start + interval, time.monotonic() - 1.0)

            if not pending:
                delay = max(0.0, next_start - time.monotonic())
                time.sleep(min(delay, 0.05))
                continue

            wait_timeout = 0.05
            if len(pending) < options.concurrency and options.connections_per_second != -1:
                wait_timeout = min(wait_timeout, max(0.0, next_start - time.monotonic()))
            done, _ = wait(pending, timeout=wait_timeout, return_when=FIRST_COMPLETED)
            for future in done:
                pending.pop(future)
                attempts_completed += 1
                try:
                    capture = future.result()
                    candidate = replace(context, proof=capture.encoded_proof)
                    parsed = parse_proof(candidate.proof, candidate.domain, candidate.challenge)
                    numeric_work = int.from_bytes(parsed.connection_work_hash, "little")
                    if best_value is None or numeric_work < best_value:
                        best_value = numeric_work
                        best_hash = internal_hash_to_display(parsed.connection_work_hash)

                    if meets_work_target(
                        parsed.connection_work_hash, candidate.connection_work_target
                    ):
                        elapsed = time.monotonic() - started_at
                        return GenerationResult(
                            candidate, attempts_completed, elapsed, capture.peer_ip
                        )
                    last_error = None
                except (
                    OSError,
                    TLSGenerationError,
                    ProofFormatError,
                    ProofVerificationError,
                ) as exc:
                    last_error = str(exc)

            if progress is not None and attempts_completed:
                elapsed = time.monotonic() - started_at
                stats = recorder.snapshot()
                progress(
                    GenerationProgress(
                        attempts=stats.completed,
                        elapsed=elapsed,
                        attempts_per_second=stats.completed / elapsed if elapsed else 0.0,
                        best_work_hash=best_hash,
                        last_error=last_error,
                        attempt_stats=stats,
                    )
                )
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
