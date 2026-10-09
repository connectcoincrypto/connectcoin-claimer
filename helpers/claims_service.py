"""Persistent, key-free protocol-4 TLS worker; no public network access at import."""

from __future__ import annotations

import json
import math
import re
import sys
import threading
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path

from connectcoin_p2c_tools.domain import is_canonical_domain
from connectcoin_p2c_tools.generator import MAX_CONNECTION_LIMIT, resolve_endpoints
from connectcoin_p2c_tools.hashes import meets_work_target
from connectcoin_p2c_tools.protocol import parse_proof
from connectcoin_p2c_tools.tls13 import CaptureCancelled, CaptureControl, TLSGenerationError, capture_tls13_proof
from connectcoin_p2c_tools.verify import (
    MAX_RSA_PUBLIC_EXPONENT_BITS,
    validate_root_bundle,
    verify_connection_proof,
)

MAX_PENDING = 512
MAX_DNS_CACHE = 4096
MAX_BUDGETS = 1024
MAX_UINT64 = (1 << 64) - 1
DNS_TTL = 60.0
DNS_RETRY = 2.0
CONNECTION_TIMEOUT = 10.0
ENDPOINT_EXPLORATION = 0.01
PUBLIC_FIELDS = ("domain", "txid", "input_index", "connection_work_target",
                 "root_certificates_version", "signature_algorithms_mask", "validation_time")


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid protocol integer")
    return value


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("invalid protocol command fields")


def _domain(value):
    if not isinstance(value, str) or not is_canonical_domain(value) or "." not in value or value.endswith((".localhost", ".local", ".internal")):
        raise ValueError("only public DNS domains are supported")
    return value


def read_frame(stream):
    line = stream.readline(16385)
    if not line:
        return None
    if len(line) > 16384 or not line.endswith(b"\n"):
        raise ValueError("protocol frame exceeds 16 KiB or is incomplete")
    # Never accept Python's non-standard NaN/Infinity JSON extensions.
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError("duplicate JSON object field")
            result[key] = value
        return result
    return json.loads(line, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON number")))


class BudgetExhausted(Exception):
    pass


@dataclass
class Budget:
    target: int
    successes: int
    users: int = 0


@dataclass(slots=True)
class EndpointScore:
    # Match the domain EMA prior and smoothing, but learn separately for each
    # DNS endpoint and exact on-chain signature policy. Credit is SWRR state,
    # not a concurrency reservation or a reason to defer any connection.
    connections: float = 0.1
    total_time: float = 0.02
    credit: float = 0.0

    def rate(self):
        # Representational bounds only: preserve finite weights after even an
        # extreme run of zero-duration samples, without a scheduling floor.
        if self.total_time == 0:
            return sys.float_info.max
        return min(sys.float_info.max, max(math.ulp(0.0), self.connections / self.total_time))


@dataclass
class Job:
    identifier: int
    kind: str
    context: object = None
    domain: str = ""
    bounty_id: str = ""
    control: CaptureControl = field(default_factory=CaptureControl)
    started: bool = False
    captured: bool = False
    seconds: float = 0.0
    started_at: float = 0.0
    running: bool = False
    successful_connections: int | None = None


class ClaimsService:
    def __init__(self, options, emit, parse_context, roots_path):
        _keys(options, ("connectionsPerSecond", "concurrency"))
        self.rate = _integer(options["connectionsPerSecond"], 1, MAX_CONNECTION_LIMIT)
        self.concurrency = _integer(options["concurrency"], 1, MAX_CONNECTION_LIMIT)
        self.max_pending = max(MAX_PENDING, self.concurrency + 2)
        validate_root_bundle(roots_path, 1)
        self.roots_path = roots_path
        self.emit_callback = emit
        self.parse_context = parse_context
        self.condition = threading.Condition(threading.RLock())
        self.output_lock = threading.Lock()
        self.capture_lock = threading.Lock()
        self.connection_lock = threading.Lock()
        self.jobs = {}
        self.pending = deque()
        self.dns = OrderedDict()
        self.budgets = OrderedDict()
        self.last_id = 0
        self.active_tls = 0
        self.active_dns = 0
        self.next_connection = 0.0
        self.connection_idle = True
        self.closed = False
        # Two resolver slots cannot occupy the TLS capacity. The same executor
        # serves all domains/bounties for the entire unlocked claims session.
        self.executor = ThreadPoolExecutor(max_workers=self.concurrency + 2, thread_name_prefix="connectwallet-p2c")
        self.scheduler = threading.Thread(target=self._schedule, name="connectwallet-p2c-scheduler", daemon=True)
        self.scheduler.start()

    def emit(self, value):
        # One writer prevents interleaved NDJSON from concurrent captures.
        encoded = json.dumps(value, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode("utf-8")) > 160 * 1024:
            raise ValueError("helper response exceeds 160 KiB")
        with self.output_lock:
            self.emit_callback(value)

    def command(self, command):
        if not isinstance(command, dict) or not isinstance(command.get("type"), str):
            raise ValueError("invalid protocol command")
        kind = command["type"]
        if kind == "cancel":
            _keys(command, ("type", "id"))
            identifier = _integer(command["id"], 1, (1 << 53) - 1)
            with self.condition:
                job = self.jobs.get(identifier)
            if job is not None:
                self._cancel(job)
            return
        if kind not in ("resolve", "attempt"):
            raise ValueError("unknown protocol command")
        _keys(command, ("type", "id", "domain") if kind == "resolve" else
              ("type", "id", "context", "bountyId", "successfulConnections"))
        identifier = _integer(command["id"], 1, (1 << 53) - 1)
        if kind == "resolve":
            job = Job(identifier, kind, domain=_domain(command["domain"]))
        else:
            context = self.parse_context(command["context"])
            bounty_id = command["bountyId"]
            successes = command["successfulConnections"]
            if not isinstance(bounty_id, str) or not re.fullmatch(r"[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})", bounty_id) or int(bounty_id[65:]) > 0xffffffff:
                raise ValueError("invalid bounty outpoint")
            if not isinstance(successes, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", successes) or int(successes) > MAX_UINT64:
                raise ValueError("invalid successful connection count")
            job = Job(identifier, kind, context, context.domain, bounty_id)
        with self.condition:
            if self.closed:
                raise ValueError("helper is shutting down")
            if identifier <= self.last_id:
                raise ValueError("request IDs must be strictly increasing")
            if len(self.jobs) >= self.max_pending:
                raise ValueError("helper pending request limit exceeded")
            if kind == "attempt":
                target = int(context.connection_work_target, 16)
                budget = self.budgets.get(bounty_id)
                if budget is None:
                    if len(self.budgets) >= MAX_BUDGETS:
                        discard = next((key for key, item in self.budgets.items() if not item.users), None)
                        if discard is None:
                            raise ValueError("helper budget cache is full")
                        del self.budgets[discard]
                    budget = Budget(target, int(successes))
                    self.budgets[bounty_id] = budget
                if budget.target != target:
                    raise ValueError("bounty target changed within helper session")
                budget.successes = max(budget.successes, int(successes))
                budget.users += 1
                self.budgets.move_to_end(bounty_id)
                # An empty or cancelled-only session earns no pacing credit.
                # Active captures and queued attempts both keep demand alive.
                if not any(item.kind == "attempt" and not item.control.cancelled() for item in self.jobs.values()):
                    self.connection_idle = True
            self.last_id = identifier
            self.jobs[identifier] = job
            self.pending.append(job)
            self.condition.notify_all()

    def _schedule(self):
        try:
            self._schedule_jobs()
        except (RuntimeError, MemoryError):
            # ThreadPoolExecutor grows lazily. A failed submit can already have
            # enqueued its job, so never retry it or leave the scheduler dead
            # with outstanding requests. The desktop closes the failed helper.
            try:
                self.emit({"type": "error", "message": "Claims helper could not create a connection worker"})
            finally:
                self.close()

    def _schedule_jobs(self):
        while True:
            with self.condition:
                if self.closed:
                    return
                chosen = next((job for job in self.pending if
                    (job.kind == "attempt" and self.active_tls < self.concurrency) or
                    (job.kind == "resolve" and self.active_dns < 2)), None)
                if chosen is None:
                    self.condition.wait()
                    continue
                self.pending.remove(chosen)
                chosen.running = True
                if chosen.kind == "attempt": self.active_tls += 1
                else: self.active_dns += 1
                self.executor.submit(self._run, chosen)

    def _run(self, job):
        try:
            if job.kind == "resolve": self._resolve(job)
            else: self._attempt(job)
        finally:
            with self.condition:
                self.jobs.pop(job.identifier, None)
                if job.kind == "attempt":
                    self.active_tls -= 1
                    self.budgets[job.bounty_id].users -= 1
                else:
                    self.active_dns -= 1
                self.condition.notify_all()

    def _resolve(self, job):
        ok = False
        if not job.control.cancelled():
            with self.condition:
                cached = self.dns.get(job.domain)
                if cached and cached["expires"] > time.monotonic():
                    self.dns.move_to_end(job.domain)
                else:
                    cached = None
            if cached is None:
                try:
                    endpoints = resolve_endpoints(job.domain, 443, allow_private=False)[:32]
                except Exception:
                    endpoints = ()
                with self.condition:
                    previous = self.dns.get(job.domain)
                    cached = {"endpoints": endpoints, "expires": time.monotonic() + (DNS_TTL if endpoints else DNS_RETRY),
                              "next": previous["next"] if previous else {},
                              # Keep the actual score objects for unchanged IPs:
                              # validation already in flight must update those
                              # same objects, not a stale copy. Removed endpoints
                              # and evicted domains have no retained cache owner.
                              "scores": {endpoint: previous["scores"].get(endpoint, {}) if previous else {}
                                         for endpoint in endpoints}}
                    self.dns[job.domain] = cached
                    self.dns.move_to_end(job.domain)
                    while len(self.dns) > MAX_DNS_CACHE:
                        self.dns.popitem(last=False)
            ok = bool(cached["endpoints"])
        cancelled = job.control.cancelled()
        self.emit({"type": "resolved", "id": job.identifier, "ok": ok and not cancelled,
                   **({"message": "Resolution cancelled" if cancelled else "Public DNS resolution failed"} if not ok or cancelled else {})})

    def _before_start(self, job):
        with self.condition:
            if self.closed or job.control.cancelled():
                raise CaptureCancelled("TLS capture cancelled")
            budget = self.budgets[job.bounty_id]
            if budget.successes == MAX_UINT64 or budget.successes * (budget.target + 1) > (1 << 257):
                raise BudgetExhausted()

    def _started(self, job):
        with self.condition:
            self._before_start(job)
            job.started = True
            job.started_at = time.monotonic()
        self.emit({"type": "started", "id": job.identifier})

    def _connecting(self, job):
        # One socket-start gate, shared by every domain. Keep its short start
        # report in the same serialized turn so delayed IPC cannot bunch
        # separately reserved permits. Waiting requests have not acknowledged
        # a start, preserving the desktop's bounded admission lookahead.
        while not self.connection_lock.acquire(timeout=0.010):
            self._before_start(job)
        try:
            self._connect_turn(job)
        finally:
            self.connection_lock.release()

    def _connect_turn(self, job):
        while True:
            with self.condition:
                self._before_start(job)
                delay = self.next_connection - time.monotonic()
                if delay <= 0:
                    break
            # Python 3.11+ uses high-resolution Windows sleeps. Condition
            # timed waits can round to ~15 ms; cap sleeps for cancellation.
            time.sleep(min(delay, 0.010))
        self._started(job)
        with self.condition:
            if self.closed or job.control.cancelled():
                raise CaptureCancelled("TLS capture cancelled")
            now = time.monotonic()
            if self.connection_idle:
                self.next_connection = max(self.next_connection, now)
                self.connection_idle = False
            # Core's shared phase retains at most one second of lateness;
            # there is no additional rolling-window quota or second timer.
            self.next_connection = max(self.next_connection + 1.0 / self.rate, now - 1.0)
            job.started_at = now

    def _select_endpoint(self, domain, signature_algorithms_mask):
        _integer(signature_algorithms_mask, 1, 7)
        with self.condition:
            cached = self.dns.get(domain)
            if not cached or cached["expires"] <= time.monotonic() or not cached["endpoints"]:
                raise ValueError("Resolve the public domain before attempting TLS")
            endpoints = cached["endpoints"]
            scores = []
            for endpoint in endpoints:
                policies = cached["scores"][endpoint]
                score = policies.get(signature_algorithms_mask)
                if score is None:
                    score = policies[signature_algorithms_mask] = EndpointScore()
                scores.append(score)
            rates = [score.rate() for score in scores]
            maximum = max(rates)
            normalized = [rate / maximum for rate in rates]
            total = sum(normalized)
            count = len(endpoints)
            for score, rate in zip(scores, normalized):
                # Reserve a small uniform share for exploration; all remaining
                # starts follow validated connections / network second.
                score.credit += ENDPOINT_EXPLORATION / count + (1.0 - ENDPOINT_EXPLORATION) * rate / total
            cursor = cached["next"].get(signature_algorithms_mask, 0) % count
            selected = cursor
            for offset in range(1, count):
                candidate = (cursor + offset) % count
                if scores[candidate].credit > scores[selected].credit:
                    selected = candidate
            scores[selected].credit -= 1.0
            cached["next"][signature_algorithms_mask] = (selected + 1) % count
            self.dns.move_to_end(domain)
            return endpoints[selected], scores[selected]

    def _observe_endpoint(self, score, validation_passed, seconds):
        if score is None or type(validation_passed) is not bool or not math.isfinite(seconds) or seconds < 0:
            return
        with self.condition:
            score.connections = 0.999 * score.connections + 0.001 * int(validation_passed)
            score.total_time = 0.999 * score.total_time + 0.001 * seconds
            # Only mutate the selected object. Never insert it into DNS here:
            # a late result for a removed IP/domain must not resurrect its state.

    def _fields(self, job):
        with self.condition:
            successes = (self.budgets[job.bounty_id].successes if job.successful_connections is None
                         else job.successful_connections)
        return {"id": job.identifier, "context": {key: getattr(job.context, key) for key in PUBLIC_FIELDS},
                "started": job.started, "captured": job.captured, "seconds": job.seconds,
                "cancelled": job.control.cancelled(), "successfulConnections": str(successes)}

    def _attempt(self, job):
        captured = None
        proof = None
        message = None
        blocked = None
        validation_passed = None
        validation_started = False
        endpoint_score = None
        try:
            if job.control.cancelled():
                raise CaptureCancelled("TLS capture cancelled")
            endpoint, endpoint_score = self._select_endpoint(job.domain, job.context.signature_algorithms_mask)
            try:
                captured = capture_tls13_proof(endpoint, job.context.domain, job.context.challenge,
                    signature_algorithms_mask=job.context.signature_algorithms_mask,
                    timeout=CONNECTION_TIMEOUT, control=job.control,
                    before_start=lambda: self._before_start(job), on_started=None,
                    on_connecting=lambda: self._connecting(job), complete_handshake=False)
                job.captured = True
            except CaptureCancelled:
                raise
            except Exception:
                # Snapshot a conclusive connection failure before emitting the
                # capture frame: cancellation afterwards must not erase it.
                if job.started and not job.control.cancelled():
                    validation_passed = False
                raise
            finally:
                if job.started:
                    elapsed = time.monotonic() - job.started_at
                    # Capture order is independent of potentially slow certificate
                    # verification. This frame measures raw captures and the
                    # successful-connection budget, not validated EMA outcomes.
                    with self.capture_lock:
                        job.seconds = round(max(0.0, elapsed), 6)
                        with self.condition:
                            if job.captured:
                                budget = self.budgets[job.bounty_id]
                                budget.successes = min(MAX_UINT64, budget.successes + 1)
                            job.successful_connections = self.budgets[job.bounty_id].successes
                        self.emit({"type": "capture", **self._fields(job)})
            if not job.control.cancelled():
                validation_started = True
                candidate = replace(job.context, proof=captured.encoded_proof)
                parsed = parse_proof(candidate.proof, candidate.domain, candidate.challenge)
                # A hash miss is still a validated TLS connection. Verify every
                # certificate path and CertificateVerify signature with only
                # the work threshold relaxed, then apply the real target.
                preflight = replace(candidate, connection_work_target="f" * 64)
                verify_connection_proof(preflight, self.roots_path)
                validation_passed = True
                if meets_work_target(parsed.connection_work_hash, candidate.connection_work_target):
                    if not job.control.cancelled(): proof = candidate.proof.hex()
        except BudgetExhausted:
            blocked = "budget"
        except CaptureCancelled:
            message = "TLS capture cancelled"
        except (TimeoutError, TLSGenerationError) as error:
            if validation_started and validation_passed is None:
                validation_passed = False
            # Socket timeouts and the capture's absolute deadline share one safe
            # description. Match only the provider's fixed local deadline error;
            # never forward arbitrary TLS/peer exception text to the desktop.
            timed_out = isinstance(error, TimeoutError) or error.args == ("TLS handshake exceeded the connection timeout",)
            if not job.started:
                message = "Public DNS resolution is required"
            else:
                message = "TLS connection timed out" if timed_out else "TLS capture or proof validation failed"
        except Exception:
            # Once synchronous proof validation starts, it produces a known
            # result even if cancellation arrives while it is running.
            if validation_started and validation_passed is None:
                validation_passed = False
            # Never echo certificates, raw socket errors, remote data or proof
            # contents in operational messages.
            message = "TLS capture or proof validation failed" if job.started else "Public DNS resolution is required"
        fields = self._fields(job)
        # Cancellation can arrive immediately after verification's final check.
        # Snapshot terminal state once, and never return a proof labelled cancelled.
        if fields["cancelled"]:
            proof = None
        # Raw capture is not sufficient evidence of a useful endpoint. Learn
        # exactly once from the terminal validated result, before publishing it;
        # an inconclusive cancellation is neutral, a known result is retained.
        self._observe_endpoint(endpoint_score, validation_passed, job.seconds)
        self.emit({"type": "attempt", **fields, "proof": proof,
                   "verified": proof is not None, "validationPassed": validation_passed,
                   **({"message": message} if message else {}), **({"blocked": blocked} if blocked else {})})

    def _cancel(self, job):
        job.control.cancel()
        with self.condition:
            queued = self.jobs.get(job.identifier) is job and not job.running
            if queued:
                self.pending.remove(job)
                self.jobs.pop(job.identifier)
            self.condition.notify_all()
        if queued:
            if job.kind == "attempt":
                self.emit({"type": "attempt", **self._fields(job), "proof": None,
                           "verified": False, "validationPassed": None, "message": "TLS capture cancelled"})
                with self.condition:
                    self.budgets[job.bounty_id].users -= 1
            else:
                self.emit({"type": "resolved", "id": job.identifier, "ok": False,
                           "message": "Resolution cancelled"})

    def close(self):
        with self.condition:
            if self.closed: return
            self.closed = True
            jobs = list(self.jobs.values())
            self.condition.notify_all()
        for job in jobs: self._cancel(job)
        if self.scheduler is not threading.current_thread():
            self.scheduler.join(2)
        # OS DNS resolution is not interruptible by Python. Electron's process
        # shutdown deadline remains the hard bound for a stuck resolver.
        self.executor.shutdown(wait=False, cancel_futures=False)


def run_service(stream, emit, parse_context, roots_path: str | Path):
    start = read_frame(stream)
    _keys(start, ("type", "protocol", "options"))
    if start["type"] != "start" or type(start["protocol"]) is not int or start["protocol"] != 4:
        raise ValueError("protocol 4 start command required")
    service = ClaimsService(start["options"], emit, parse_context, roots_path)
    try:
        service.emit({"type": "ready", "protocol": 4, "roots": 1,
                      "security": {"rsaPublicExponentMaxBits": MAX_RSA_PUBLIC_EXPONENT_BITS}})
        while True:
            command = read_frame(stream)
            if command is None: break
            if isinstance(command, dict) and command.get("type") == "shutdown":
                _keys(command, ("type",))
                break
            service.command(command)
    finally:
        service.close()
    return 0
