"""One key-free RSA capability handshake with a DNS-inclusive monotonic budget."""

from __future__ import annotations

import ipaddress
import json
import secrets
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread

from connectcoin_p2c_tools.domain import is_canonical_domain
from connectcoin_p2c_tools.envelope import ConnectionProof
from connectcoin_p2c_tools.generator import resolve_endpoints
from connectcoin_p2c_tools.tls13 import CaptureControl, capture_tls13_proof
from connectcoin_p2c_tools.verify import validate_root_bundle, verify_connection_proof

PROBE_SECONDS = 3.0
MAX_REQUEST_BYTES = 1024
REQUEST_KEYS = {"domain", "rootVersion", "validationTime"}


def parse_probe_request(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != REQUEST_KEYS:
        raise ValueError("invalid RSA probe request")
    domain = value["domain"]
    if (not isinstance(domain, str) or not is_canonical_domain(domain) or "." not in domain
            or domain.endswith((".localhost", ".local", ".internal", ".home.arpa"))):
        raise ValueError("invalid RSA probe domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("RSA probe requires a DNS domain")
    if type(value["rootVersion"]) is not int or value["rootVersion"] != 1:
        raise ValueError("unsupported RSA probe roots")
    moment = value["validationTime"]
    if type(moment) is not int or not 1 <= moment <= 253402300799:
        raise ValueError("invalid RSA probe time")
    datetime.fromtimestamp(moment, UTC)
    return {key: value[key] for key in REQUEST_KEYS}


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate RSA probe field")
        value[key] = item
    return value


def _remaining(deadline: float, control: CaptureControl) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0 or control.cancelled():
        raise TimeoutError("RSA probe expired")
    return remaining


def probe_rsa(request: dict, roots_path: str | Path, deadline: float,
              control: CaptureControl) -> bool:
    """Callers accept only an authenticated, completed RSA TLS 1.3 exchange."""
    request = parse_probe_request(request)
    _remaining(deadline, control)
    validate_root_bundle(roots_path, request["rootVersion"], enforce_root_pin=True)
    _remaining(deadline, control)
    endpoints = resolve_endpoints(request["domain"], 443, allow_private=False)
    _remaining(deadline, control)
    # Fresh randomness is independent of any wallet or transaction. The maximum
    # work target lets the proof verifier authenticate capability without mining.
    context = ConnectionProof(
        domain=request["domain"], txid=secrets.token_hex(32), input_index=0,
        connection_work_target="ff" * 32, root_certificates_version=1,
        signature_algorithms_mask=6, validation_time=request["validationTime"], proof=b"",
    )
    captured = capture_tls13_proof(
        endpoints[0], context.domain, context.challenge,
        signature_algorithms_mask=6, timeout=_remaining(deadline, control),
        control=control, complete_handshake=True,
    )
    _remaining(deadline, control)
    verify_connection_proof(replace(context, proof=captured.encoded_proof), roots_path,
                            enforce_root_pin=True)
    _remaining(deadline, control)
    return True


def run_probe(input_stream, emit, roots_path: str | Path, *, deadline: float | None = None) -> int:
    if deadline is None:
        deadline = time.monotonic() + PROBE_SECONDS
    control, done = CaptureControl(), Event()
    outcome = {"response": None, "verified": False}

    def work():
        try:
            line = input_stream.readline(MAX_REQUEST_BYTES + 1)
            if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
                raise ValueError("invalid RSA probe frame")
            request = parse_probe_request(json.loads(line, object_pairs_hook=_unique_object))
            # Require exactly one input frame and EOF (the parent closes stdin).
            if input_stream.read(1):
                raise ValueError("unexpected RSA probe frame")
            outcome["response"] = {"type": "rsa-probe", **request, "verified": False}
            outcome["verified"] = probe_rsa(request, roots_path, deadline, control)
        except Exception:
            # Network, certificate, parser and dependency errors are untrusted.
            # Nothing from them may reach the UI or escape as a traceback.
            pass
        finally:
            done.set()

    # OS DNS cannot be interrupted. A daemon keeps resolver hangs from holding
    # up this one-shot process; the parent also kills it at its startup deadline.
    worker = Thread(target=work, name="p2c-rsa-probe", daemon=True)
    worker.start()
    finished = done.wait(max(0.0, deadline - time.monotonic()))
    verified = finished and time.monotonic() < deadline and outcome["verified"] is True
    control.cancel()
    response = outcome["response"]
    if response is None:
        emit({"type": "error", "message": "Invalid or incomplete RSA probe request."})
        return 1
    emit({**response, "verified": verified})
    return 0
