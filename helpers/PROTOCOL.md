# Persistent claims helper protocol 4

The initial `start` and `ready` frames require `protocol: 4`. The ready frame
retains `roots: 1` and must include
`security: {"rsaPublicExponentMaxBits": 64}`. The desktop rejects a missing or
different limit before sending DNS/claim requests and asks for a helper rebuild.
One-shot claims and RSA probes use the suffix `--require-rsa-exponent-64`;
older helpers reject it before processing input or starting network work.
Proof encoding and the probe's fixed response fields are unchanged. Protocols
1–3 are rejected before starting work; older helpers do not provide validated
attempt outcomes and cannot be used for EMA observations.

An attempt emits `started` after reserving its start, immediately before the
actual TCP-start pacing gate, then `capture` when that capture finishes and one
terminal `attempt` result. The terminal result repeats the capture's
status, elapsed seconds and exact successful-connection count. A failed capture
does not consume the successful-capture budget. A full capture still consumes
that budget even if its certificate/signature later fails validation. This
capture accounting is separate from the EMA outcome.

Every terminal `attempt` result includes required `validationPassed`:

- `true`: domain, challenge, signature policy, pinned-root certificate path and
  CertificateVerify signature validation completed successfully, regardless of
  whether the connection work hash meets the real target.
- `false`: a started TCP/TLS capture failed without local cancellation, or a
  completed capture failed proof parsing or cryptographic validation.
- `null`: the attempt did not start, or local cancellation left capture or
  validation unfinished. Cancellation before verification begins is `null`.

Validation runs with the maximum work target, then the actual target is checked
separately. `verified` still means a winning proof is returned. A cancelled
attempt never returns a proof, but validation already completed or running to
completion retains its known `true`/`false` outcome. Only the terminal result
supplies a validated EMA observation, once per request; early `capture` frames
remain useful for diagnostics and the existing successful-connection budget.
The `seconds` field measures TCP/TLS effort from the actual connection start and
excludes queueing, local start-reporting delays, rate waits and proof verification.
The absolute handshake deadline remains ten seconds. Desktop captures complete
TLS 1.3, including server/client Finished, and attempt an authenticated
`close_notify`; this best-effort teardown adds at most 200 ms and drains at most
64 KiB. Teardown failure does not discard a completed capture.

The existing `blocked: "budget"` result is a no-start outcome, requiring
`started: false`, `captured: false`, `seconds: 0`, `validationPassed: null`,
`proof: null` and `verified: false`. No per-domain/IP cooldown response is
supported: `blocked: "endpoint"` and `retryAfterMs` are rejected. The helper
uses a weighted rotation of resolved public IPs, independently per domain and
signature-policy mask, without imposing additional transport backoff. It learns
from the same conclusive validated outcomes as the domain EMA, including valid
target misses, and reserves 1% of selection weight for uniform exploration.
Endpoint scores remain internal; no new wire fields or private data are needed.

During shutdown, the desktop drains results for outstanding requests within
the existing two-second process-termination deadline. Known validation outcomes
still update the EMA, but closing requests cannot deliver a proof for submission.

Legacy one-shot progress snapshots declare
`attemptStats.validation: "certificate-proof-v1"`. Their `recent` observations
use the same cryptographic success criterion and TCP/TLS duration. Snapshots
without that marker cannot be imported as validated EMA observations.

The terminal result's optional `message` contains only a fixed description:

- `TLS connection timed out` for socket timeout exceptions or expiry of the
  capture's absolute handshake deadline.
- `TLS capture or proof validation failed` for other capture/verification errors.
- `TLS capture cancelled` for cancelled captures.
- `Public DNS resolution is required` when the attempt could not start.

The desktop accepts these descriptions and replaces any other supplied message
with the generic capture failure. Fatal `error` frames use a fixed desktop
description too. Exception text, certificates, peer data and socket details are
never included in these descriptions. The existing diagnostics classifier maps
`TLS connection timed out` to `timeout`; generic failure descriptions remain accepted once the
helper has passed the startup security-capability check.
