# Automatic Claims verification boundary

The offline Python tests run a controlled loopback TLS 1.3 server with a
temporary test CA. The real capture implementation obtains its handshake;
the independent verifier checks its CertificateVerify signature, certificate
path, DNS name, challenge and work target. Altered challenges, signatures,
targets, signature policies and the production-root pin are rejected.
The custom CA exception exists only in the test's direct verifier call, not
in `claims_bridge.py` or the wallet's production worker.

Provider security regressions use complete locally signed proofs with DNS
name-constrained intermediate CAs and duplicate self-signed intermediates at
the eight-certificate limit. They check wildcard escape rejection, legitimate
exact-name/wildcard acceptance and trusted duplicate-chain acceptance. The
duplicate-chain cases run in killable subprocesses with five-second deadlines.
No external endpoint or production trust-anchor substitution is involved.
Self-test regressions reject obsolete/prerelease providers; desktop packaging
also rejects legacy self-test output or a provider different from the source pin.
Packaging also rejects helpers that do not report the 64-bit RSA public-exponent
limit, even if their cryptography provider is otherwise current.
RSA regressions cover ordinary and restricted PSS keys, 1,024/2,048-bit moduli,
the inclusive 64-bit boundary (including DER sign padding), 65/256-bit rejection,
all supplied certificate positions, unused certificates/roots, and the direct
TLS-signature helper. Controlled capture tests reject oversized exponents at
the Certificate message without waiting for CertificateVerify, in both claim
and completed-probe modes. Runtime tests reject legacy helper capabilities and
enforce the one-shot/probe compatibility flag before any network work.
Root-cache regressions check file replacement, exact pin enforcement after
warmup, distinct root paths and unpinned test fixtures, bounded cache size,
concurrent callers and returned-list mutation. Fully signed proofs continue
to reject altered signatures, names, challenges, times, policies and targets;
oversized RSA roots remain rejected after cache warmup.

Offline telemetry tests cover completion order under concurrency, rolling
100-entry snapshots and monotonic completion counts, validated captures that
miss the work target, failed certificate/signature validation, queued cancellation,
DNS failure, and in-flight completions after a winning proof. A 100,000-attempt
simulation verifies the once-per-second output limit and bounded NDJSON size.
These scheduler tests mock public capture calls and send no public traffic.

Persistent protocol-4 tests cover startup/shutdown and rejection of earlier
protocols, strict framing/IDs/options,
DNS caching/expiry and endpoint rotation, global start-rate/concurrency limits,
per-attempt cancellation, completion-before-verification ordering, exact uint64
successful-capture budgets and their strict two-expected-value boundary, and
bounded pending/DNS/counter caches. A 1,100-capture simulation verifies that one
executor survives across all bounties without a 1,000-attempt lifetime cap. A
second loopback fixture verifies that cancellation interrupts a real blocked
socket receive rather than waiting for the handshake deadline.
Terminal validation tests use fully signed fixture proofs to distinguish a
cryptographically valid hash miss from invalid certificate names and invalid
CertificateVerify signatures. They also cover malformed proofs, known results
preserved through cancellation during/after verification, null outcomes when
cancelled before verification, unchanged capture duration, and one terminal
validated observation per request. Fixture roots are substituted only within
the test verifier call; the production service has no custom-root bypass.

The independent native Core regtest checks ConnectWallet's typed transaction wire
encoding, native Schnorr payments, P2C funding and the spending transaction's
exact challenge. Wallet service tests exercise complete bounty snapshots,
journal catch-up, reorg/window cleanup, preparation, cancellation and broadcast
failure handling using controlled RPC responses.

**An entire successful TLS proof claim accepted by the unmodified Core daemon
has not been verified end-to-end offline.** Core uses its immutable public CA
bundle in regtest too. Our generated test CA is deliberately not in that bundle.
Core's `VerifyP2CCertificateProofForTest` permits test roots only as a C++ unit
test API; it is not a runtime RPC or regtest switch. A recorded public proof
also cannot be reused for an arbitrary local claim: ClientHello is bound to
that spending transaction's ID and input index.

A positive daemon-level test requires an authorized TLS endpoint with a
certificate chaining to the pinned public roots, or an explicitly separate
test-only consensus harness. Neither production root enforcement nor the Core
daemon was modified to manufacture a passing test. These checks alone do not
establish mainnet readiness.
