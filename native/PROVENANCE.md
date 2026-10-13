# Native helper provenance

The C++ helper replaces the Python capture/validation service, preserving the
public protocol-4 boundary to the existing JavaScript controller. It does not
hold wallet private keys, build transactions, or broadcast transactions.

Parser, certificate validation, TLS capture adapters and provider patches are
adapted from MIT-licensed ConnectCoin Core at commit
`48f963c637893018ac353d71ce58110e084bf949`:

- `src/consensus/p2c.cpp` and `src/consensus/p2c_x509.cpp`;
- `src/wallet/p2c_tls.cpp` and `src/wallet/p2c_tls_private.*`;
- Mbed TLS RSA-PSS/root-first adapters and corresponding CMake patches;
- `src/univalue/include` and `src/univalue/lib` (MIT; original copyright
  notices retained in every imported file).

The transport and service adapters replace Core's node-specific dependencies.
Worker-local certificate/root parsing state avoids a shared verification lock.
The bounded worker-local certificate parsing LRU owns up to four exact TLS
Certificate messages and immutable metadata tied to their DER. It retains at
most 65,536 bytes of message/DER storage and a separate conservative 262,144-byte
charge for parsed structures/key allocations per worker (not measured RSS).
Larger inputs still undergo all validation without being retained. Parse or
admission failures cannot evict a previously valid entry. All supplied RSA
exponents are checked before publication,
leaf KU/EKU is decoded once, and all supplied validity dates are converted to
Unix bounds once. Each proof still checks its new block-median validation time
against every supplied certificate's bounds and enforces the leaf usage result.
Invalid date encodings and denied usage remain failures; this is not a cache of
whether a certificate is valid at a previous time, domain or trust anchor.
A separate positive-only signature cache owns exact child and parent DER bytes,
with at most eight entries and 65,536 DER bytes per worker (FIFO eviction).
Only successful static certificate-signature mathematics is memoized, never a
path, hostname, trust decision, validity interval, key policy or TLS
CertificateVerify. Parent selection and its diagnostic observer run on every
attempt, and failed signatures are never stored. Every proof still undergoes
context, certificate path, domain, validity, key-policy and dynamic CV checks.
Prepared contexts own validated inputs and precompute only public challenge and
target bytes. Reuse requires exact equality of domain, claim transaction ID,
input index, target, root version and signature mask, never bounty ID alone.
A new validation time is independently range-checked and retained for every
attempt; no cached context supplies a stale certificate-validation time.
Moved-from contexts cannot be reused. Captured proofs own immutable
bytes/context/parsed spans so the ordinary service can reuse one parse and its
hashes through authentication.
No ephemeral key, TLS nonce, shared secret or CV result is reused.
Each worker reuses only its TLS configuration and record-buffer allocations.
After every capture, including failures and cancellation, the complete provider
session reset clears handshake/session/transform state. RNG, BIO and hostname
bindings are detached before the storage becomes idle; reset failure discards
the context. Signature masks and the challenge are rebound per attempt. This
does not enable session resumption, share state across workers, or cache any
dynamic proof result. Offline tests exercise mixed domains/masks, fresh key
shares, interrupted captures, reset failure and subsequent successful recovery.

The TCP start gate uses a FIFO wait queue with one deadline-owning head instead
of periodic polling by every queued worker. Cancellation is published and wakes
the waiter before acquiring its socket mutex; budget/reachability invalidations
and shutdown also wake affected jobs. Start acknowledgement still precedes TCP,
and the original configurable pacing phase and one-second catch-up bound remain.
A failed acknowledgement closes admission before a successor can start. Capture
and validation counters retain their separate, per-job immutable observations.
The existing Python helper remains in `helpers/` as a differential reference,
not a runtime dependency or automatic fallback.

Mbed TLS **3.6.7** is statically built from its upstream release archive, with
SHA-256 `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.
The provider is Apache-2.0 licensed and retains its own third-party notices.
The claimer's setup/packaging includes the dependency licenses.

The checked X25519 patch routes only PSA Curve25519 public-key derivation and
shared-secret multiplication to the existing Project Everest/HACL code bundled
in that same archive. PSA still decodes and validates each private key and peer
point with the original Mbed TLS functions before dispatch; the adapter
serializes those validated values using Mbed TLS. RFC 7748 scalar clamping,
coordinate top-bit handling and reduction are preserved, and all-zero shared
outputs are rejected. Adapter scalar/coordinate copies and failed outputs are
cleared with `mbedtls_platform_zeroize`. Every ephemeral private key is still
freshly generated by the original PSA RNG path. Other curves, certificates,
TLS CertificateVerify, work hashes and target checks retain their existing code.
The HACL native-128-bit and portable implementations are selected by upstream's
compiler checks; no new curve arithmetic is introduced. The legacy generic ECP
implementation stays available with `CLAIMER_X25519_ACCELERATION=OFF` for
differential tests and comparison builds. Optional
`CLAIMER_X25519_TESTING=ON` counters verify both PSA dispatches in test builds;
production builds omit counter instrumentation.

SHA-224/SHA-256 optionally replace only Mbed TLS's compression function through
`MBEDTLS_SHA256_PROCESS_ALT`. Provider initialization, updates, byte counters,
cloning, padding, output formatting, errors and context cleanup are unchanged.
`CLAIMER_SHA256_ACCELERATION=ON` dispatches at runtime on x86-64 only when CPUID
reports SHA, SSSE3 and SSE4.1; other CPUs/platforms use the unchanged pinned
Mbed TLS C compression. Detection is thread-safe and runs once. ISA flags apply
only to the SHA-NI source, never the dispatcher or portable fallback. The full
portable provider is compiled under private names as a differential reference;
its compression also supplies the production fallback. No digest, HMAC, KDF
secret or validation result is cached or skipped.

The SHA-NI transform is adapted from `src/crypto/sha256_x86_shani.cpp` in the
same Core commit above (original file SHA-256
`7b5d092cea8d4c8ada0dbad2025c162126eb9d333d9ccf4beab1812813b4b33e`).
Its Bitcoin Core MIT attribution, including Jeffrey Walton/Intel/miTLS origins,
is retained; `Bitcoin-Core-COPYING` is included in the package. Only the general
compression transform and its helpers are included, not SHA256D64. Adaptations
replace Core's inline-attribute header, add a narrow C entry point and explicitly
zeroize addressable vector schedule/state scratch with the provider's cleanup
primitive. The round arithmetic is unchanged.
`CLAIMER_SHA256_ACCELERATION=OFF` retains stock provider hashing. Optional
`CLAIMER_SHA256_TESTING=ON` counters and a thread-local forced-portable override
verify dispatch in tests; production omits both. Building with
`CLAIMER_SHA256_X86_BACKEND=OFF` tests the CPU-independent accelerated-build
fallback without compiling any special-ISA code. Differential tests cover
SHA-224/256 known vectors, partial and unaligned updates, multiple blocks,
cloning/counter carry, PSA hashing, HKDF, concurrency and context zeroization.

A claimer-specific checked patch also reserves 49,152 additional input-buffer
bytes for fragmented Certificate handshake messages. This expands only bounded
reassembly storage; the TLS plaintext record limit remains 16,384 bytes, the
Certificate message limit remains 49,152 bytes, and the proof limit remains
65,536 bytes. Offline tests cover a valid certificate message larger than one
record and reject oversized records independently.

The embedded consensus-v1 root bundle is `helpers/p2c_roots_v1.pem`, SHA-256
`f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`.
CMake rejects a different bundle. It is never replaced by the host trust store.
The bundle's Mozilla attribution remains in its header.

Ordinary captures stop at CertificateVerify. Cryptographic validation is done
by the verifier after capture, including for valid proofs that miss the work
target. The separate RSA compatibility probe can complete the TLS handshake.

The abbreviated Certificate adapter in `p2c_tls_private.c` mirrors the envelope
parser from Mbed TLS 3.6.7 `library/ssl_tls13_generic.c` (Copyright The Mbed TLS
Contributors, used under Apache-2.0). It retains upstream record decryption and
bounded reassembly, request-context/list/entry/extension bounds, empty-chain
rejection, per-certificate extension-mask reset and the original
`mbedtls_ssl_tls13_check_received_extension` admission checks. Only the redundant
TLS-owned DER chain is omitted: the caller immediately parses the same exact
message through the owned certificate cache, and every proof still undergoes
the full chain, hostname, time, usage, signature-mask, CertificateVerify and
target checks. No untrusted parsed input becomes an authentication result.
The complete-handshake path keeps the original Mbed TLS handler. Offline
differential tests compare old/new admission for ECDSA/RSA, malformed lengths,
DER/count limits, empty chains, unknown/forbidden/unsolicited/duplicate
extensions and per-entry masks; loopback tests cover fragmented certificates,
fresh repeated captures, cache reuse and both native/Python proof verification.
