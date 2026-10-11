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
The single-message certificate parsing cache also owns immutable metadata tied
to its exact DER: all supplied RSA exponents are checked before publication,
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
The existing Python helper remains in `helpers/` as a differential reference,
not a runtime dependency or automatic fallback.

Mbed TLS **3.6.7** is statically built from its upstream release archive, with
SHA-256 `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.
The provider is Apache-2.0 licensed and retains its own third-party notices.
The claimer's setup/packaging includes the dependency licenses.

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
