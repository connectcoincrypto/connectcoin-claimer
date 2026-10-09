# Automatic Claims helper

`vendor/connectcoin_p2c_tools` contains the MIT-licensed, independent TLS 1.3
P2C implementation from [connectcoin-p2c-tools](https://github.com/connectcoincrypto/connectcoin-p2c-tools),
commit `ad35a58a0c59ed985b3566d352053773269e76d2` (0.3.0). The CLI and tests
are not required at runtime. The upstream license is retained alongside it.
ConnectWallet's local hardening in `generator.py` also rejects multicast,
reserved and IPv6 translation/tunnel destinations: `is_global` by itself is
not a sufficient SSRF boundary. Local patches also add independently cancellable
capture sockets and completion telemetry. Desktop raw capture success means
TLS capture through CertificateVerify, without waiting for server Finished or
sending client Finished, before certificate-path/CertificateVerify verification and the hash-target
test; it still governs the existing successful-connection budget. The protocol-4
desktop service emits a raw capture event before verification, then one terminal
result per request with a required tri-state `validationPassed`. For each domain and exact
signature-policy mask, the main process keeps two exponential moving averages:
validated success starts at `0.1`, capture time at `0.02` seconds, and every
completed attempt applies `new = 0.999 * old + 0.001 * observation`. Success is
`1` only after certificate-path and CertificateVerify signature verification,
and `0` for a TCP/TLS, proof-format, certificate or signature failure. Verification
relaxes only the work target to its maximum; a cryptographically valid hash miss
is a successful observation. The rate is the success average divided by the time
average. Every terminal validated outcome is consumed once, even when many
frames arrive in one pipe chunk; its elapsed time remains the original TCP/TLS
duration and excludes verification. Early raw capture frames do not update EMA.
DNS failures and locally cancelled unfinished attempts have `validationPassed:
null` and do not create TLS observations. Cancellation before validation begins
also has no validated observation. Once validation completes, its `true` or
`false` outcome is retained even if cancellation suppresses proof delivery,
including cancellation while synchronous validation is running. Raw captures
still consume the successful-connection budget even when validation fails.
The legacy one-shot generator retains bounded snapshots for development tooling;
it is not the desktop scheduling path. Its local scheduling patch now retains
the Core's bounded-debt deadline (`max(next + interval, now - 1 second)`), and
both the legacy bridge and persistent service accept positive signed 32-bit
rate/concurrency settings instead of imposing a 256 ceiling. Every worker verifies its capture before
recording an outcome, including in-flight work completed after another proof
wins. Snapshots identify these semantics with `validation: "certificate-proof-v1"`.
Importing a snapshot into the EMA rejects an absent/different marker or a gap
larger than the retained 100 samples, because omitted completions cannot
reconstruct the exact EMA. Legacy proof generation may still expose bounded
progress with such gaps. Persistent service and self-test require protocol 4;
earlier helpers must be rebuilt before the desktop accepts their outcomes.
Proof encoding is unchanged.

The RSA public-exponent limit is backported from P2C Tools commit
`2dbb42ba93ad194b3166ed455a0b2a95e8a05000`, aligned with Core commit
`a32fb95618f058a79125f1c5b98d95ad972445da`. This is a targeted backport;
the remaining vendored files retain the base and local patches described above.
The vendored verifier and capture path enforce Core's RSA public-exponent limit:
`e.bit_length() <= 64` (`e <= 2^64 - 1`), for every RSA modulus size. This is
not a 64-bit RSA key size: supported modulus sizes remain unchanged. Both
`rsaEncryption` and restricted RSA-PSS keys are covered, including every
supplied intermediate or unused certificate and every trusted root. Capture
checks the received Certificate message before proceeding to CertificateVerify;
proof verification checks keys before certificate-path or TLS signature work.
This tightens accepted proofs to match Core, without changing proof encoding,
root versions or the immutable root bundle.

The local `--probe-rsa` mode follows Core's `ProbeP2CRsaForTest` in
`src/wallet/p2c_tls.cpp`: one public endpoint on port 443, RSA mask 6, the pinned
version-1 roots, and certificate validation at the supplied wall-clock time.
It completes TLS 1.3, verifies Server Finished and sends Client Finished before
reporting authenticated RSA capability. This is an opt-in extension to `tls13.py`;
the desktop claims service does not opt into full handshake completion. Proofs
still encode only the original five messages through CertificateVerify. The probe uses a random dummy
transaction ID solely to reuse the challenge/proof verifier, and a maximum work
target; no wallet transaction or keys enter the process and no HTTP is sent.
Its three-second monotonic deadline includes input, roots, DNS, TLS and verification.
A daemon resolver cannot hold up process exit; the desktop also enforces a
three-second deadline including process startup. Only a fixed, bounded result
is emitted; network and certificate error text is suppressed.

`p2c_roots_v1.pem` is the immutable Mozilla-derived consensus trust bundle from
ConnectCoin Core. Its SHA-256 is
`f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`.
The provider verifies this pin before connecting and re-reads and checks the
current bundle on every proof verification. A one-entry cache keyed by exact
bundle bytes reuses only parsed, immutable root certificates and their RSA
exponent checks; each caller receives its own list. Peer certificate, time,
domain, path, policy and proof-signature checks still run for every proof.
Do not refresh the bundle with the operating system's current roots: a new
consensus bundle requires a new version. Its source and attribution are in its header.

The bridge accepts only a prepared claim's public context. It never accepts a
mnemonic, private key, wallet password, cookie, or RPC credentials. A proof is
bound to the **spending transaction ID**, not the bounty's funding transaction
ID. Validation uses the chain's median time past supplied by the main process.
The main process independently checks the funding transaction and builds the
claim before starting this helper. An unencrypted, untrusted RPC is not SPV;
the helper does not prove that the advertised chain is the canonical chain.

The helper uses TLS 1.3 with ephemeral X25519 keys from the cryptographic
provider and OS-backed random session IDs (`secrets.token_bytes`). Connections
are restricted to public IPs after DNS resolution, and DNS results are pinned
for each job. The TLS port is always 443. No HTTP requests are sent. Every
returned result passes work, domain, pinned-root certificate path, output
signature-mask, challenge, and CertificateVerify verification. This independent
X.509 implementation can reject some encodings accepted by Core; the node's
consensus validation remains authoritative.

The desktop uses one persistent helper/executor shared across all bounties,
defaulting to 100 starts/sec and 100 simultaneous TLS connections. Both settings
accept integers from 1 to 2,147,483,647, subject to actual OS/network capacity;
worker threads are created only as needed. Those global limits remain available to a single domain, without
additional per-domain/IP caps or progressive transport cooldowns. Below-floor domain/mask
policies that qualify at the initial 5/s rate have bounded once-per-minute
recovery probes without resetting EMA or weakening verification. Each connection
has a 10-second network deadline, excluding local queue/rate/start-report waits;
there is no 1,000-attempt
or 180-second batch limit. DNS resolution uses two bounded slots, a 60-second
positive cache and 2-second negative cache. The cache holds at most 4,096 domains
with 32 pinned endpoints each. The retained-request limit is
`max(512, concurrency + 2)` for TLS and DNS work; the desktop separately bounds
admissions awaiting a start acknowledgment to at most 128 (fewer at low rates).
That admission bound does not cap already-started connections at 128. Failure
to create a worker ends the helper session instead of silently losing requests.
Resolved endpoints use a weighted rotation per domain/signature-policy mask:
99% of selection weight follows each IP's valid-proof/TCP-TLS-time EMA and 1%
is uniform exploration. Each IP starts with `connections = 0.1` and
`totalTime = 0.02`, updating both with `0.999 * old + 0.001 * observation`.
Only certificate/path and proof-signature validation counts as success; a
valid target miss is also successful, while inconclusive cancellations are
neutral. This does not change the separate domain EMA or capture budget.
IP histories for unchanged endpoints survive DNS refreshes and are bounded by
the existing cache and seven supported signature-policy masks. No per-IP
connection cap or cooldown is added, and the ten-second timeout is unchanged.
Socket-start reports run outside the cancellation lock. A single serialized
TCP-start gate includes acknowledgment and advances its shared deadline from a
fresh monotonic reading, retaining at most one second of scheduling debt.
There is no additional rolling-window quota; catch-up may briefly exceed the
configured average rate, while true idle periods cannot bank credit. Captures
close after CertificateVerify and cancellation still aborts delivery. Only
opt-in full handshakes (the RSA probe) send an application-key close_notify and
drain up to 64 KiB for at most 200 ms; best-effort teardown failures do not
invalidate an otherwise completed capture. These are ConnectWallet-local patches;
Core and the upstream P2C Tools repository are not changed by them.
The helper independently enforces Core's exact successful-capture budget:
stop starting attempts once `successes * (target + 1) > 2^257`, including successful
captures whose hash misses. Already in-flight captures may still finish. A
bounded 1,024-entry counter cache never evicts active/queued bounties; the main
process supplies its retained uint64 counter on every request. No private-network
or unpinned-root bypass is available. Automatic Claims remain opt-in. Individual
cancellation closes only that attempt's socket. Cancellable TLS receives also
check cancellation using receive polls of up to 100 ms, including partial record headers and
bodies: cross-thread socket closure alone does not reliably wake macOS receives.
These polls share the original absolute handshake deadline; they do not extend
it. Wallet lock/stop terminates the entire helper. OS DNS calls cannot be interrupted by Python, so process termination
remains the hard shutdown bound for a stuck resolver. Input/output frames are
limited to 16/160 KiB and concurrent output is serialized.

For development, run `node scripts/setup-claims.mjs`. It creates a private
Python virtual environment and installs the pinned provider. Python 3.11+
must already be installed. This is a local setup operation, never an automatic
download triggered by a remote bounty. For desktop packaging, run
`node scripts/setup-claims.mjs --build` on each target OS. The resulting
`helpers/bin/connectwallet-claims/` directory must be copied unchanged into Electron's
external resources (not inside ASAR). Its launcher is `connectwallet-claims.exe` on
Windows and `connectwallet-claims` on macOS/Linux. A user-created source installation
can use the virtual environment instead.

The provider is pinned to `cryptography==50.0.1` (official wheels include OpenSSL
4.0.2). This includes the fixes for GHSA-jwv3-5hgf-82ww, GHSA-m2h6-j472-rp4c,
GHSA-537c-gmf6-5ccf and GHSA-g6cj-pr64-35w5. The first two affect certificate
path verification; listing the latter advisories does not imply their affected
APIs were reachable from this helper. `--self-test` reports the actual provider
and its OpenSSL backend and rejects obsolete or prerelease providers. Desktop
packaging requires that report to match the source pin and declare
`rsaPublicExponentMaxBits: 64`, preventing reuse of an old helper after a
source-only dependency or verification-policy update. Existing distributed apps
must be rebuilt/replaced; there is no remote runtime dependency download.
At runtime the persistent service must advertise that exponent limit before
the desktop sends any DNS/claim jobs, together with protocol 4 for validated
attempt observations. One-shot claim and RSA-probe launchers
pass `--require-rsa-exponent-64`; older helpers reject this unknown argument
before starting network work, so a source update cannot silently reuse them.

The build copies original Python, provider, CFFI, parser and bootloader notices
into `_internal/licenses/dependencies`. It includes the installed provider's
SBOMs and obtains the original OpenSSL notices from version-tagged upstream
sources. Rust dependency license archives are checked against the exact crate
SHA-256 checksums in the provider's SBOM; their text is retained unchanged.
`manifest.json` records the provenance and hash of each copied notice. A fresh
packaging build therefore needs Internet access for these license sources;
the resulting desktop helper does not download them at runtime.
