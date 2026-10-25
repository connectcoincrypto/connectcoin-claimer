# ConnectCoin Claimer

A headless, address-only Automatic Claims client for ConnectCoin mainnet.
It discovers P2C bounties through the same public JSON-RPC service used by
ConnectWallet, generates and validates TLS proofs locally, and sends claim
rewards to the address you configure. It does not run a full node or a GUI.

**No seed, private key, wallet file or password is needed.** This program cannot
make ordinary payments from your wallet. It only builds transactions spending
eligible P2C bounties with connection proofs. Never put wallet secrets in its
configuration.

## Run the portable program

1. Extract the **whole ZIP** into a writable folder. Keep `claimer.exe`
   (Windows) or `claimer` (Linux/macOS) together with its `helpers` directory.
2. Run `claimer.exe` / `./claimer`. The ZIP contains no configuration file or
   example. On first launch, the program creates `claimer.conf` beside the
   executable with a blank receiving address and exits without connecting.
3. Set `receiving_address` to **your own mainnet `cc1p...` address**.
4. Optionally run `claimer.exe --check` (or `./claimer --check`). This validates
   the configuration and helper availability offline, without making claims.
5. Run the program again. With a valid configuration it starts automatically.
   Use **Ctrl+C** for a clean shutdown. Do not run another instance with the same
   configuration file.

You do not need Node.js, Python, Electron, or ConnectCoin Core installed to use
the portable package. Windows binaries are currently unsigned. The Linux x64
CI package is built on Ubuntu 22.04 and requires a compatible glibc-based OS;
it is not an Alpine/musl package.

macOS ZIPs are separate native builds: `macos-arm64` for Apple Silicon and
`macos-x64` for Intel. They target **macOS 15 or newer** and are tested on macOS
15. Run `./claimer` in Terminal from the extracted folder. No Homebrew, Node.js
or Python installation is needed. The binaries have **ad-hoc signatures**, not
Apple Developer ID signatures or notarization; Gatekeeper may block downloaded
executables. Only approve software you trust using macOS Privacy & Security;
do not disable Gatekeeper globally. Verify the published SHA-256 first.

## Configuration

```ini
receiving_address=
max_connections_per_second=100
max_simultaneous_connections=100
min_connects_per_connection_second=1000

rpc_host=connectcoin4.com
rpc_port=48190
lookback_blocks=600
fee_rate=1500
```

- `receiving_address`: required mainnet address with a valid checksum and
  secp256k1 public key. There is no default donation/developer destination.
- `max_connections_per_second`: desired maximum TCP starts per second across
  all domains. Positive signed 32-bit integer; **no 256 ceiling**. Hardware,
  the network, servers and simultaneous slots can reduce the achieved rate.
- `max_simultaneous_connections`: global number of concurrent claim jobs, also
  a positive signed 32-bit integer. Large values consume sockets, CPU and RAM;
  they are not preallocated as that many workers at startup.
- `min_connects_per_connection_second`: minimum estimated **net atomic connects
  earned per second of connection effort**, not a minimum number of connections.
  Default `1000`; `0` disables this economic floor. Uses work probability,
  payout after fee, and the domain/signature-policy smoothed recent valid-proof/time ratio.
  Positive, valid candidates below this floor receive only the bounded bootstrap/
  recovery sampling described below, not ordinary full-rate connection work.
- `rpc_host`, `rpc_port`: the public plaintext TCP JSON-RPC endpoint, **not**
  Core's administrative HTTP RPC. No RPC username/password is needed. Mainnet
  identity/genesis are checked; another network is rejected.
- `lookback_blocks`: recent blocks used for bounty discovery, `1..600`.
- `fee_rate`: atomic connects per virtual byte, `1201..100000`. Default `1500`.
  **1 CONN = 10,000,000,000 connects.** The conservative claim fee reserves the
  maximum proof size, as in ConnectWallet; a smaller actual proof does not
  automatically refund this fee. This may exclude very small bounties.

Blank lines and lines starting with `#` or `;` are accepted. Unknown keys,
duplicate settings and invalid values are errors; settings are never silently
clamped. Restart after editing. With `--config PATH`, the state/lock files are
kept next to that configuration. Relative paths resolve from the current
working directory. Source runs default to `./claimer.conf`.

## Claiming behavior

- Reuses the ConnectWallet **v1.1.5** scheduler and native helper, with a small
  public-only transaction layer and a configurable economic floor.
- Shares one pacing clock at actual TCP start:
  `next = max(next + 1/rate, now - 1 second)`. Idle time does not earn unlimited
  credit. Bounded catch-up can briefly exceed the configured rate over a shorter
  measurement interval; this is not a strict rolling one-second quota.
- Alternates domain rotation and expected return, using each domain's best
  eligible bounty. Keeps endpoint rotation and successful-connection budgets
  from the desktop engine; performance estimates use the rolling window below.
- Checks the work target immediately after **Certificate** and discards misses
  without waiting for CertificateVerify or verifying signatures. The hash covers
  ClientHello, ServerHello, EncryptedExtensions and Certificate. Candidates that
  meet the target continue through **CertificateVerify**, without waiting for
  Finished, and still require certificate path, domain, time, usage, signature
  policy, proof binding, signature and target validation before acceptance.
  Uses the pinned consensus roots. Early discards are reported as `target misses`,
  separately from valid proofs and failures; each consumes one candidate budget
  slot, never a claim or authenticated-proof counter.
  The abbreviated capture omits only the TLS library's unused Certificate
  transcript checksum; the proof verifier still hashes and authenticates the
  exact captured transcript. Completed TLS handshakes keep their usual checksum.
- Restricts TLS endpoints to public IPs on port 443; does not send HTTP requests.
- Immediately excludes an endpoint after an explicit OS no-route/network-down
  error, rather than repeatedly selecting it through normal performance scoring.
  Only an unsupported socket family excludes that entire IP family. Exclusions
  last 60 seconds, span domains/signature policies and survive DNS refreshes;
  queued attempts check them again before TCP starts. All-excluded domains use
  the existing bounded DNS retry while waiting for connectivity to recover.
  Timeouts, connection refusal, TLS/certificate errors and local resource
  exhaustion do not declare an address family unsupported. Validation is unchanged.
- Discovers up to 600 recent blocks with at most four parallel block reads;
  stages coherent snapshots and replays the bounty journal. Healthy polling
  reuses the cursor and block cache rather than redownloading every block.
  The validated canonical hash list is also cached: an unchanged tip requires
  no `getrecentblockhashes` download. Discovery still replays all journal pages
  (including mempool changes). The last complete page supplies an atomic
  tip-and-cursor fence; any later hash or block read requires another replay
  before publication. An unchanged warm cycle therefore needs one journal
  request, without a redundant second poll or `getchaintip` request.
  Compatible servers also accept `compact: true`: unchanged replies acknowledge
  a SHA-256 binding of the exact requested network, tip metadata and cursor.
  That acknowledgement can only reuse this request's validated complete window;
  it cannot advance a cursor or invent block hashes, bounty rows or empty counts.
  Changed pages share publication tips through a bounded page-local table.
  Mutable-state patches bind to the SHA-256 digest of an already validated
  bounty's immutable fields, and the reconstructed row passes the same full
  validation as an expanded row. Event labels/spenders may be intermediate
  coalesced mutations; the validated final row controls admission. Unknown rows
  trigger an expanded replay from the same cursor, before publication. Malformed
  envelopes, known-reference mismatches and contradictory counts never use that
  fallback. Optional features are removed individually only on RPC `-32602`;
  backend, transport and malformed-data failures do not negotiate away checks.
  The current `compact_version: 3` opt-in extends version 2's wire reductions, not
  validation: request-bound tip/block arrays and unchanged cursors reconstruct
  from the exact privately owned request snapshot; page-tip references, added
  identities and equal spender aliases are expanded before the same complete
  row, count, sequence and canonical-chain checks. Reorganizations and unbound
  responses retain explicit tips, cursors and block-delta bases. Contradictory
  or mixed aliases fail closed. Unsupported v3 falls back to v2, then v1, at the
  same cursor, remembered only for that RPC connection epoch and retried after a
  reconnect. Polling, receipt schedules, journal retention and counters do not
  change.
  A changed tip not covered by an inline block delta, including a same-height reorganization, requests
  the latest 5 hashes, then 100, then 600 as needed to find a matching cached
  hash **and height** and reconstruct the complete window. Contradictory
  ancestry is rejected, and a rollback that lacks the oldest required blocks
  also escalates. Each response is reconciled independently, never joined to
  another partial response from a different tip. Journal resets discard all
  cached bounty state and count authority, then obtain a complete current,
  validated hash/count manifest after a new journal watermark. Retained hashes
  only check consistency; old counts or a short suffix cannot replace that
  manifest. Fresh acknowledged zero counts avoid empty streams; positive counts
  require either a complete validated journal-row set or a complete block stream
  and replay. Unknown counts always require the complete stream and replay. RPCs
  without count support retain the full-stream fallback. This complete manifest
  is for initialization/reset recovery, not every ordinary new block.
  Startup without a cache and RPC reconnects
  fetch the full hash list; reconnects retain the existing cursor and block
  contents for incremental recovery when that cursor remains valid. The RPC
  server must support the optional `getrecentblockhashes` `count` parameter for
  reduced transfers. Older servers that reject it fall back to a full request;
  malformed data never triggers that compatibility fallback.
  Hash-window reads request authoritative all-output bounty counts when supported.
  Only the explicit `bounty_counts: 1` acknowledgement and a valid count for every
  returned block can establish an empty block. Positive counts still require a
  complete snapshot of exactly that size, including spent, pending and immature
  outputs. Hash reads always require journal replay before publication. A cold
  600-block window with acknowledged zero counts therefore needs three RPCs
  instead of 600 empty streams plus the window and journal reads. Counts remain
  bound to canonical block hashes and are revoked with a journal reset.
  Journal pages build a fallback outpoint index only when a validated event
  lacks its block hash, at most once per page. Empty pages and explicitly located
  events avoid that scan; event validation, replay and final snapshot checks remain.
- A catalog resync keeps the same helper, validated captures, successful-work
  budgets and verified proofs. New preparations and broadcasts wait until the
  complete replacement snapshot and journal replay are published atomically;
  a final pre-write check also fences broadcasts queued behind RPC quotas.
  Known spent/reorganized outpoints are cancelled individually. Normal window
  aging does not discard already-started captures or their verified winners.
- Preparation is limited to four concurrent jobs. Indexed views of all eligible
  candidates and already-prepared candidates share the same priority and rotation
  state. Filling or freeing a preparation slot does not scan and repark the entire
  backlog. Retry deadlines, cancellation and prepared-cache eviction update these
  views without stranding queued candidates.
- Reuses fully validated funding transactions by their exact bytes, including
  witness, across bounties sharing a parent. Cached output records are private and
  immutable; each claim still checks its outpoint, amount, ownership, bounty
  metadata, receiving address, fee and dust. Both caches use least-recently-used
  eviction, with at most 256 entries each and conservative retained-size budgets
  of 16 MiB for raw transactions and 32 MiB for validated records. These are cache
  budgets, not process-memory limits. Oversized entries are validated without
  retention; disconnect, failure and stop clear both caches.
  Funding reads request `raw_only: true` to omit unused verbose metadata, not
  transaction data: the complete original hex, including every witness byte,
  still undergoes the same parsing, identity and output checks. Only `-32602`
  retries the same txid through the legacy response shape. That compatibility
  choice is retained for the current RPC epoch; cancelling one consumer never
  cancels another consumer's shared parent read.
- Uses one RPC connection, polling every five seconds, with conservative client
  quotas: 48 ordinary calls/minute/method, eight calls/minute/block for bounty
  streams, at most four normal submissions in flight, and one serial recovery
  operation (which can retransmit one saved claim). Recovery shares the same
  RPC quotas and twelve-request global capacity. These are separate from the
  TCP/TLS connection settings. Server limits/cooldowns are also respected;
  other clients sharing your IP consume the same server quotas.
- A busy or invalidated block read stops new work in that discovery batch;
  already-started streams keep all validation and time/size limits before the
  batch retries. A genuine malformed sibling still fails closed and no partial
  catalog or cursor is published.
- Disconnects pause the workers; discovery catches up before resuming. Invalid
  chain identity, malformed snapshots and fatal helper errors stop the client.

Terminal output reports TCP connection attempts, active started connections, valid and
failed observations, early target misses, targets reached and accepted submissions. The recent rate
uses a bounded ten-second window. `accepted` means the RPC acknowledged the
transaction, **not** that it is confirmed in a block. Duplicate winning proofs
for the same bounty are not submitted concurrently.

During a catalog rebuild, `[resyncing]` distinguishes the submission barrier
from a stopped helper. `Discovery reset:` reports a safe reset reason and RPC
code, when available. `RPC failure:` reports the method, stage, failure source,
safe error category/codes, and whether a request was written or its outcome is
unknown. These diagnostic lines do not print RPC bodies or proof bytes. The
five-second metrics line keeps the same field order and ten-second rate window.

This light client relies on its configured RPC for chain state, availability
and relay; validating a proof locally is not independent full-node validation.
The service is plaintext, so use an endpoint/network you trust. Claims consume
bandwidth and CPU; a configured rate does not guarantee earnings.

### Recent domain and IP performance

Each tracked domain/signature policy and native DNS endpoint/signature policy keeps
up to **60 one-minute buckets**: concluded observations, usable work candidates
and total TCP/TLS duration. The estimated rate includes a fixed smoothing base:

`rate = (5 + usable candidates in the window) / (1 + total TCP/TLS seconds in the window)`

A usable candidate is a fully validated proof or a structurally checked
Certificate prefix discarded because its work hash misses the target. The
latter measures connection throughput, not authenticated server identity; it
never increments the valid-proof counter. Winners must pass full verification.

The base is **5 virtual successes and 1 second**, applied once at score lookup,
not once per observation or per bucket. It never appears in real attempt/proof
counters, successful-capture budgets or claims. This is a fixed-window ratio with
a smoothing base, not an exponential moving average or a wall-clock start rate.
Failed conclusive attempts
contribute time but no usable candidate; cancellation before a conclusive
validation or target-miss result is not an observation. Explicit local route/family failures retain their actual
attempt counters but do not penalize remote domain or endpoint quality. Ordinary
timeouts still contribute failed observations. All certificate and proof validations
still run before accepting a winning proof.

The current minute and the previous 59 minutes are retained. This is a
minute-granularity window: a sample expires approximately 59–60 minutes after
completion, not exactly 3,600 seconds later. A monotonic clock advances buckets
on both observation and score lookup, including when an endpoint is idle. The
usual update does not scan past connections or allocate a per-connection record.

An empty, expired or evicted history has the same base estimate of **5/s**. One
failed attempt lasting 1 second changes an otherwise empty history to **2.5/s**,
not zero; one lasting 0.2 seconds gives approximately **4.167/s**. The base does
not expire, accumulate on reads or create imaginary valid proofs. Repeated
failures can still bring expected return below the configured economic floor;
bounded bootstrap/recovery probes remain applicable in that case, including
when a fresh candidate is below the floor even at the 5/s base estimate.
The native 99% performance / 1% rotation weighting is unchanged.

Sampling selects at most one representative per domain/signature-mask policy.
Each retained sampling episode allows up to **32 starts**, at least **250 ms**
apart, then at most one start per **60 seconds** for that policy. All sampled
policies share a **global maximum of four starts per second**, with one pending
start acknowledgement at a time and no accumulated idle/burst credit. Ordinary
economically eligible work keeps the configured transport rate/concurrency and
does not wait for another policy's sampling acknowledgement. The existing queue
bound, positive authenticated payout, capture budget, local validation, lifecycle,
catalog reset, and broadcast-journal guards still apply.

Only an actual helper `started` acknowledgement consumes a sampling turn;
dispatch, preparation, DNS, cancellation, or failure before that acknowledgement
do not. The helper may conservatively retain its acknowledged start counter if
a concurrent budget/endpoint invalidation vetoes TCP immediately after the ACK;
such a result never invents a capture, proof, or remote-quality observation.
Sampler state is bounded to 256 policies. Catalog cleanup or eviction may begin
a new sampling episode on re-entry, but never resets the global 250 ms deadline.
Real target-evaluable or validated observations determine promotion to ordinary economic work;
sampling does not inflate the smoothing base or any actual success counter.

The numeric buckets occupy 1,440 bytes per allocated history, plus metadata.
Native endpoint histories are allocated lazily and bounded to 8,192 histories
across the helper, with least-recently-observed eviction. Eviction discards only
performance history, not endpoint rotation credit or validation state. Domain
histories are retained only for relevant catalog/active/pending-proof policies.
The catalog is capped at 100,000 bounties; 100,000 distinct observed policies
would use about 137 MiB of domain bucket payload, plus object overhead and
active/pending work retained separately. Ordinary use with a few domains is much
smaller. This storage depends on tracked policies, not connections per second.

Expiration never clears claims, saved transactions, successful-capture budgets,
terminal counters or the cumulative observation count. DNS refresh and temporary
unreachable-address exclusions retain their separate existing lifetimes. Process
restart and journal recovery behavior are unchanged; this is not a periodic
service restart or a blanket domain/IP reset.

Existing lifecycle cleanup still applies: a policy removed from the catalog
with no active/pending work, or an IP removed from DNS and later reintroduced,
can be a new observation context. The window does not introduce a permanent
database of every domain or address ever seen.

Offline bookkeeping benchmarks (no network or broadcasts):

```sh
node --expose-gc scripts/benchmark-performance-window.mjs
cmake --build tmp/native-build --config Release --target claimer-performance-bench
```

Run the resulting `claimer-performance-bench` executable from the build folder
(`Release/` on Visual Studio). It is not installed or packaged. These benchmarks
measure history bookkeeping and bounded allocation, not full TLS throughput;
the native wall-time estimate is not a production CPU measurement.

## Incremental bounty updates

After the initial bounded snapshot, the claimer requests
`getbountychanges` with `include_bounties: true`. A versioned delta carries the
complete changed bounty and its publication tip, not the other bounties from
its block. Cached rows are replaced only after validating the full payload,
immutable identity, canonical block, status, spender and pagination fences.
With a validated cached window the request also includes `known_tip` (height
and hash). A server advertising `block_deltas: 1` may return up to five new,
contiguous block hashes and their authoritative total P2C bounty counts in the
same indexed publication. Only an explicit zero count permits installing an
empty block without a stream; missing counts, unsupported extensions, gaps
and reorganizations never imply emptiness. For a positive count, fully validated
journal rows accumulate separately from the complete cache until every page is
drained and the number of distinct outpoints exactly matches that authoritative
all-output count (including spent, pending and immature outputs). Only then can
the new block be installed without downloading the same rows again. Partial or
unknown-count blocks still require a complete stream and subsequent journal
replay; streamed immutable identities must also agree with any candidates.
Ordinary status updates
to already loaded blocks do not reread them. Confirmation counts advance with
the published tip. Authoritative totals remain attached to the immutable local
window across pages and cycles: later rows and complete streams must agree
with them. Reorganizations discard displaced counts; journal resets discard
all count authority before rebuilding the catalog.

Compact version 3 (`compact: true`, `compact_version: 3`) omits empty/default
fields and binds tip references to this request's validated tip/cursor digest.
State-row confirmations can be derived from the event's historical publication
height and the digest-checked immutable block height. Explicit values are still
validated, never silently corrected. Reconstruction precedes the normal row,
sequence, canonical-chain and count checks. Unknown immutable references replay
the same cursor in expanded form before publication. Parameter rejection alone
negotiates version 3, then 2, then 1; the negotiated version is retained for the
current RPC connection epoch and reset on disconnect. No polling interval,
claim/proof counter, signature validation or durable journal format changes.

Journal gaps, reorganizations and inconsistent snapshots still trigger the
existing coherent resynchronization. Older servers fall back to block reads
without skipping their journal cursor: after negotiating compact versions and
representation, parameter rejection retries without `known_tip`, retaining
bounty deltas, then negotiates the legacy
schema if necessary. Malformed data and transport errors never negotiate
compatibility. Cached state is published atomically:
a failed page cannot consume its cursor or partially install updates.

## Shutdown, crash recovery and uncertain broadcasts

Before a broadcast, the application durably writes a version-3 public
`claimer.conf.state.json` journal containing the outpoint, transaction ID,
receiving address, status, **exact serialized claim transaction including its
public proof witness**, and a SHA-256 digest of those bytes. It never contains
seeds or private keys. Keep this file: it preserves winning proofs across lost
RPC replies and restarts. Verified winners waiting at clean shutdown are also
saved. The journal has explicit size/record limits and fails closed on storage
errors rather than silently dropping records. New capture preparations reserve
worst-case witness capacity in advance; when outstanding confirmations fill
that budget, new work waits while reconciliation can compact confirmed records.
If a competing mempool spend arrives while a verified winner is still waiting
for its first submission, the winner is transferred to this journal before its
queue entry is invalidated. No transmission is permitted while that spend is
pending. The original in-memory proof stays owned until the atomic write
succeeds, including during storage-failure shutdown.

A `pending` (saved without a recorded accepted outcome) or `unknown` (possibly
sent without a conclusive reply) record reserves **only that outpoint**;
unrelated claims can continue. Neither status proves that no transmission took
place. A definite node policy rejection also retains the original winning proof
in the journal as `pending`; a later pending-spend/catalog change cannot discard
it and force recapture. Recovery validates the saved bytes' digest, transaction
identity, input, receiving output and proof binding locally, then queries
`gettransactionstatus` for the saved ID. This indexed-only receipt contains
identity, pending/confirmed state, confirmation count and block location; it
does not download the raw transaction or witness. If it is absent from the index,
absence is **not** treated as rejection: the client may retransmit only the
**identical saved bytes**, after checking the digest, transaction ID, recipient
and proof structure/binding. It never creates a competing replacement claim.
The receiving node still applies its current full validation and fee policy.
Reconciliation is bounded, uses the normal RPC quotas and retries with delay.

Once acceptance is observed or acknowledged, the record becomes `accepted` but
retains its exact transaction/proof bytes: an ACK is not block confirmation.
Recovery checks the transaction using the same bounded RPC lane. If an accepted
transaction disappears and a coherent catalog reports its input available
again, only those identical bytes can be retransmitted. A signed claim that has
aged out of the bounded discovery window can also be replayed normally; an
explicit spent/unavailable row blocks replay for every saved status (including
previous rejections), but absence from that window is
not proof of a spent input. A replay never credits
another completed claim. Only validated block-confirmation metadata and the
matching transaction permit transition to `confirmed` and compacting the
saved bytes; the outpoint/ID reservation remains. Transaction IDs exclude the
witness, so a node-observed proof can differ from our saved proof while still
matching the same input, payout and challenge. The full node validates the
accepted proof; recovery rechecks our original saved proof, and never replaces
its bytes with a remotely observed witness. Work is checked against the bounty target while
that metadata remains available; the full node remains the consensus validator.
A later timeout, quota response or node rejection cannot release an
outpoint whose earlier broadcast is still uncertain. Invalid saved data or
malformed transaction identity still stops the service.

After an atomic journal replacement, subsequent writes always start from the
newly published state, even if the final POSIX directory flush fails. Such a
failure is still reported, not treated as a successful durable write. This
prevents a queued write from erasing the newly saved proof or downgrading an
accepted record; it does not guarantee persistence across power loss when the
storage system fails to flush.

Recovery reads the complete bounded journal through EOF before validating or
publishing any records. Short filesystem reads are continued; trailing corrupt
data, interrupted reads and growth beyond the 8 MiB limit remain errors and
never authorize replay from a partially read state.

Receipt metadata must bind to the saved transaction: its required reported
transaction ID must match exactly, and an unconfirmed receipt cannot
carry a block hash or nonzero confirmations. A confirmation at height zero must
match the network's pinned genesis, even when that block is outside the current
discovery window. Inconsistent replies never compact the saved proof or credit
a completed claim. Confirmation counts must agree with the indexed tip and
block height. Well-formed location conflicts retain the owner and retry through
normal bounded reconciliation instead of stopping the service; malformed
identity or field types still fail closed. Older RPC servers without the compact
method leave proofs reserved for retry; there is no full-transaction fallback
for confirmation polling. Full funding transactions are still fetched and
validated when preparing a claim, with the existing bounded shared cache.

Receipt reads are fenced against catalog resets, including while a confirmation
waits for durable storage. An old reply cannot compact a witness or authorize a
replay against a replacement catalog. After legitimate compaction, a complete
catalog may reopen a confirmed outpoint only when it is available again and its
confirming block is demonstrably orphaned. Merely aging outside the hash window
does not qualify; a lower tip proves rollback only after that confirmation was
previously anchored locally. The compact journal marker is removed atomically
before recapture is admitted. Original unconfirmed proofs are never removed by
this path. Bounded accounting metadata prevents crediting the same transaction
twice when its proof must be recaptured after compaction.

Within the current 600-block horizon, a funding transaction temporarily absent
after a reorganization retains only its selection factor and successful-capture
budget. Re-mining that same output does not restart its budget; old proposals
and proofs are not restored through this accounting history. History uses the
existing 100,000-factor bound and expires with the discovery horizon.

If the first durable write fails, the service halts without broadcasting but
retains an explicit in-memory owner of the verified winner. If shutdown cannot
save that proof, the CLI stays alive with claims stopped and the instance lock
held, warns that the proof is still only in memory, and retries persistence
every five seconds. This also covers fatal events and startup failures; repeated
stop signals share the same drain instead of forcing an unsafe exit. Restore
writable storage without terminating the process. After recovery it exits with
an error status, not a false success. This cannot protect against forced process
termination or power loss before any durable write succeeds.

Version-1 and version-2 journals remain readable. A legacy record without saved
transaction bytes cannot be authenticated or replayed by a compact receipt;
only that outpoint remains quarantined for review, with its reservation intact.
The client never downloads a replacement proof for that record. A saved claim for
a different receiving address is also quarantined, never redirected. Keep a
backup and check the transaction ID/outpoint through a trusted node before
resolving such a record. Never delete the whole journal or switch configuration
paths merely to bypass a reservation.

A normal exit removes `claimer.conf.lock`. An interrupted process can leave the
lock behind. Stop all instances and review any pending/unknown broadcasts before
manually removing that **lock file only**. Changing the config path to bypass
these protections risks duplicate work.

## Build from source

Requires Node.js **24.19.0 or newer within Node 24**, CMake **3.22+**, and a
C++20 compiler for the native build architecture. Unix archive builds require
`zip` and `unzip`.
Packaging targets: Windows x64, Linux x64, macOS arm64 and macOS x64. Each CI
job extracts and tests its native ZIP before uploading it, including executable
permissions. Windows builds require Visual Studio C++ build tools; Linux uses
GCC or Clang; macOS uses Xcode command-line tools. Python, Rust and a system
OpenSSL development package are not needed for the C++ helper.
The packaged Mach-O files are checked for native architecture, valid code
signatures and library references limited to the package or system libraries.

```sh
npm ci
npm test
npm run build:claims
npm run build -- --archive
npm run test:package
```

`build:claims` fetches SHA-256-pinned Mbed TLS sources, builds the C++ helper and
runs its offline CTest suite before installing it in `helpers/native-bin/`.
The network/validation workers have no Python interpreter or GIL. The existing
JavaScript controller retains RPC, priorities, transaction construction and
the durable submission journal. Set `CLAIMER_BUILD_JOBS` to limit build load.
`npm run setup:python-reference` separately prepares the historical Python
implementation for differential tests; normal execution never falls back to it.
`build` bundles the JS into a Node single executable application (SEA), includes
the helper and all of its runtime libraries, dependency licenses, and produces
`dist/` portable ZIP archives with SHA-256 manifests and archive checksums. No
installer is produced. The entire extracted folder is required, not just the
EXE. `test:package` verifies the ZIP checksum, extracts it, checks every packaged
file and tests first launch offline. An explicit ZIP path can be passed with
`npm run test:package -- /path/to/package.zip`. The source-only
`claimer.conf.example` is not included in release ZIPs.

For development: `npm start -- --init`, edit `claimer.conf`, then `npm start`.
Tests use fake workers or loopback servers; they do not claim real bounties or
broadcast to the public network. CI builds verified artifacts on pushes/PRs;
it **does not publish GitHub Releases automatically**.

## Attribution

MIT licensed. See [PROVENANCE.md](PROVENANCE.md),
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[native/PROVENANCE.md](native/PROVENANCE.md) and the historical
[helpers/PROVENANCE.md](helpers/PROVENANCE.md) for pinned upstream sources,
the root-bundle pin and retained license notices.
