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
  payout after fee, and the domain/signature-policy success/time EMA.
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
  eligible bounty. Keeps domain EMA, endpoint rotation and successful-connection
  budgets from the desktop engine.
- Captures through **CertificateVerify**, without waiting for Finished, while
  still verifying certificate path, domain, signature policy, proof binding and
  target before accepting a winning proof. Uses the pinned consensus roots.
- Restricts TLS endpoints to public IPs on port 443; does not send HTTP requests.
- Immediately excludes an endpoint after an explicit OS no-route/network-down
  error, rather than repeatedly selecting it through the normal success EMA.
  Only an unsupported socket family excludes that entire IP family. Exclusions
  last 60 seconds, span domains/signature policies and survive DNS refreshes;
  queued attempts check them again before TCP starts. All-excluded domains use
  the existing bounded DNS retry while waiting for connectivity to recover.
  Timeouts, connection refusal, TLS/certificate errors and local resource
  exhaustion do not declare an address family unsupported. Validation is unchanged.
- Discovers up to 600 recent blocks with at most four parallel block reads;
  stages coherent snapshots and replays the bounty journal. Healthy polling
  reuses the cursor and block cache rather than redownloading every block.
- A catalog resync keeps the same helper, validated captures, successful-work
  budgets and verified proofs. New preparations and broadcasts wait until the
  complete replacement snapshot and journal replay are published atomically;
  a final pre-write check also fences broadcasts queued behind RPC quotas.
  Known spent/reorganized outpoints are cancelled individually. Normal window
  aging does not discard already-started captures or their verified winners.
- Preparation is limited to four concurrent jobs. Parked candidates become
  eligible again whenever preparation capacity is available, through the same
  priority scheduler and retry deadlines. Removing or aging out an awakened
  candidate cannot strand the remaining queue.
- Uses one RPC connection, polling every five seconds, with conservative client
  quotas: 48 ordinary calls/minute/method, eight calls/minute/block for bounty
  streams, at most four normal submissions in flight, and one serial recovery
  operation (which can retransmit one saved claim). Recovery shares the same
  RPC quotas and twelve-request global capacity. These are separate from the
  TCP/TLS connection settings. Server limits/cooldowns are also respected;
  other clients sharing your IP consume the same server quotas.
- Disconnects pause the workers; discovery catches up before resuming. Invalid
  chain identity, malformed snapshots and fatal helper errors stop the client.

Terminal output reports TCP connection attempts, active started connections, valid and
failed observations, targets reached and accepted submissions. The recent rate
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

## Shutdown, crash recovery and uncertain broadcasts

Before a broadcast, the application durably writes a version-2 public
`claimer.conf.state.json` journal containing the outpoint, transaction ID,
receiving address, status, **exact serialized claim transaction including its
public proof witness**, and a SHA-256 digest of those bytes. It never contains
seeds or private keys. Keep this file: it preserves winning proofs across lost
RPC replies and restarts. Verified winners waiting at clean shutdown are also
saved. The journal has explicit size/record limits and fails closed on storage
errors rather than silently dropping records.

A `pending` (saved without a recorded accepted outcome) or `unknown` (possibly
sent without a conclusive reply) record reserves **only that outpoint**;
unrelated claims can continue. Neither status proves that no transmission took
place. Recovery first queries
`gettransaction` for the saved ID and validates returned transaction identity,
input, receiving output and proof binding. If it is absent from the index,
absence is **not** treated as rejection: the client may retransmit only the
**identical saved bytes**, after checking the digest, transaction ID, recipient
and proof structure/binding. It never creates a competing replacement claim.
The receiving node still applies its current full validation and fee policy.
Reconciliation is bounded, uses the normal RPC quotas and retries with delay.

Once acceptance is observed or acknowledged, the record becomes `accepted` and
its transaction/proof bytes are removed; the compact outpoint/ID reservation
remains. A later timeout, quota response or node rejection cannot release an
outpoint whose earlier broadcast is still uncertain. Invalid saved data or
malformed transaction identity still stops the service.

Version-1 journals remain readable. A legacy unresolved record without saved
transaction bytes can be recognized by an RPC lookup, but cannot be replayed
if absent; only that outpoint remains quarantined for review. A saved claim for
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
