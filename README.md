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

1. Extract the **whole** archive into a writable folder. Keep `claimer.exe`
   (Windows) or `claimer` (Linux) together with its `helpers` directory.
2. Run `claimer.exe` / `./claimer`. If `claimer.conf` is missing, the program
   creates it beside the executable and exits without connecting.
3. Set `receiving_address` to **your own mainnet `cc1p...` address**.
4. Optionally run `claimer.exe --check` (or `./claimer --check`). This validates
   the configuration and helper availability offline, without making claims.
5. Run the program again. With a valid configuration it starts automatically.
   Use **Ctrl+C** for a clean shutdown. Do not run another instance with the same
   configuration file.

You do not need Node.js, Python, Electron, or ConnectCoin Core installed to use
the portable package. Windows binaries are currently unsigned. The Linux x64
CI package is built on Ubuntu 22.04 and requires a compatible glibc-based OS;
it is not an Alpine/musl package. macOS packaging is not included yet.

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
- Discovers up to 600 recent blocks with at most four parallel block reads;
  stages coherent snapshots and replays the bounty journal. Healthy polling
  reuses the cursor and block cache rather than redownloading every block.
- Uses one RPC connection, polling every five seconds, with conservative client
  quotas: 48 ordinary calls/minute/method, eight calls/minute/block for bounty
  streams, and at most four submissions in flight. These are separate from the
  TCP/TLS connection settings. Server limits/cooldowns are also respected;
  other clients sharing your IP consume the same server quotas.
- Disconnects pause the workers; discovery catches up before resuming. Invalid
  chain identity, malformed snapshots and fatal helper errors stop the client.

Terminal output reports real TCP starts, active started connections, valid and
failed observations, targets reached and accepted submissions. The recent rate
uses a bounded ten-second window. `accepted` means the RPC acknowledged the
transaction, **not** that it is confirmed in a block. Duplicate winning proofs
for the same bounty are not submitted concurrently.

This light client relies on its configured RPC for chain state, availability
and relay; validating a proof locally is not independent full-node validation.
The service is plaintext, so use an endpoint/network you trust. Claims consume
bandwidth and CPU; a configured rate does not guarantee earnings.

## Shutdown, crash recovery and uncertain broadcasts

The application writes a public `claimer.conf.state.json` journal before each
broadcast. It contains only outpoints, transaction IDs, receiving addresses and
statuses, never seeds, private keys or raw proof witnesses. Accepted outpoints
remain reserved. The journal has explicit resource limits rather than silently
discarding pending records.

If a connection is lost during submission, the transaction may already have
been accepted. The claimer stops and records an uncertain result instead of
blindly generating another claim. On startup, a `pending` or `unknown` record
also requires operator review. Keep a backup of this file, check the transaction
ID and outpoint through a trusted node/explorer, and only then resolve that
record: mark it `accepted` if the transaction was accepted, or remove that
specific record if you have established no broadcast remains and the bounty is
available. Do not delete the entire journal to bypass a warning.

A normal exit removes `claimer.conf.lock`. An interrupted process can leave the
lock behind. Stop all instances and review any pending/unknown broadcasts before
manually removing that **lock file only**. Changing the config path to bypass
these protections risks duplicate work.

## Build from source

Requires Node.js **24.19.0 or newer within Node 24**, Python **3.11+**, and the
native build architecture. Packaging targets: Windows x64 and Linux x64; each
CI job tests its native artifact before uploading it.

```sh
npm ci
npm test
npm run build:claims
npm run build -- --archive
npm run test:package
```

`build:claims` installs pinned dependencies in a repository-local `.claims-venv`,
runs the Python/loopback tests, and builds the native helper. Set `PYTHON` to an
explicit Python executable if needed. It does not alter global Python packages.
`build` bundles the JS into a Node single executable application (SEA), includes
the helper and dependency licenses, and produces `dist/` portable archives with
SHA-256 manifests. The entire extracted folder is required, not just the EXE.

For development: `npm start -- --init`, edit `claimer.conf`, then `npm start`.
Tests use fake workers or loopback servers; they do not claim real bounties or
broadcast to the public network. CI builds verified artifacts on pushes/PRs;
it **does not publish GitHub Releases automatically**.

## Attribution

MIT licensed. See [PROVENANCE.md](PROVENANCE.md),
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[helpers/PROVENANCE.md](helpers/PROVENANCE.md) for pinned upstream sources,
the root-bundle pin and retained license notices.
