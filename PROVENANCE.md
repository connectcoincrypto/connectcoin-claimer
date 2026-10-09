# Source provenance

The initial client reuses MIT-licensed ConnectWallet v1.1.5 sources from
https://github.com/connectcoincrypto/connectcoin-connect-wallet at commit
`d215d177d683a8a26c09c1dd2b61a87840fa2bf5`.

Imported components: `src/core/claims*.mjs`, `claim-*.mjs`,
`connection-limits.mjs`, `diagnostics.mjs`, `rpc.mjs`, `bounty-discovery.mjs`,
the full `helpers/` source/test/license tree, and helper build/security scripts.
Related standalone scheduler, transport, lifecycle and telemetry regression
tests retain their original behavior. Wallet/UI/custody modules were not copied.

Local adaptations:

- Public-only address/transaction modules retain exact claim wire formats and
  funding checks, with golden vectors against desktop v1.1.5. No mnemonic,
  derivation, ordinary-payment signing or vault implementation is included.
- Mainnet-only identity/config adapter, CLI config/lock, orchestration and durable
  public broadcast journal are specific to this repository.
- Economic minimum is per instance, default 1000, threaded through scheduler,
  admission, recovery-probe and dispatch decisions; no mutable global policy.
- Native capture/verifier and TCP pacing retain desktop protocol 4 behavior.
- The RPC stream reader preserves only well-formed server `-32011` (expired
  bounty snapshot) and `-32001` (not ready) errors for rescan/retry. Malformed
  streams and other errors still fail closed; server text is not exposed.

The helper executable keeps its internal `connectwallet-claims` name so the
existing build, isolation, root verification and protocol tests remain aligned.
Its historical helper documentation refers to the original desktop integration.
See `helpers/PROVENANCE.md` for the underlying P2C Tools commit and security
patches. No other repository is modified by this project.
