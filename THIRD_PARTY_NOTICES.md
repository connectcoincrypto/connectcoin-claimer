# Third-party notices

ConnectCoin Claimer is MIT-licensed; copyright 2026 ConnectCoin contributors.
It contains MIT-licensed components adapted from ConnectWallet v1.1.5 and
ConnectCoin P2C Tools. Original licenses are retained in `LICENSE` and
`helpers/vendor/LICENSE.connectcoin-p2c-tools`.

Runtime JavaScript dependencies include `@noble/curves`, its `@noble/hashes`
dependency, and `@scure/base` (MIT). Portable builds include the complete Node.js
runtime and its dependency license notices. Build tools esbuild and postject
are used to create the executable; their packages are development dependencies.

The C++ helper includes MIT-licensed Core adapters and UniValue, plus statically
linked Mbed TLS 3.6.7 (Apache-2.0 and its retained third-party notices). Native
dependency licenses are shipped beside the helper under `licenses/`; JavaScript
and Node licenses are in the package's top-level `licenses/` directory. See
`native/PROVENANCE.md` for source revisions and archive hashes.

The historical Python helper is retained as test-reference source only. Its
CPython/cryptography/OpenSSL/cffi dependencies are not part of native packages.

`helpers/p2c_roots_v1.pem` is an immutable Mozilla-derived ConnectCoin consensus
root bundle. Its original attribution is retained in the file header. It is not
replaced by the machine's system trust store. See `helpers/PROVENANCE.md` for its
SHA-256 and upstream source.
