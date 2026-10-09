# Third-party notices

ConnectCoin Claimer is MIT-licensed; copyright 2026 ConnectCoin contributors.
It contains MIT-licensed components adapted from ConnectWallet v1.1.5 and
ConnectCoin P2C Tools. Original licenses are retained in `LICENSE` and
`helpers/vendor/LICENSE.connectcoin-p2c-tools`.

Runtime JavaScript dependencies include `@noble/curves`, its `@noble/hashes`
dependency, and `@scure/base` (MIT). Portable builds include the complete Node.js
runtime and its dependency license notices. Build tools esbuild and postject
are used to create the executable; their packages are development dependencies.

The Python helper bundles CPython, cryptography, OpenSSL, cffi and their required
runtime components. `helpers/collect_licenses.py` collects original licenses and
an SBOM from the installed, pinned runtime/build dependencies. Portable builds
include these under the helper's `_internal/licenses/dependencies` directory,
plus JavaScript and Node licenses under `licenses/`.

`helpers/p2c_roots_v1.pem` is an immutable Mozilla-derived ConnectCoin consensus
root bundle. Its original attribution is retained in the file header. It is not
replaced by the machine's system trust store. See `helpers/PROVENANCE.md` for its
SHA-256 and upstream source.
