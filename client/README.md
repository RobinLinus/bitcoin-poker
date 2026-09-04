# BP52 web client

This workspace contains prototype application infrastructure for Bitcoin
Poker. It depends on the deterministic `dealing/` and `chain/` workspaces,
while those workspaces do not depend on this one.

The boundary is deliberately event-oriented:

- protocol code receives raw Bitcoin transactions, outpoint observations, and
  block references;
- the chain runtime, rather than an adapter, validates protocol transitions;
- adapters only fetch chain data or submit already validated transactions;
- funding wallets and live signers are separate capabilities;
- session persistence is accessed through a backend-neutral store interface.

The checked-in prototype deployment targets Mutinynet's public Esplora API.
Mutinynet is data in `deployments/mutinynet/client.json`, not an adapter or game
implementation: the same generic Esplora adapter is constructed from a
Rust-validated deployment. Esplora is a trusted observation boundary: the
remote service can omit, delay, or equivocate about observations. The
deployment derives its exact network identifier from the complete custom-Signet
challenge and pins a checkpoint to reject default Signet or another custom
signet.

Mainnet transaction submission remains disabled. Backend-neutral ports make a
future read-only profile for `https://blockstream.info/api` structurally
possible, but they do not authorize mainnet publishing or satisfy any
production-readiness gate.

The standalone native application lives in the sibling
[`client-cli/`](../client-cli/) workspace. The two applications share only the
backend-neutral ports and protocol reducers that both need; native transport,
wallet, persistence, and executable code are kept out of this workspace.

The checked-in game profile is deliberately singular: each player deposits
₿27,000, receives a ₿20,000 stack, and plays ₿100/₿200 fixed-limit blinds. This
is exactly 100 big blinds. Once both deposits are confirmed, origin creation,
the private deal, graph authorization, and activation proceed automatically.
The table presents stacks, pot, blinds, funding progress, and the current poker
decision; protocol progress and diagnostics stay out of player-facing copy.

## Workspace

```text
crates/bp52-client-ports       backend-neutral capabilities and observations
crates/bp52-game-session       I/O-free DEAL/CHAIN session reducer and journal
crates/bp52-origin             backend-neutral origin/refund transaction policy
crates/bp52-browser-wallet-wasm isolated staging-key signer and descriptor code
crates/bp52-browser-origin-wasm isolated origin/refund transaction builder
crates/bp52-browser-deal-wasm  private dealing worker engine
crates/bp52-browser-game-wasm  raw Wasm bridge for the public session reducer
crates/bp52-browser-chain-wasm private graph/signing/runtime worker engine
crates/bp52-browser-transaction-wasm rust-bitcoin transaction inspection bridge
crates/bp52-relay-server       opaque capability-authenticated room relay + web UI
deployments/mutinynet          Mutinynet deployment notes
```

The Wasm crates are separate on purpose: DEAL secrets, chain/signing secrets,
the public reducer, and transaction inspection have different lifetimes and
trust boundaries. They are not backend-specific implementations. Large crates
are split into internal modules where doing so preserves those boundaries; the
crate boundary itself is not used as a substitute for source organization.

Rust Serde owns operator configuration plus every browser control and public
view object. Bytes that are signed, hashed, relayed, journaled, or interpreted
by Bitcoin continue to use strict canonical Rust codecs; JSON object
serialization is deliberately not a consensus format. JavaScript performs
bounded copies and transports those artifacts opaquely while handling HTTP,
persistence, and presentation.

Run the local relay and open `http://127.0.0.1:3000`:

```sh
cargo run --locked -p bp52-relay-server -- \
  ./bp52-relay.sqlite3 127.0.0.1:3000 \
  deployments/mutinynet/client.json
```

The deployment path is required: the relay has no network-specific production
default. It exposes that single Rust-validated deployment to every new table.

The browser/Worker boundary, current limitations, and exact single-thread Wasm
proof measurements are recorded in [`docs/browser-prototype.md`](docs/browser-prototype.md).
The dedicated real-protocol DEAL Worker, opaque artifact API, static artifact
routes, coordinator handoff, and sealed private-state format are documented in
[`browser/deal/README.md`](browser/deal/README.md).
The public game reducer, strict Serde control/view boundary,
source-provenance gate, and Worker replay API are documented in
[`browser/game/README.md`](browser/game/README.md).

Run the normal checks from this directory:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --no-deps --locked -- -D warnings
cargo doc --workspace --no-deps --locked
node scripts/test-browser.mjs
```

The layered test strategy, fixture rules, and deliberately separate expensive
qualification suites are summarized in [`TESTING.md`](TESTING.md).

Build and validate all browser Wasm modules with the digest-pinned
rustc/LLVM and clang toolchain:

```sh
./scripts/build-browser-wasm.sh
./scripts/build-browser-wasm.sh --check
```

The exact artifacts, isolated security boundaries, raw static-file layout,
and local-build requirements are documented in
[`docs/browser-wasm-build.md`](docs/browser-wasm-build.md).

This is research software. The Mutinynet adapter is a diagnostic prototype,
not a production deployment. Do not use it with mainnet or real funds.
