# Testing

## Native and browser

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --no-deps --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
node scripts/test-browser.mjs
node apps/web/tests/deal-e2e.mjs
```

The native suite includes protocol acceptance, canonical encodings, complete
reference topology/accounting, funding/refund signatures, and backend contracts.
The browser suite covers modules, workers, Wasm loading, and practice move logs.
The real Wasm scenario runs two dealer participants through setup and showdown.
Relay integration tests check asset imports, schema-3 practice config, opaque
message behavior, and the removal of legacy assets.

## Qualified Wasm artifacts

```sh
scripts/build-browser-wasm.sh --docker
scripts/build-browser-wasm.sh --check
```

The pinned Docker toolchain builds each binding independently. Dealer Wasm keeps
its 8 MiB stack setting. Avoid workspace-wide Wasm builds: host/network features
must not leak into secret-owning browser modules. `--validate-only` checks built
artifacts without publishing. Export, import, size, and hash contracts are defined
in `toolchains/browser-wasm-artifacts.json`.

## Bitcoin Core

```sh
scripts/bitcoin-core-regtest.sh --docker --suite all --require
```

The runner uses a cached pinned Core image and an isolated standard-policy regtest
node, then cleans it up. `--native` uses locally installed Core. The complete suite
covers card gates, reusable reveals, score/payout branches, prepared short-stack
settlement, recovery, and CSV timeouts. `--suite dlog-graph` runs only the complete
hand campaign; `dlog` is an algorithm label, not a package prefix.

## Source archives

`scripts/check-workspace.sh` checks the locked dependency graph. Run
`scripts/check-source-archive.sh` after committing to verify that HEAD contains a
complete source distribution. These checks do not substitute for compilation.
