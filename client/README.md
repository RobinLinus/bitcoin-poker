# Dlog browser client

The relay serves the dlog practice table through `bootstrap.js`. The old funded
application and hash-based proof workers/Wasm have been removed. Wallet, origin,
transaction inspection, relay, and backend-neutral ports remain for integration.
Funded dlog browser play is not yet connected to the native settlement graph.

```sh
cargo run -p bp52-relay-server
cargo test --workspace --locked
node scripts/test-browser.mjs
```

See [MVP status](docs/DLOG_ONCHAIN_IMPLEMENTATION.md),
[Wasm build](docs/browser-wasm-build.md), and [testing](TESTING.md).
