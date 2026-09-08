# Development

Use the root Cargo workspace. `rust-toolchain.toml` selects the qualified
development compiler; `rust-version` describes the separately tested minimum
compiler. Node runs the browser contracts without a bundler or package install.

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
node scripts/test-browser.mjs
node apps/web/tests/deal-e2e.mjs
scripts/check-workspace.sh
```

Run the practice app with:

```sh
cargo run -p poker-relay -- 127.0.0.1:3000 deployments/mutinynet/client.json
```

Protocol developer tools:

```sh
cargo run -p deal-tools --bin deal-params
cargo run --release -p deal-tools --bin deal-benchmark
node tools/wasm-benchmark.mjs
```

The standalone browser diagnostic is served at `/tools/deal`; it is a developer
entry point separate from the default practice app. There is no playable native
CLI. Native storage, transport, and monitoring libraries remain reusable.

## Adding code

Rust package folders match their kebab-case package name; Rust modules use
snake_case. JS modules and Markdown subjects use kebab-case. Unit tests stay
beside their owner; integration scenarios and fixtures live in the owning
crate/application's `tests/` directory. Prefer specific modules over generic
`utils`, `common`, or catch-all `runtime` files.

Keep application state out of protocol crates. Add an on-chain browser module
when integrating actual graph transitions; do not extend practice state into an
implicit funded implementation. Distinguish canonical Alice/Bob identity roles
from local/opponent, transport seat, and button position.

Generated binaries and their manifest live in `apps/web/public/wasm/` and must be
published through the build script. Local databases/secrets stay outside source;