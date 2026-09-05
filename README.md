# Bitcoin Poker

Private dealing and on-chain poker settlement, with a browser practice table.

- `crates/dealer-*`: the cryptographic dealing protocol, selective openings, card signatures, and Wasm bindings.
- `crates/poker-*`: poker evaluation, the full settlement graph, Bitcoin scripts, funding utilities, and client adapters.
- `apps/relay`: the opaque message relay and static asset server.
- `apps/web`: the browser application; its current mode is practice play.
- `tools`: protocol diagnostics and benchmarks.

The native on-chain backbone is implemented and qualified against Bitcoin Core.
Funded browser integration, durable game recovery, and MutinyNet deployment are
still pending. Cooperative play is a later optimization of on-chain settlement.

```sh
cargo test --workspace --locked
node scripts/test-browser.mjs
cargo run -p poker-relay -- /tmp/poker.sqlite 127.0.0.1:3000 deployments/mutinynet/client.json
```

Open `http://127.0.0.1:3000` for the practice table. The deployment config names
the diagnostic network; it does not enable funded play or broadcasting.

Start with [development](docs/development.md), [architecture](docs/architecture.md),
[testing](docs/testing.md), and [current status](docs/status.md).
The [roadmap](docs/roadmap.md) tracks the on-chain MVP. See [security](SECURITY.md)
for the project's experimental scope.
