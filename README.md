# Bitcoin Poker

Private poker using dlog dealing and a finite Bitcoin settlement graph.
The hash-based dealing implementation and its applications have been removed.

- [`dealing-dlog/`](dealing-dlog/) implements private dealing, selective openings, and card signatures.
- [`chain/`](chain/) implements the full poker graph, transaction preparation, on-chain reveals, showdown, and timeout settlement. It also owns the shared binary codec.
- [`client/`](client/) contains the dlog practice table, relay, and reusable wallet/origin infrastructure.
- [`client-cli/`](client-cli/) contains reusable native storage, transport, and Esplora libraries; there is currently no playable CLI executable.

The native dlog on-chain backbone is implemented. Funded browser integration,
durable game recovery, and MutinyNet deployment remain unfinished. See the
[implementation status](client/docs/DLOG_ONCHAIN_IMPLEMENTATION.md) and
[MVP plan](client/docs/DLOG_MUTINYNET_MVP_PLAN.md).

Run `cargo test --workspace --locked` from each workspace, and
`node client/scripts/test-browser.mjs` from the repository root.
Run `chain/scripts/bitcoin-core-regtest.sh --docker --suite dlog --require`
for isolated Bitcoin Core qualification using a cached Core image.

Keep all four workspaces together: they share path dependencies.
`scripts/check-source-integrity.sh` verifies the locked dependency graphs;
`--archive-smoke` checks the committed HEAD archive instead of local edits.

This is experimental test-network software. See [SECURITY.md](SECURITY.md).
