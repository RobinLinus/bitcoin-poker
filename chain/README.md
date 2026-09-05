# Dlog poker settlement

This workspace implements the full finite poker graph and its dlog Bitcoin
transactions: betting, selective reveals, folds, unilateral timeouts, showdown,
and payout. The shared poker evaluator, Lamport score certificates, binary codec,
and Bitcoin helpers remain. Hash-based dealing and its runtime/CLI are removed.

See [implementation status](../client/docs/DLOG_ONCHAIN_IMPLEMENTATION.md) for
integration instructions and limitations.

```sh
cargo test --workspace --locked
scripts/bitcoin-core-regtest.sh --docker --suite dlog --require
```
