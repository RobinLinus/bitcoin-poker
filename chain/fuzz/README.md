# BP52-CHAIN fuzz targets

The standalone harness covers the externally supplied, bounded parsers in the
chain protocol:

- `chain_decode` checks canonical round trips for descriptors, betting and
  amount state, outcomes, logical transactions, edges, node records, and the
  graph/signature commit-open exchange. Canonically decoded logical
  transactions are also passed through the Bitcoin consensus reparser and
  duplicated-field/value checks;
- `witness_lamport_decode` checks runtime witnesses and every Lamport public
  wire object used across the signing boundary.

From the `chain/` directory:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-09-01 fuzz run chain_decode -- -max_len=1000000
cargo +nightly-2026-09-01 fuzz run witness_lamport_decode -- -max_len=8192
```

Generated corpora and crash artifacts are intentionally untracked. Preserve
and investigate every crash before clearing it.
