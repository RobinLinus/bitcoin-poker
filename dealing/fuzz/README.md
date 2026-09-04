# BP52 fuzz targets

These targets cover the parser and state-schedule surfaces required by
BP52-DEAL-v1 section 25.5:

- `wire_decode`: all top-level wire objects, typed payloads, length prefixes,
  Ristretto points/scalars, and contribution ciphertexts;
- `proof_parse`: all manual Sigma proof parsers plus the canonical Bulletproof
  parser and exact-size gates;
- `state_schedule`: arbitrary schedule indices, first-blinder selection,
  every header rejection branch, all 16 transcript transitions, and replay
  rejection without cursor mutation.

Install the pinned driver and run a target with nightly Rust:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly fuzz run wire_decode
cargo +nightly fuzz run proof_parse -- -max_len=25000
cargo +nightly fuzz run state_schedule
```

Build all harnesses without running them with `cargo +nightly fuzz build`.
Generated corpora and crash artifacts are intentionally ignored; preserve and
triage every crash before clearing it. The scheduled GitHub workflow pins both
the nightly toolchain and cargo-fuzz, gives each target a bounded smoke-test
campaign, and uploads any crash artifact.
