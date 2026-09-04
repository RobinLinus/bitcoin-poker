# DLOG52-DEAL-v1 research implementation

This directory contains a from-scratch Rust implementation of the algebraic
dealing design in `DLOG52-DEAL-v1-implementation-spec.md`. It is research code,
has not been audited, and must not be used with real funds.

Implemented:

- strict primitive codec and tagged/rejection-sampled transcript hashes;
- the fixed RFC 9380 secp256k1 message generator and parameter manifest;
- Pedersen contributions, threshold ElGamal ciphertexts, candidate keys, and
  exhaustive card arithmetic;
- key possession, exact 108-record `Range52-BitOR-v1`, and nine-record
  encryption-link proofs;
- 927-key catalogue screening, 108 uniqueness ciphertexts, both exact scale
  rounds, batched partial-decryption proofs, and collision recovery;
- typed bundle generation/verification and secret zeroization boundaries;
- verified opening/card-key derivation and BIP340 signing;
- the exact candidate tapscript leaf plus a hard regtest-only gate.

Not yet implemented, and therefore deliberately not represented as complete:

- the 16-envelope persistent state machine and full certificate replay parser;
- BIP341 tree/control-block/transaction construction and Bitcoin Core tests;
- the browser/WASM worker, confidential reveal transport, fuzz targets,
  independent implementation vectors, and physical-device benchmarks.

Run the current checks with an installed stable toolchain:

```sh
cargo +stable test --workspace --offline
cargo +stable fmt --all -- --check
cargo +stable run --offline -p dlog52-cli
cargo +stable build --release --target wasm32-unknown-unknown -p dlog52-wasm
node wasm-benchmark.mjs
```

The repository pins the intended MSRV in `rust-toolchain.toml`; `+stable` is
only used above for hosts where that exact toolchain is not already installed.
