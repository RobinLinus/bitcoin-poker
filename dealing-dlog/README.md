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
- the exact candidate tapscript leaf plus nine hard regtest-only Taproot gates;
- the exact authenticated 16-envelope live state machine, durable-send
  boundary, idempotent retransmission, collision retries, certificate export,
  and full certificate replay verification;
- balanced 103-leaf gate trees, control blocks, gate-spend BIP341 sighashes,
  and canonical witness assembly; and
- a no-import browser Wasm module and two-Worker browser E2E harness.

Deliberate limits:

- DLOG52 defines dealing and the nine card-gate outputs. It does not define a
  complete Bitcoin poker settlement transaction graph, and this implementation
  does not claim or synthesize one.
- The HTTP relay stores opaque bytes but is not an authenticated confidential
  peer channel. The browser demo passes selective openings locally between its
  two Workers; remote private hole-card delivery remains gated on a separately
  reviewed end-to-end channel.
- The real Bitcoin Core regtest integration remains environment-gated. Native
  tests construct the actual BIP341 sighash, signatures, witness, and verify
  the Taproot control commitment; the repository-wide Core test is ignored
  unless an isolated node is provided.
- Fuzz targets, independent implementation vectors, a security audit, and
  physical-device benchmarks remain future hardening work.

Run the current checks with an installed stable toolchain:

```sh
cargo +stable test --workspace --offline
cargo +stable fmt --all -- --check
cargo +stable run --offline -p dlog52-cli
cargo +stable build --release --target wasm32-unknown-unknown -p dlog52-wasm
node wasm-benchmark.mjs
```

The relay-server exposes the actual browser harness at `/dlog52`. It runs two
secret-owning Workers, replays the common 102,070-byte setup certificate,
checks all nine gate manifests, and plays a complete fixed-limit demonstration
through showdown. Build/publish all browser artifacts, including
`/wasm/dlog52.wasm`, with `client/scripts/build-browser-wasm.sh`.

The repository pins the intended MSRV in `rust-toolchain.toml`; `+stable` is
only used above for hosts where that exact toolchain is not already installed.
