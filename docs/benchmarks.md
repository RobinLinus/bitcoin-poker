# Native benchmark — 2026-09-04

Research measurements only. These are not browser/WASM or networked end-to-end
results.

- Hardware: Apple M5 Pro MacBook Pro, 15 cores, 24 GB RAM
- OS: macOS 26.6.1 arm64
- Build: optimized Rust `release` profile, `k256 0.13.4`
- RNG: deterministic ChaCha20 benchmark fixture (not production entropy)

| Operation | Samples | Median | p95 | Wire bytes |
|---|---:|---:|---:|---:|
| Range prove | 20 | 26.768 ms | 27.163 ms | 13,964 |
| Range verify | 100 | 13.548 ms | 13.971 ms | — |
| Link prove | 50 | 1.562 ms | 1.598 ms | 1,755 |
| Link verify | 100 | 2.166 ms | 2.215 ms | — |
| Scale prove, 108 tests | 20 | 35.434 ms | 35.837 ms | 24,840 |
| Scale verify, 108 tests | 50 | 17.783 ms | 17.976 ms | — |
| Partial decrypt prove, 108 tests | 50 | 6.506 ms | 6.581 ms | 7,193 |
| Partial decrypt verify, 108 tests | 50 | 6.587 ms | 6.851 ms | — |

The current range and scale constructors defensively verify the generated proof
before returning, so their reported "prove" latency includes that self-check.
The link and partial-decryption constructors do not include a verifier pass.

Run with:

```sh
cargo +stable run --release --offline -p deal-tools --bin deal-params --bin benchmark
```

Format-derived aggregate sizes from the protocol specification:

- player bundle: 16,611 bytes;
- successful setup certificate: 102,070 bytes;
- all 16 authenticated envelopes for a successful attempt: 100,924 bytes;
- expected traffic through acceptance with honest collision retries: about 210 kB.

## WebAssembly / Node V8

Measured on the same machine with Node.js 24.19.0, using an optimized
`wasm32-unknown-unknown` build executed by V8's WebAssembly engine. Each table
sample is a batched run divided by its iteration count; five samples were
collected after warmup.

| Operation | Median | p95 | WASM/native median |
|---|---:|---:|---:|
| Range prove | 87.020 ms | 90.219 ms | 3.25x |
| Range verify | 42.732 ms | 45.221 ms | 3.15x |
| Link prove | 4.554 ms | 4.571 ms | 2.92x |
| Link verify | 6.496 ms | 6.596 ms | 3.00x |
| Scale prove, 108 tests | 109.844 ms | 111.256 ms | 3.10x |
| Scale verify, 108 tests | 55.814 ms | 56.898 ms | 3.14x |
| Partial decrypt prove, 108 tests | 19.951 ms | 20.006 ms | 3.07x |
| Partial decrypt verify, 108 tests | 19.698 ms | 19.927 ms | 2.99x |

Artifact:

- raw size: 626,813 bytes;
- gzip size: 150,983 bytes;
- SHA-256: `e254da6a5faa31d3ae8bc7b91bf0065bb917eb11c98825a625ce6675bd8fdb1a`.

Build and execute:

```sh
cargo +stable build --release --target wasm32-unknown-unknown -p dealer-wasm
node tools/wasm-benchmark.mjs
```

This measures V8 on desktop, not a browser Worker or physical phone. It omits
message encoding, certificate replay, persistence, network latency, and the
not-yet-implemented complete state machine. Summing the measured cryptographic
phases gives roughly 0.35 seconds of local CPU work per client per successful
attempt, but that is an estimate rather than an end-to-end measurement.
