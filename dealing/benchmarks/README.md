# BP52 performance harness

This stable-Rust harness exposes every measurement required by
BP52-DEAL-v1 section 26. Build and run one scenario at a time so expensive
Bulletproof setup does not contaminate the lightweight Sigma measurements:

```sh
cargo run --release --manifest-path benchmarks/Cargo.toml -- hash-length
cargo run --release --manifest-path benchmarks/Cargo.toml -- encryption-link
cargo run --release --manifest-path benchmarks/Cargo.toml -- uniqueness
cargo run --release --manifest-path benchmarks/Cargo.toml -- bandwidth
cargo run --release --manifest-path benchmarks/Cargo.toml -- attempt
```

`hash-length` reports nine-slot Bulletproof setup, generation, verification,
and proof size. `encryption-link` reports nine-slot generation and verification.
`uniqueness` reports generation and verification for both 108-test blinding
rounds and both partial-decryption batches. `bandwidth` reports the exact fixed
16-envelope and accepted-certificate byte counts.

`attempt` constructs a valid accepted deal at the exact `T4`, `T6`, `T10`,
`T11`, and `T12` proof roots. Its live total includes fixed-parameter setup,
fresh threshold keys, two key proofs, both player bundles and their
verification, both uniqueness rounds and partial decryptions, every
commit/open digest, all 16 envelope encodes/signatures/verifications/hash-chain
steps, and both accepted-deal signatures. It then reports a separately timed
production archive/state-machine replay; the final combined line includes this
independent observer replay and therefore intentionally repeats verification
work. Neither line includes transport latency.

The accepted fixture fixes only the 18 benchmark witness values so the nine
resulting cards are guaranteed distinct. Preimages, threshold keys, proof
randomizers, commitment blindings, envelope auxiliary randomness, and all
other cryptographic randomness still come from the operating system RNG. The
fixture is benchmark instrumentation, not an application deal-generation API.

Peak resident memory must be measured by the operating system so allocator and
backend storage are included. Use one of:

```sh
/usr/bin/time -v cargo run --release --manifest-path benchmarks/Cargo.toml -- hash-length
/usr/bin/time -l cargo run --release --manifest-path benchmarks/Cargo.toml -- hash-length
```

The first form is for GNU `time` (Linux), the second for macOS. Record the
commit, target triple, CPU, RAM, toolchain, optimization profile, and at least
five samples with any published result. Never change circuit shape, nonce
sampling, scalar independence, or canonical decoding to improve a score.

The [`wasm`](wasm/README.md) subdirectory contains a reproducible
single-thread `wasm32-unknown-unknown` spike for the same production
hash-length circuit. Its default deterministic entropy source is benchmark-only
and must never be used by an application.
