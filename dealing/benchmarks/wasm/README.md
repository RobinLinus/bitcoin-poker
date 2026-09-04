# BP52 single-thread WebAssembly proof spike

This isolated spike compiles the production nine-slot hash-length circuit to
`wasm32-unknown-unknown` and measures it synchronously under Node. It exists to
answer whether today's Bulletproof implementation is suitable for a browser;
it is not a production browser package.

The default `benchmark-custom-rng` feature registers a deterministic,
cryptographically insecure entropy callback so the raw Wasm can run without
generated JavaScript glue. Never enable it in an application. The separate
`browser-entropy` feature enables `getrandom/js`, which is the minimum entropy
configuration for a real `wasm-bindgen` browser wrapper.

## Reproduce

Install the target, build the raw benchmark, and run it with Node:

```sh
rustup target add wasm32-unknown-unknown --toolchain 1.98.0
cargo +1.98.0 build --release --locked \
  --manifest-path dealing/benchmarks/wasm/Cargo.toml \
  --target wasm32-unknown-unknown
node dealing/benchmarks/wasm/run-node.mjs
```

Compile-check the real browser entropy path separately:

```sh
cargo +1.98.0 check --release --locked \
  --manifest-path dealing/benchmarks/wasm/Cargo.toml \
  --target wasm32-unknown-unknown \
  --no-default-features --features browser-entropy
```

The direct Wasm-only `clear_on_drop/no_cc` dependency intentionally
feature-unifies the pinned Bulletproof backend's atomic optimizer barrier. A
plain Rust Wasm target does not include a C compiler for its default barrier.

## Measured result

Measured 2026-09-02 on an Apple M5 Pro MacBook Pro with 24 GiB RAM, Rust
1.98.0, release LTO, and Node 24.19.0. Native and Wasm use the same fixed
fixture and exact 503,901-multiplier production circuit. Proof randomness comes
from the platform benchmark entropy source and is not byte-identical.

| Phase | Native Rayon | Native, one Rayon thread | Node, single-thread Wasm |
|---|---:|---:|---:|
| parameter setup | 5.303 s | 5.343 s | 10.286 s |
| proof generation | 9.518 s | 68.867 s | 225.499 s |
| proof verification | 3.613 s | 3.682 s | 10.302 s |

The raw release module was 641,869 bytes (185,908 bytes through gzip), before
`wasm-bindgen` glue or `wasm-opt`. The native Rayon run peaked at 1,077,182,464
resident bytes. Wasm linear memory grew as follows:

| Checkpoint | Wasm linear memory | Node RSS sample |
|---|---:|---:|
| after parameter setup | 161.25 MiB | 58.14 MiB |
| after proof generation | 941.19 MiB | 518.00 MiB |
| after verification | 1,389.25 MiB | 563.17 MiB |

Linear-memory size is a high-water mark rather than live heap usage: freed
allocations do not shrink `WebAssembly.Memory`. Even so, this proves that the
common 1 GiB shared-memory example limit is too small for the current sequence.

## Conclusion

Single-thread browser proving is a no-go for an interactive action. It must be
precomputed in a background worker after the session-bound transcript inputs
are known. The current Rayon calls can use browser threads through
[`wasm-bindgen-rayon`](https://github.com/RReverser/wasm-bindgen-rayon), but that
requires a separate threaded build, cross-origin isolation, a fixed nightly
toolchain with `build-std`, shared Wasm memory, and a declared maximum of at
least 2 GiB for the measured implementation. Keep a feature-detected
single-thread fallback, but treat it as slow background work.

The browser-facing package should run cryptography outside the UI thread and
should consider disposable prover and verifier workers. Terminating each worker
reclaims its Wasm high-water memory; keeping one module alive through both
operations retains the 1.39 GiB linear-memory allocation.

## Production integration notes

The Bulletproof fork already expresses its large MSMs and folds through Rayon.
After a browser wrapper re-exports and awaits `initThreadPool`, those calls can
use the adapter's global pool without changing the arithmetic code. Use a
dedicated crypto worker outside the UI thread and cap the pool initially (for
example, at eight workers); browser measurements are still required before
claiming any threaded speedup.

The threaded build is deliberately separate from the stable single-thread
build. At the time of this spike, `wasm-bindgen-rayon` 1.3 documents a pinned
nightly toolchain, `rust-src`, `wasm-pack --target web`, rebuilt `std`, and at
least these linker properties:

```text
-C target-feature=+atomics,+bulk-memory
-C link-arg=--shared-memory
-C link-arg=--max-memory=2147483648
-C link-arg=--import-memory
-C link-arg=--export=__wasm_init_tls
-C link-arg=--export=__tls_size
-C link-arg=--export=__tls_align
-C link-arg=--export=__tls_base
-Z build-std=panic_abort,std
```

The 2 GiB maximum above replaces the adapter documentation's common 1 GiB
example because this benchmark crossed 1 GiB. Shared memory requires a maximum
at link time. The web server must serve HTTPS and cross-origin isolation
headers, normally:

```text
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

All embedded third-party assets then need compatible CORS or
Cross-Origin-Resource-Policy headers. Ship a second non-threaded artifact and
select it through Wasm thread feature detection when `crossOriginIsolated` is
false.

`curve25519-dalek` 4.1 selects its serial 32-bit backend on `wasm32`; its SIMD
backend is x86-64-only, so merely enabling Wasm `simd128` does not accelerate
these Ristretto operations. The full `bp52-protocol` path also includes
`secp256k1-sys`: its bundled C supports Wasm, but the build machine needs a
Clang/LLVM installation with a WebAssembly target. The Apple system Clang used
for this spike lacked that target; this is a build-toolchain issue, separate
from the proof backend measured here.
