# Browser WebAssembly build

All six browser modules are ordinary `wasm32-unknown-unknown` Rust `cdylib`
artifacts. Rust is compiled by rustc 1.98.0 and its LLVM WebAssembly backend;
the small C dependency used by `rust-secp256k1` is cross-compiled by clang 14.
No JavaScript transaction implementation, source rewriting, fake Wasm wrapper,
or `wasm-bindgen` post-processing participates in this build.

The modules intentionally remain separate security boundaries:

| Artifact | Boundary |
| --- | --- |
| `wallet.wasm` | disposable local staging signer |
| `origin.wasm` | deterministic origin transaction builder |
| `deal.wasm` | secret-owning DEAL Worker |
| `game.wasm` | public game-session reducer |
| `chain.wasm` | secret-owning CHAIN Worker |
| `transaction.wasm` | read-only rust-bitcoin transaction inspector |

## Qualified build

From `client/`, run:

```sh
./scripts/build-browser-wasm.sh
```

The checked-in Dockerfile pins the official multi-platform Rust 1.98.0
Bookworm image by digest, pins clang/LLVM 14.0.6, installs only the
`wasm32-unknown-unknown` Rust target, and builds the exact locked package list
in `browser-wasm-artifacts.json`. Cargo output and registry downloads are
isolated under the ignored `target/` directory. The container runs with the
invoking user's UID/GID, so it does not leave root-owned build products on
Linux hosts. The driver refuses to build unless rustc reports its qualified
LLVM 22.1.8 backend and clang reports 14.0.6.

The build validates every module with the JavaScript engine, rejects Wasm
imports, checks boundary-specific required exports and size caps, then copies
the raw modules into `crates/bp52-relay-server/web/wasm/`. It writes a stable
manifest containing each URL, byte length, SHA-256 digest, and security
boundary. Verify checked-in/published files without rebuilding:

```sh
./scripts/build-browser-wasm.sh --check
```

An already provisioned Linux system can use `--local`. That mode deliberately
requires rustc 1.98.0, the Wasm target, clang 14, LLVM `ar`/`ranlib`, and Node;
the Docker build is the cross-platform qualified path.

```sh
./scripts/build-browser-wasm.sh --local
```

Use `--validate-only` with either backend to compile and validate without
changing the published files. The server must return `.wasm` with
`Content-Type: application/wasm` so browser loaders can use
`WebAssembly.instantiateStreaming`; it returns `manifest.json` as JSON. Wasm
responses should use immutable caching only when their URL includes a digest.

`client/target-game-wasm-docker/` was an ad-hoc, generated Cargo target tree.
It is now ignored for safety and is not used by this build. It may be deleted
locally after confirming no in-progress compiler is using it.
