#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$root/target/browser-wasm-cargo/registry" "$root/target/browser-wasm-cargo/git"
# Same pinned builder as the application, but a separate diagnostic artifact.
docker run --rm --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$root,target=/workspace" \
  --mount "type=bind,source=$root/target/browser-wasm-cargo/registry,target=/usr/local/cargo/registry" \
  --mount "type=bind,source=$root/target/browser-wasm-cargo/git,target=/usr/local/cargo/git" \
  --env CARGO_TARGET_DIR=/workspace/target/browser-wasm \
  --env 'CFLAGS_wasm32_unknown_unknown=--target=wasm32-unknown-unknown -ffile-prefix-map=/workspace=. -DUSE_FORCE_WIDEMUL_INT64' \
  --env 'RUSTFLAGS=--remap-path-prefix=/workspace=. -C link-arg=-zstack-size=33554432' \
  --workdir /workspace bp52-browser-wasm-builder:rust-1.98.0-clang14-v1 \
  cargo build --release --locked --target wasm32-unknown-unknown -p settlement-benchmark
