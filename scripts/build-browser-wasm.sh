#!/bin/sh

set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
builder_image="bp52-browser-wasm-builder:rust-1.98.0-clang14-v1"
target="wasm32-unknown-unknown"
publish=1
backend=docker
operation=build

usage() {
  printf '%s\n' \
    "usage: scripts/build-browser-wasm.sh [--docker|--local] [--validate-only]" \
    "       scripts/build-browser-wasm.sh --check" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --docker)
      backend=docker
      ;;
    --local)
      backend=local
      ;;
    --container)
      backend=container
      ;;
    --validate-only)
      publish=0
      ;;
    --check)
      operation=check
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  shift
done

if [ "${operation}" = check ]; then
  exec node "${repository_root}/scripts/package-browser-wasm.mjs" --check
fi

if [ "${backend}" = docker ]; then
  docker build \
    --file "${repository_root}/toolchains/browser-wasm.Dockerfile" \
    --tag "${builder_image}" \
    "${repository_root}/toolchains"
  cargo_cache_root="${repository_root}/target/browser-wasm-cargo"
  mkdir -p "${cargo_cache_root}/registry" "${cargo_cache_root}/git"
  host_uid=$(id -u)
  host_gid=$(id -g)
  if [ "${operation}" = check ]; then
    set -- --check
  elif [ "${publish}" -eq 0 ]; then
    set -- --validate-only
  else
    set --
  fi
  exec docker run --rm \
    --user "${host_uid}:${host_gid}" \
    --mount "type=bind,source=${repository_root},target=/workspace" \
    --mount "type=bind,source=${cargo_cache_root}/registry,target=/usr/local/cargo/registry" \
    --mount "type=bind,source=${cargo_cache_root}/git,target=/usr/local/cargo/git" \
    --env CARGO_TARGET_DIR=/workspace/target/browser-wasm \
    --workdir /workspace \
    "${builder_image}" \
    /workspace/scripts/build-browser-wasm.sh --container "$@"
fi

rust_version=$(rustc --version)
case "${rust_version}" in
  "rustc 1.98.0 "*) ;;
  *)
    printf 'expected rustc 1.98.0, found %s\n' "${rust_version}" >&2
    exit 1
    ;;
esac

if ! rustup target list --installed | grep -qx "${target}"; then
  printf 'missing Rust target %s\n' "${target}" >&2
  exit 1
fi

if [ "${backend}" = container ]; then
  wasm_cc=clang-14
  wasm_ar=llvm-ar-14
  wasm_ranlib=llvm-ranlib-14
else
  wasm_cc=${BP52_WASM_CC:-clang-14}
  wasm_ar=${BP52_WASM_AR:-llvm-ar-14}
  wasm_ranlib=${BP52_WASM_RANLIB:-llvm-ranlib-14}
fi

command -v "${wasm_cc}" >/dev/null
command -v "${wasm_ar}" >/dev/null
command -v "${wasm_ranlib}" >/dev/null
command -v node >/dev/null

if ! rustc --version --verbose | grep -qx 'LLVM version: 22.1.8'; then
  printf 'rustc is not using the qualified LLVM 22.1.8 backend\n' >&2
  exit 1
fi
if ! "${wasm_cc}" --version | sed -n '1p' | grep -Eq 'clang version 14\.0\.6'; then
  printf 'the Wasm C compiler is not the qualified clang 14.0.6 release\n' >&2
  exit 1
fi

export AR_wasm32_unknown_unknown="${wasm_ar}"
export CARGO_INCREMENTAL=0
export CC_wasm32_unknown_unknown="${wasm_cc}"
# Avoid Wasm's expensive int128 emulation using libsecp256k1's supported backend.
export CFLAGS_wasm32_unknown_unknown="--target=wasm32-unknown-unknown -ffile-prefix-map=${repository_root}=. -DUSE_FORCE_WIDEMUL_INT64"
export RANLIB_wasm32_unknown_unknown="${wasm_ranlib}"
export RUSTFLAGS="--remap-path-prefix=${repository_root}=."
export SOURCE_DATE_EPOCH=0
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"${repository_root}/target/browser-wasm"}
export CARGO_TARGET_DIR

while IFS= read -r package; do
  # Build each surviving security boundary independently.
  cargo build \
    --manifest-path "${repository_root}/Cargo.toml" \
    --locked \
    --release \
    --target "${target}" \
    --package "${package}"
done <<'PACKAGES'
poker-wallet-wasm
poker-funding-wasm
poker-transaction-wasm
PACKAGES

# Build DLOG52 independently, preserving the 8 MiB Wasm stack required by the
# fixed 927-candidate catalogue verifier.
RUSTFLAGS="${RUSTFLAGS} -C link-arg=-zstack-size=8388608" cargo build \
  --manifest-path "${repository_root}/Cargo.toml" \
  --locked \
  --release \
  --target "${target}" \
  --package dealer-wasm

RUSTFLAGS="${RUSTFLAGS} -C link-arg=-zstack-size=33554432" cargo build \
  --manifest-path "${repository_root}/Cargo.toml" --locked --release \
  --target "${target}" --package poker-session-wasm

artifact_directory="${CARGO_TARGET_DIR}/${target}/release"
if [ "${publish}" -eq 1 ]; then
  node "${repository_root}/scripts/package-browser-wasm.mjs" \
    --write \
    --from "${artifact_directory}"
else
  node "${repository_root}/scripts/package-browser-wasm.mjs" \
    --validate-built \
    --from "${artifact_directory}"
fi
