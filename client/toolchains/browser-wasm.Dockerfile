# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Exact Rust release and Docker multi-platform index. This prevents a moving
# `latest` tag from silently changing either rustc or its LLVM Wasm backend.
FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922

LABEL org.opencontainers.image.title="BP52 browser Wasm builder"
LABEL org.opencontainers.image.description="Pinned rustc/LLVM and clang cross-toolchain for BP52 browser artifacts"

ARG LLVM_DEBIAN_VERSION="1:14.0.6-12"
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        clang-14="${LLVM_DEBIAN_VERSION}" \
        lld-14="${LLVM_DEBIAN_VERSION}" \
        llvm-14="${LLVM_DEBIAN_VERSION}" \
        nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add --toolchain 1.98.0 clippy rustfmt \
    && rustup target add --toolchain 1.98.0 wasm32-unknown-unknown

ENV AR_wasm32_unknown_unknown=llvm-ar-14 \
    CARGO_INCREMENTAL=0 \
    CC_wasm32_unknown_unknown=clang-14 \
    CFLAGS_wasm32_unknown_unknown="--target=wasm32-unknown-unknown -ffile-prefix-map=/workspace=." \
    RANLIB_wasm32_unknown_unknown=llvm-ranlib-14 \
    RUSTFLAGS="--remap-path-prefix=/workspace=." \
    RUSTUP_TOOLCHAIN=1.98.0

WORKDIR /workspace/client
