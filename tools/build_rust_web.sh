#!/usr/bin/env bash
# Builds crates/client/mc3-runtime for wasm32-unknown-emscripten with wasm threads, prints the staticlib's path.
# Emscripten pthreads need every object built with atomics + bulk memory (a Rust std without them cannot share
# the memory), so std is rebuilt from source: nightly + rust-src (rustup toolchain install nightly
# --component rust-src; rustup target add wasm32-unknown-emscripten --toolchain nightly). Used by CMakeLists.txt
# (MC3_RUST_RUNTIME) and tools/test_rust_crypto.sh. TARGET_DIR: where cargo builds (default work-rust).
set -euo pipefail
cd "$(dirname "$0")/.."
T=${TARGET_DIR:-work-rust}
RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals -C panic=abort" \
    cargo +nightly build -q -p mc3-runtime --release --target wasm32-unknown-emscripten \
    -Zbuild-std=std,panic_abort --target-dir "$T" >&2
echo "$T/wasm32-unknown-emscripten/release/libmc3_runtime.a"
