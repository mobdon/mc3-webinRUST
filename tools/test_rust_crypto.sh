#!/usr/bin/env bash
# The Rust crypto (crates/client/mc3-runtime) against kernel_crypto.c, natively and in Emscripten with pthreads
# (tools/test_rust_crypto.c). Needs nightly + rust-src for the wasm half (tools/build_rust_web.sh); skips it
# without Emscripten. Scratch goes to work-rust/.
set -euo pipefail
cd "$(dirname "$0")/.."
K=xboxrecomp/src/kernel
INC=(-I"$K" -Ixboxrecomp/src -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
REN=()
for f in SHAInit SHAUpdate SHAFinal RC4Key RC4Crypt HMAC PKGetKeyLen PKDecPrivate PKEncPublic VerifyPKCS1Signature \
         ModExp DESKeyParity KeyTable BlockCrypt BlockCryptCBC CryptService UpdateCrypto; do
    REN+=("-Dxbox_Xc$f=c_Xc$f")
done
O=work-rust/test-crypto
mkdir -p "$O"

echo "== native"
cargo build -q -p mc3-runtime --release --target-dir work-rust
cc -O2 "${INC[@]}" "${REN[@]}" -c "$K/kernel_crypto.c" -o "$O/c_crypto.o"
cc -O2 "${INC[@]}" tools/test_rust_crypto.c "$O/c_crypto.o" work-rust/release/libmc3_runtime.a -lpthread -ldl -lm -o "$O/native"
"$O/native"

if ! command -v emcc >/dev/null; then
    [ -f "${EMSDK:-/opt/emsdk}/emsdk_env.sh" ] && . "${EMSDK:-/opt/emsdk}/emsdk_env.sh" >/dev/null 2>&1 || true
fi
command -v emcc >/dev/null || { echo "== wasm: skipped (no Emscripten)"; exit 0; }
echo "== wasm32-unknown-emscripten, -pthread"
A=$(bash tools/build_rust_web.sh)
emcc -O2 -pthread "${INC[@]}" "${REN[@]}" -c "$K/kernel_crypto.c" -o "$O/c_crypto.wasm.o"
emcc -O2 -pthread -sPTHREAD_POOL_SIZE=4 -sENVIRONMENT=node "${INC[@]}" tools/test_rust_crypto.c "$O/c_crypto.wasm.o" "$A" \
    -o "$O/wasm.js"
node "$O/wasm.js"
