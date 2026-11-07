#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Running browser WASM tests..."
# One page load runs a whole test binary; OPFS-backed multi-client fixtures outlast the
# runner's 20 s default.
AR_wasm32_unknown_unknown="$PWD/build-tools/wasm-ar" \
    WASM_BINDGEN_TEST_TIMEOUT="${WASM_BINDGEN_TEST_TIMEOUT:-120}" \
    wasm-pack test --headless --firefox "$@"
