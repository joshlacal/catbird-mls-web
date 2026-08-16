#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Running browser WASM tests..."
AR_wasm32_unknown_unknown="$PWD/build-tools/wasm-ar" \
    wasm-pack test --headless --firefox "$@"
