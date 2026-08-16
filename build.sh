#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building catbird-mls-web (release)..."
AR_wasm32_unknown_unknown="$PWD/build-tools/wasm-ar" \
    wasm-pack build --target web --release --out-dir pkg

if command -v wasm-opt &>/dev/null; then
    echo "Running wasm-opt..."
    wasm-opt -Oz pkg/catbird_mls_web_bg.wasm -o pkg/catbird_mls_web_bg.wasm
fi

echo "Done. Output in pkg/"
