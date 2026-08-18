#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building catbird-mls-web (dev)..."
AR_wasm32_unknown_unknown="$PWD/build-tools/wasm-ar" \
    wasm-pack build --target web --dev --out-dir pkg

echo "Done. Output in pkg/"
