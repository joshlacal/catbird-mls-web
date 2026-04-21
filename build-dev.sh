#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Building catbird-mls-web (dev)..."
wasm-pack build --target web --dev --out-dir pkg

echo "Done. Output in pkg/"
