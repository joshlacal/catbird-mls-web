#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Running browser WASM tests..."
wasm-pack test --headless --firefox "$@"
