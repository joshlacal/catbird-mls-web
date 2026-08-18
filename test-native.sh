#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Running native catbird-mls-web tests (WASM-only SQLite/Opus dependencies excluded)..."
cargo test --lib "$@"
