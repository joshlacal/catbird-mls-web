#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Cargo config is intentionally free of a Unix shell archiver override. This
# keeps native Windows Cargo builds on Cargo's platform default; Unix WASM
# entry points inject build-tools/wasm-ar only for their own invocation.
if [[ -f .cargo/config.toml ]] && rg -n 'wasm-ar|AR_wasm32_unknown_unknown' .cargo/config.toml; then
    echo "WASM archiver must not be configured unconditionally in .cargo/config.toml" >&2
    exit 1
fi

echo "Tooling config is safe for native Windows Cargo builds."
