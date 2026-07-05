#!/usr/bin/env bash
set -euo pipefail

# Package Ad-Wolf: try Tauri GUI bundle first, fall back to CLI-only.
# Usage: ./scripts/package.sh [cli-only]

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-}"

if [ "$TARGET" != "cli-only" ] && command -v npm &>/dev/null; then
    echo "==> Building CLI daemon binary for sidecar..."
    cargo build --release --bin dns-filter

    echo "==> Copying binary to Tauri sidecar location..."
    TRIPLE=$(rustc -vV | grep host | awk '{print $2}')
    mkdir -p gui/src-tauri/binaries
    cp "target/release/dns-filter${EXE:-}" "gui/src-tauri/binaries/dns-filter-$TRIPLE${EXE:-}"

    echo "==> Installing frontend dependencies..."
    cd gui && npm install && cd "$ROOT"

    echo "==> Building Tauri app (includes GUI + CLI daemon)..."
    cd gui/src-tauri && cargo tauri build && cd "$ROOT"

    echo "==> Bundles created at gui/src-tauri/target/release/bundle/"
else
    echo "==> npm not available, building CLI-only package..."

    cargo build --release --bin dns-filter

    if command -v cargo-deb &>/dev/null; then
        echo "==> Building .deb..."
        cargo deb --output artifacts/dns-filter.deb
    fi

    if command -v cargo-generate-rpm &>/dev/null; then
        echo "==> Building .rpm..."
        cargo generate-rpm --output artifacts/dns-filter.rpm
    fi

    if command -v cargo-wix &>/dev/null; then
        echo "==> Building .msi..."
        cargo wix --no-banner --output artifacts/dns-filter.msi
    fi

    echo "==> CLI-only packages created at artifacts/"
fi
