#!/bin/bash
# scripts/build_cross_fast.sh
# High-speed cross-compilation from Mac (arm64) to Linux (amd64).
# Uses cargo-zigbuild to avoid slow QEMU emulation.

set -e

# 1. Check Rust version (needs 1.81+ for recent crates)
RUST_VERSION=$(rustc --version | awk '{print $2}')
V_MAJOR=$(echo $RUST_VERSION | cut -d. -f1)
V_MINOR=$(echo $RUST_VERSION | cut -d. -f2)

if [ "$V_MAJOR" -lt 1 ] || { [ "$V_MAJOR" -eq 1 ] && [ "$V_MINOR" -lt 81 ]; }; then
    echo "⚠️  Your Rust version ($RUST_VERSION) is too old for current dependencies."
    echo "Please run: rustup update stable"
    exit 1
fi

# 2. Check for cargo-zigbuild
if ! command -v cargo-zigbuild &> /dev/null; then
    echo "⚠️  cargo-zigbuild not found. Installing..."
    brew install zig
    # Pinning version to avoid breaking changes if needed, but usually latest is best on compatible rust
    cargo install cargo-zigbuild
fi

# 2. Add target and source component (required for some cross-builds)
rustup target add x86_64-unknown-linux-gnu
rustup component add rust-src

# 3. Build
echo "🚀 Building for x86_64-unknown-linux-gnu (Native Cross)..."
# Using standard target first to ensure core/std are found
cargo zigbuild -p omni-daemon --release --target x86_64-unknown-linux-gnu

# 4. Copy binary
mkdir -p scripts
cp target/x86_64-unknown-linux-gnu/release/omni-daemon scripts/omni-daemon-linux-amd64

echo "✅ Fast build complete: scripts/omni-daemon-linux-amd64"
file scripts/omni-daemon-linux-amd64
