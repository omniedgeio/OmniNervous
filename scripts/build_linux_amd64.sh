#!/bin/bash
# Cross-compile omni-daemon for linux-amd64 from macOS arm64
# Uses Docker with Rust official image

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$SCRIPT_DIR"

echo "🔨 Cross-compiling omni-daemon for linux-amd64..."
echo "   Project: $PROJECT_ROOT"
echo "   Output:  $OUTPUT_DIR/omni-daemon-linux-amd64"

# Build using Docker with explicit platform
docker build \
    --platform linux/amd64 \
    -t omni-daemon-builder:amd64 \
    -f "$PROJECT_ROOT/Dockerfile" \
    "$PROJECT_ROOT"

# Extract the binary from the built image
CONTAINER_ID=$(docker create --platform linux/amd64 omni-daemon-builder:amd64)
docker cp "$CONTAINER_ID:/usr/local/bin/omni-daemon" "$OUTPUT_DIR/omni-daemon-linux-amd64"
docker rm "$CONTAINER_ID"

# Verify the binary
echo ""
echo "✅ Build complete!"
file "$OUTPUT_DIR/omni-daemon-linux-amd64"
ls -lh "$OUTPUT_DIR/omni-daemon-linux-amd64"
