#!/bin/bash
# scripts/build_local_docker.sh
# Builds omni-daemon using Docker and extracts the binary.
# Best for native amd64 builds.

set -e

# Configuration
IMAGE_NAME="omni-daemon-build-local"
BINARY_NAME="omni-daemon"
OUTPUT_PATH="scripts/omni-daemon-linux-amd64"

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔨 Building $BINARY_NAME using Docker..."
cd "$PROJECT_ROOT"

# 1. Build the Docker image
docker build -t "$IMAGE_NAME" .

# 2. Extract the binary
echo "📦 Extracting binary to $OUTPUT_PATH..."
CONTAINER_ID=$(docker create "$IMAGE_NAME")
docker cp "$CONTAINER_ID":/usr/local/bin/"$BINARY_NAME" "$PROJECT_ROOT/$OUTPUT_PATH"
docker rm "$CONTAINER_ID"

# 3. Cleanup (optional - uncomment if you want to keep host clean)
# echo "🧹 Cleaning up Docker image..."
# docker rmi "$IMAGE_NAME"

echo "✅ Build complete: $OUTPUT_PATH"
ls -lh "$PROJECT_ROOT/$OUTPUT_PATH"
