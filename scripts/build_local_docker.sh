#!/bin/bash
# scripts/build_local_docker.sh
# Builds omni-daemon using Docker and extracts the binary.
# Compatible with macOS and Linux.

set -e

# Configuration
IMAGE_NAME="omni-daemon-build-local"
BINARY_NAME="omni-daemon"
OUTPUT_PATH="scripts/omni-daemon-linux-amd64"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo -e "${CYAN}🔨 Building $BINARY_NAME using Docker...${NC}"
cd "$PROJECT_ROOT"

# 1. Build the Docker image
# Using --platform linux/amd64 to ensure the binary is correct for cloud deployment
# even when building on Apple Silicon (arm64) macOS.
docker build --platform linux/amd64 --no-cache -t "$IMAGE_NAME" .

# 2. Extract the binary
echo -e "${CYAN}📦 Extracting binary to $OUTPUT_PATH...${NC}"
CONTAINER_ID=$(docker create --platform linux/amd64 "$IMAGE_NAME")

# Ensure the parent directory of the output path exists
mkdir -p "$(dirname "$PROJECT_ROOT/$OUTPUT_PATH")"

docker cp "$CONTAINER_ID":/usr/local/bin/"$BINARY_NAME" "$PROJECT_ROOT/$OUTPUT_PATH"
docker rm "$CONTAINER_ID"

echo -e "${GREEN}✅ Build complete: $OUTPUT_PATH${NC}"
ls -lh "$PROJECT_ROOT/$OUTPUT_PATH"
