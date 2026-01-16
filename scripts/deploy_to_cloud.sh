#!/bin/bash
# scripts/deploy_to_cloud.sh
# Efficiently syncs the project to a cloud instance using rsync.

set -e

# Configuration
TARGET=$1
REMOTE_PATH=${2:-"~/OmniNervous"}

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <user@host> [remote_path]"
    echo "Example: $0 root@104.248.221.140"
    exit 1
fi

# If TARGET already contains a colon, it's user@host:path
if [[ "$TARGET" == *:* ]]; then
    # If path is provided as 2nd arg, and TARGET has path, warn/handle?
    # For now, let's just use TARGET if it has a colon.
    RSYNC_DEST="$TARGET"
else
    RSYNC_DEST="$TARGET:$REMOTE_PATH"
fi

echo "🚀 Syncing project to $RSYNC_DEST..."

# Sync using rsync with smart excludes
rsync -avz --progress \
    --exclude '.git/' \
    --exclude '.gemini/' \
    --exclude '.github/' \
    --exclude 'target/' \
    --exclude 'omni-daemon/target/' \
    --exclude 'omni-ebpf/target/' \
    --exclude '**/ebpf/omni-ebpf-core' \
    --exclude '.idea/' \
    --exclude '.vscode/' \
    --exclude '*.log' \
    --exclude '*.key' \
    --exclude '.omni/' \
    --exclude 'node_modules/' \
    --exclude 'scripts/omni-daemon-linux-amd64' \
    ./ "$RSYNC_DEST/"

echo "✅ Sync complete!"
