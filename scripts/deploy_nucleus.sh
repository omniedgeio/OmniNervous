#!/bin/bash
# deploy_nucleus.sh
# OmniNervous Cloud Nucleus Deployment Helper

set -e

REMOTE_HOST=$1
KEY_PATH=$2

if [ -z "$REMOTE_HOST" ]; then
  echo "Usage: ./scripts/deploy_nucleus.sh <user@remote-ip> [ssh-key-path]"
  exit 1
fi

SSH_OPTS=""
if [ -n "$KEY_PATH" ]; then
  SSH_OPTS="-i $KEY_PATH"
fi

echo "🚀 [OmniNervous] Deploying Nucleus to $REMOTE_HOST..."

# 1. Prepare remote environment
ssh $SSH_OPTS $REMOTE_HOST "sudo apt-get update && sudo apt-get install -y docker.io docker-compose"

# 2. Sync project source (simplified for demo)
echo "📦 Syncing project to remote..."
rsync -avz -e "ssh $SSH_OPTS" --exclude 'target' --exclude '.git' . $REMOTE_HOST:~/omninervous

# 3. Launch Nucleus and Edge Node on remote
echo "📡 Launching Nucleus and Cloud Edge on remote..."
ssh $SSH_OPTS $REMOTE_HOST "cd ~/omninervous && sudo docker-compose up -d nucleus edge-a"

# 4. Success Output
PUBLIC_IP=$(echo $REMOTE_HOST | cut -d'@' -f2)
echo "------------------------------------------------"
echo "✅ Nucleus & Cloud Edge Deployed Successfully!"
echo "📍 Public IP: $PUBLIC_IP"
echo "🔑 Signaling Port: 51820 (UDP)"
echo ""
echo "The cloud VM is now both a Nucleus and an active Edge node."
echo "To verify performance, run from a local node:"
echo "iperf3 -c $PUBLIC_IP"
echo ""
echo "To connect local nodes, run:"
echo "./omni-daemon --nucleus $PUBLIC_IP --cluster cloud-fabric"
echo "------------------------------------------------"
