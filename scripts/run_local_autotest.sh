#!/bin/bash
# run_local_autotest.sh
# One-click automated test for OmniNervous Hybrid Cloud Simulation (Nucleus + Cloud Edge)

set -e

echo "🐳 [OmniNervous] Preparing Local Docker Fabric..."

# 1. Cleanup previous runs
docker-compose down -v --remove-orphans > /dev/null 2>&1

# 2. Build and Start the Cluster
echo "🏗️ Building and Launching Nodes..."
docker-compose up -d nucleus edge-a edge-b

# 3. Run the Tester
echo "🧪 Running Automated Connectivity Suite..."
docker-compose up --abort-on-container-exit tester

# 4. Final Cleanup
echo "🧹 Cleaning up environment..."
docker-compose down -v > /dev/null 2>&1

echo "✨ Local Autotest Complete!"
