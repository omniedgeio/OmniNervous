#!/bin/bash
set -e

# 1. Fast build
./scripts/build_cross_fast.sh

# 2. Deploy
./scripts/deploy_to_cloud.sh root@104.248.221.140

echo "\nTo run the test:"
echo "./scripts/cloud_test.sh root@104.248.221.140"
