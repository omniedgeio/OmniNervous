#!/bin/bash
set -e

# =============================================================================
# OmniNervous Cloud Test 50-Run Suite
# Wrapper to run cloud_test.sh 50 times for stability/performance analysis
# =============================================================================

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_TEST_SCRIPT="$SCRIPT_DIR/cloud_test.sh"
HARDCODED_ARGS="--nucleus 18.214.99.197 --node-a 13.218.141.197 --node-b 54.202.146.75 --ssh-user ubuntu --secret your-secret-min16 --userspace"

if [ ! -f "$CLOUD_TEST_SCRIPT" ]; then
    echo "Error: cloud_test.sh not found at $CLOUD_TEST_SCRIPT"
    exit 1
fi

# Pass all arguments to the underlying script
ARGS="$HARDCODED_ARGS $@"

echo "============================================================================="
echo "STARTING 50-RUN STABILITY SUITE"
echo "Target Script: $CLOUD_TEST_SCRIPT"
echo "Arguments: $ARGS"
echo "============================================================================="

# Create a batch timestamp for logging if needed (results are individually timestamped)
BATCH_ID=$(date +%Y%m%d_%H%M%S)
echo "Batch ID: $BATCH_ID"

START_TIME=$(date +%s)

for i in {1..50}; do
    echo ""
    echo "-----------------------------------------------------------------------------"
    echo "RUN #$i / 50"
    echo "-----------------------------------------------------------------------------"
    
    # Optimization: Only deploy binary on the first run (unless user explicitly skipped it)
    # If the user passed --skip-deploy, we respect it.
    # Otherwise, we allow deploy on run 1, then append --skip-deploy for runs 2-50.
    
    CURRENT_ARGS="$ARGS"
    
    if [ $i -gt 1 ]; then
        if [[ "$ARGS" != *"--skip-deploy"* ]]; then
             CURRENT_ARGS="$ARGS --skip-deploy"
             echo "Info: Skipping binary deployment for iteration $i (already deployed in run #1)"
        fi
    fi
    
    # Run the test script
    # We use 'bash' explictly to ensure execution
    bash "$CLOUD_TEST_SCRIPT" $CURRENT_ARGS
    
    # Small cooldown between tests to let sockets fully close
    echo "Cooling down for 2 seconds..."
    sleep 2
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "============================================================================="
echo "SUITE COMPLETE"
echo "Total Runs: 50"
echo "Total Duration: ${DURATION}s"
echo "Results saved in ./test_results/"
echo "============================================================================="
