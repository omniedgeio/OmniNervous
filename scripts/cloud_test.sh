#!/bin/bash
# =============================================================================
# OmniNervous Cloud-to-Cloud Test Orchestrator
# Run from LOCAL machine, orchestrates tests between TWO remote cloud instances
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "\n${GREEN}=== $1 ===${NC}\n"
}

print_step() {
    echo -e "${CYAN}>>> $1${NC}"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

# =============================================================================
# Configuration
# =============================================================================

NODE_A=""
NODE_B=""
SSH_KEY=""
SSH_USER="${SSH_USER:-ubuntu}"
OMNI_PORT=${OMNI_PORT:-51820}
TEST_DURATION=${TEST_DURATION:-10}
RESULTS_DIR="./test_results"
BINARY_PATH="./target/release/omni-daemon"

show_help() {
    cat << EOF
OmniNervous Cloud-to-Cloud Test Orchestrator

Runs from your LOCAL machine, SSHs into two cloud instances, deploys binaries,
runs P2P connectivity test, and collects results locally.

Usage:
  $0 --node-a <IP_A> --node-b <IP_B> [OPTIONS]

Required:
  --node-a        IP address of Node A (initiator)
  --node-b        IP address of Node B (responder)

Options:
  --ssh-key       Path to SSH private key (default: ~/.ssh/id_rsa)
  --ssh-user      SSH username (default: ubuntu)
  --port          OmniNervous UDP port (default: 51820)
  --duration      iperf3 test duration in seconds (default: 10)
  --skip-build    Skip local cargo build
  --skip-deploy   Skip binary deployment (use existing)
  --help          Show this help

Environment Variables:
  SSH_USER        SSH username (default: ubuntu)
  OMNI_PORT       UDP port (default: 51820)
  TEST_DURATION   iperf3 test duration

Example:
  # Test between AWS (us-west-2) and GCP (us-central1)
  $0 --node-a 54.x.x.x --node-b 35.x.x.x --ssh-key ~/.ssh/cloud.pem

Prerequisites on cloud nodes:
  - iperf3 installed (apt-get install iperf3)
  - UDP port $OMNI_PORT open in firewall/security group
  - SSH access with key authentication
EOF
}

# =============================================================================
# SSH Helper Functions
# =============================================================================

ssh_cmd() {
    local host="$1"
    shift
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        ${SSH_KEY:+-i "$SSH_KEY"} \
        "$SSH_USER@$host" "$@"
}

scp_to() {
    local src="$1"
    local host="$2"
    local dest="$3"
    scp -o StrictHostKeyChecking=no \
        ${SSH_KEY:+-i "$SSH_KEY"} \
        "$src" "$SSH_USER@$host:$dest"
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight_check() {
    print_header "Pre-flight Checks (Local)"
    
    local errors=0
    
    # Check local binary
    if [[ -f "$BINARY_PATH" ]]; then
        echo -e "✅ Local binary found: $BINARY_PATH"
    else
        echo -e "❌ Local binary not found: $BINARY_PATH"
        echo "   Run: cargo build -p omni-daemon --release"
        errors=$((errors + 1))
    fi
    
    # Check SSH connectivity to Node A
    print_step "Testing SSH to Node A ($NODE_A)..."
    if ssh_cmd "$NODE_A" "echo ok" &>/dev/null; then
        echo -e "✅ SSH to Node A successful"
    else
        echo -e "❌ SSH to Node A failed"
        errors=$((errors + 1))
    fi
    
    # Check SSH connectivity to Node B
    print_step "Testing SSH to Node B ($NODE_B)..."
    if ssh_cmd "$NODE_B" "echo ok" &>/dev/null; then
        echo -e "✅ SSH to Node B successful"
    else
        echo -e "❌ SSH to Node B failed"
        errors=$((errors + 1))
    fi
    
    # Check iperf3 on nodes
    print_step "Checking iperf3 on remote nodes..."
    for node in "$NODE_A" "$NODE_B"; do
        if ssh_cmd "$node" "which iperf3" &>/dev/null; then
            echo -e "✅ iperf3 installed on $node"
        else
            echo -e "❌ iperf3 not installed on $node"
            echo "   Run: ssh $SSH_USER@$node 'sudo apt-get install -y iperf3'"
            errors=$((errors + 1))
        fi
    done
    
    if [[ $errors -gt 0 ]]; then
        print_error "Pre-flight checks failed with $errors errors"
        exit 1
    fi
    
    echo -e "\n${GREEN}All pre-flight checks passed!${NC}"
}

# =============================================================================
# Deploy Binaries
# =============================================================================

deploy_binaries() {
    print_header "Deploying Binaries"
    
    for node in "$NODE_A" "$NODE_B"; do
        print_step "Deploying to $node..."
        
        # Create remote directory
        ssh_cmd "$node" "mkdir -p ~/omni-test"
        
        # Copy binary
        scp_to "$BINARY_PATH" "$node" "~/omni-test/omni-daemon"
        
        # Make executable
        ssh_cmd "$node" "chmod +x ~/omni-test/omni-daemon"
        
        echo -e "✅ Deployed to $node"
    done
}

# =============================================================================
# Run Test
# =============================================================================

run_test() {
    print_header "Running P2P Test"
    
    # Create local results directory
    mkdir -p "$RESULTS_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local result_file="$RESULTS_DIR/cloud_test_$timestamp.json"
    
    # Kill any existing processes
    print_step "Cleaning up old processes..."
    for node in "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "pkill -f omni-daemon || true; pkill -f iperf3 || true" 2>/dev/null || true
    done
    sleep 2
    
    # Start responder on Node B
    print_step "Starting responder on Node B ($NODE_B)..."
    ssh_cmd "$NODE_B" "cd ~/omni-test && nohup ./omni-daemon --port $OMNI_PORT > daemon.log 2>&1 &"
    ssh_cmd "$NODE_B" "nohup iperf3 -s -p 5201 > iperf_server.log 2>&1 &"
    sleep 3
    
    # Start initiator on Node A and connect to Node B
    print_step "Starting initiator on Node A ($NODE_A), connecting to Node B..."
    ssh_cmd "$NODE_A" "cd ~/omni-test && nohup ./omni-daemon --port $OMNI_PORT --endpoint $NODE_B:$OMNI_PORT > daemon.log 2>&1 &"
    sleep 5
    
    # Run connectivity tests from Node A to Node B
    print_header "Network Metrics (A → B)"
    
    # Latency test (via Node A to Node B)
    print_step "Measuring latency..."
    local latency_output
    latency_output=$(ssh_cmd "$NODE_A" "ping -c 10 $NODE_B 2>/dev/null | tail -1" 2>/dev/null || echo "")
    local avg_latency
    avg_latency=$(echo "$latency_output" | awk -F'/' '{print $5}' 2>/dev/null || echo "N/A")
    echo -e "  Average Latency: ${YELLOW}${avg_latency} ms${NC}"
    
    # Throughput test
    print_step "Running iperf3 throughput test ($TEST_DURATION seconds)..."
    local iperf_json
    iperf_json=$(ssh_cmd "$NODE_A" "iperf3 -c $NODE_B -p 5201 -t $TEST_DURATION --json 2>/dev/null" || echo "{}")
    
    local throughput_bps
    throughput_bps=$(echo "$iperf_json" | jq '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
    local throughput_mbps
    throughput_mbps=$(echo "scale=2; $throughput_bps / 1000000" | bc 2>/dev/null || echo "N/A")
    
    local retransmits
    retransmits=$(echo "$iperf_json" | jq '.end.sum_sent.retransmits // 0' 2>/dev/null || echo "0")
    
    echo -e "  Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
    echo -e "  Retransmits: $retransmits"
    
    # Collect daemon logs
    print_step "Collecting logs..."
    ssh_cmd "$NODE_A" "cat ~/omni-test/daemon.log" > "$RESULTS_DIR/node_a_daemon.log" 2>/dev/null || true
    ssh_cmd "$NODE_B" "cat ~/omni-test/daemon.log" > "$RESULTS_DIR/node_b_daemon.log" 2>/dev/null || true
    
    # Create results JSON
    cat > "$result_file" << EOF
{
  "timestamp": "$timestamp",
  "node_a": "$NODE_A",
  "node_b": "$NODE_B",
  "test_duration_sec": $TEST_DURATION,
  "results": {
    "latency_ms": "$avg_latency",
    "throughput_mbps": $throughput_mbps,
    "throughput_bps": $throughput_bps,
    "retransmits": $retransmits
  },
  "raw_iperf": $iperf_json
}
EOF
    
    # Cleanup remote processes
    print_step "Cleaning up remote processes..."
    for node in "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "pkill -f omni-daemon || true; pkill -f iperf3 || true" 2>/dev/null || true
    done
    
    # Summary
    print_header "Test Complete"
    
    echo -e "Node A (Initiator): $NODE_A"
    echo -e "Node B (Responder): $NODE_B"
    echo ""
    echo -e "┌──────────────────────────────────────┐"
    echo -e "│  ${GREEN}RESULTS${NC}                             │"
    echo -e "├──────────────────────────────────────┤"
    echo -e "│  Latency:     ${YELLOW}${avg_latency} ms${NC}"
    echo -e "│  Throughput:  ${YELLOW}${throughput_mbps} Mbps${NC}"
    echo -e "│  Retransmits: $retransmits"
    echo -e "└──────────────────────────────────────┘"
    echo ""
    echo -e "Results saved to: ${CYAN}$result_file${NC}"
    echo -e "Daemon logs: ${CYAN}$RESULTS_DIR/node_*_daemon.log${NC}"
}

# =============================================================================
# Main
# =============================================================================

SKIP_BUILD=false
SKIP_DEPLOY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --node-a)
            NODE_A="$2"
            shift 2
            ;;
        --node-b)
            NODE_B="$2"
            shift 2
            ;;
        --ssh-key)
            SSH_KEY="$2"
            shift 2
            ;;
        --ssh-user)
            SSH_USER="$2"
            shift 2
            ;;
        --port)
            OMNI_PORT="$2"
            shift 2
            ;;
        --duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-deploy)
            SKIP_DEPLOY=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate required args
if [[ -z "$NODE_A" || -z "$NODE_B" ]]; then
    print_error "Both --node-a and --node-b are required"
    show_help
    exit 1
fi

print_header "OmniNervous Cloud-to-Cloud Test"
echo "Node A (Initiator): $NODE_A"
echo "Node B (Responder): $NODE_B"

# Build locally if needed
if ! $SKIP_BUILD; then
    print_header "Building Binary (Local)"
    cargo build -p omni-daemon --release --target x86_64-unknown-linux-gnu 2>/dev/null || \
    cargo build -p omni-daemon --release
fi

# Run test sequence
preflight_check

if ! $SKIP_DEPLOY; then
    deploy_binaries
fi

run_test

echo -e "\n${GREEN}✅ Cloud test completed successfully!${NC}"
