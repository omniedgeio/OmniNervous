#!/bin/bash
# =============================================================================
# OmniNervous Cloud-to-Cloud Test Orchestrator (3-Node Architecture)
# Run from LOCAL machine, orchestrates tests between cloud instances
# Architecture: Nucleus (signaling) + Edge A + Edge B (P2P tunnel)
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

NUCLEUS=""
NODE_A=""
NODE_B=""
SSH_KEY=""
SSH_USER="${SSH_USER:-ubuntu}"
OMNI_PORT=${OMNI_PORT:-51820}
TEST_DURATION=${TEST_DURATION:-10}
RESULTS_DIR="./test_results"
# Use cross-compiled Linux binary path (x86_64)
BINARY_PATH="./target/x86_64-unknown-linux-gnu/release/omni-daemon"
BINARY_PATH_FALLBACK="./target/release/omni-daemon"

# Virtual IPs for P2P tunnel
VIP_A="10.200.0.10"
VIP_B="10.200.0.20"
CLUSTER_NAME="${CLUSTER_NAME:-omni-test}"
CLUSTER_SECRET="${CLUSTER_SECRET:-}"

show_help() {
    cat << EOF
OmniNervous 3-Node Cloud Test Orchestrator

Architecture:
  ┌──────────┐      ┌──────────┐      ┌──────────┐
  │ Nucleus  │◄────►│  Edge A  │◄────►│  Edge B  │
  │ Signaling│      │ $VIP_A │      │ $VIP_B │
  └──────────┘      └──────────┘      └──────────┘

Usage:
  $0 --nucleus <IP> --node-a <IP> --node-b <IP> [OPTIONS]

Required:
  --nucleus       IP address of Nucleus (signaling server)
  --node-a        IP address of Edge A
  --node-b        IP address of Edge B

Options:
  --ssh-key       Path to SSH private key
  --ssh-user      SSH username (default: ubuntu)
  --port          OmniNervous UDP port (default: 51820)
  --duration      iperf3 test duration (default: 10s)
  --cluster       Cluster name (default: omni-test)
  --secret        Cluster secret (min 16 chars, recommended)
  --skip-build    Skip local cargo build
  --skip-deploy   Skip binary deployment
  --help          Show this help

Environment Variables:
  SSH_USER        SSH username
  OMNI_PORT       UDP port
  CLUSTER_SECRET  Cluster authentication secret

Example:
  $0 --nucleus 104.x.x.x --node-a 54.x.x.x --node-b 35.x.x.x \\
     --ssh-key ~/.ssh/cloud.pem --secret "my-secure-secret-16"

Prerequisites:
  - iperf3 installed on edge nodes
  - UDP port $OMNI_PORT open in firewalls
  - SSH access with key authentication
  - Root access for TUN device creation
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
    
    # Check local binary (prefer cross-compiled for Linux)
    if [[ -f "$BINARY_PATH" ]]; then
        echo -e "✅ Local binary found: $BINARY_PATH"
    elif [[ -f "$BINARY_PATH_FALLBACK" ]]; then
        BINARY_PATH="$BINARY_PATH_FALLBACK"
        echo -e "⚠️  Using fallback binary: $BINARY_PATH"
        echo "   Warning: Native binary may not work on Linux targets!"
    else
        echo -e "❌ No binary found"
        echo "   Run: cargo build -p omni-daemon --release --target x86_64-unknown-linux-gnu"
        errors=$((errors + 1))
    fi
    
    # Check SSH connectivity
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        print_step "Testing SSH to $node..."
        if ssh_cmd "$node" "echo ok" &>/dev/null; then
            echo -e "✅ SSH to $node successful"
        else
            echo -e "❌ SSH to $node failed"
            errors=$((errors + 1))
        fi
    done
    
    # Check iperf3 on edge nodes
    print_step "Checking iperf3 on edge nodes..."
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
# Deploy via Docker
# =============================================================================

deploy_binaries() {
    print_header "Deploying via Docker"
    
    # GitHub repo for cloning
    local REPO_URL="https://github.com/omniedgeio/OmniNervous.git"
    
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        print_step "Setting up Docker on $node..."
        
        # Check if Docker is installed, install if needed
        ssh_cmd "$node" "command -v docker >/dev/null 2>&1 || (curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker \$USER)"
        
        # Clone or update repo
        print_step "Cloning repository on $node..."
        ssh_cmd "$node" "if [ -d ~/OmniNervous ]; then cd ~/OmniNervous && git pull; else git clone $REPO_URL ~/OmniNervous; fi"
        
        # Build Docker image on this node
        print_step "Building Docker image on $node (this may take a few minutes first time)..."
        ssh_cmd "$node" "cd ~/OmniNervous && sudo docker build -t omni-daemon:latest . 2>&1 | tail -5"
        
        if [ $? -ne 0 ]; then
            print_error "Docker build failed on $node"
            # Continue anyway - might already have the image
        fi
        
        echo -e "✅ Deployed to $node"
    done
}

# =============================================================================
# Run Test
# =============================================================================

run_test() {
    print_header "Running 3-Node P2P Test"
    
    # Create local results directory
    mkdir -p "$RESULTS_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local result_file="$RESULTS_DIR/cloud_test_$timestamp.json"
    
    # Build secret args
    local secret_args=""
    if [[ -n "$CLUSTER_SECRET" ]]; then
        if [[ ${#CLUSTER_SECRET} -lt 16 ]]; then
            print_error "Secret must be at least 16 characters"
            exit 1
        fi
        secret_args="--secret $CLUSTER_SECRET"
        echo -e "🔐 Cluster authentication enabled"
    else
        echo -e "⚠️  No secret specified, running in OPEN mode"
    fi
    
    # Kill any existing containers/processes
    print_step "Cleaning up old containers..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo docker stop omni-nucleus omni-edge 2>/dev/null; sudo docker rm omni-nucleus omni-edge 2>/dev/null; pkill -f iperf3 || true" 2>/dev/null || true
    done
    sleep 2
    
    # Start Nucleus Docker container
    print_step "Starting Nucleus on $NUCLEUS..."
    ssh_cmd "$NUCLEUS" "sudo docker run -d --name omni-nucleus \
        --network=host \
        omni-daemon:latest \
        --mode nucleus --port $OMNI_PORT"
    sleep 3
    
    # Start Edge A Docker container with VIP
    print_step "Starting Edge A on $NODE_A (VIP: $VIP_A)..."
    ssh_cmd "$NODE_A" "sudo docker run -d --name omni-edge \
        --network=host \
        --privileged \
        --cap-add=NET_ADMIN \
        -v /dev/net/tun:/dev/net/tun \
        omni-daemon:latest \
        --nucleus $NUCLEUS:$OMNI_PORT \
        --cluster $CLUSTER_NAME $secret_args \
        --vip $VIP_A \
        --port $OMNI_PORT"
    sleep 3
    
    # Start Edge B Docker container with VIP
    print_step "Starting Edge B on $NODE_B (VIP: $VIP_B)..."
    ssh_cmd "$NODE_B" "sudo docker run -d --name omni-edge \
        --network=host \
        --privileged \
        --cap-add=NET_ADMIN \
        -v /dev/net/tun:/dev/net/tun \
        omni-daemon:latest \
        --nucleus $NUCLEUS:$OMNI_PORT \
        --cluster $CLUSTER_NAME $secret_args \
        --vip $VIP_B \
        --port $((OMNI_PORT + 1))"
    sleep 5
    
    # Wait for P2P tunnel establishment
    print_step "Waiting for P2P tunnel establishment..."
    sleep 5
    
    # Check if containers are running
    print_step "Checking Docker containers..."
    echo "Nucleus container:"
    ssh_cmd "$NUCLEUS" "sudo docker ps --filter name=omni-nucleus --format '{{.Names}} {{.Status}}' || echo 'NOT RUNNING'"
    echo "Edge A container:"
    ssh_cmd "$NODE_A" "sudo docker ps --filter name=omni-edge --format '{{.Names}} {{.Status}}' || echo 'NOT RUNNING'"
    echo "Edge B container:"
    ssh_cmd "$NODE_B" "sudo docker ps --filter name=omni-edge --format '{{.Names}} {{.Status}}' || echo 'NOT RUNNING'"
    echo ""
    
    # Show container logs for debugging
    print_step "Container logs (last 10 lines)..."
    echo "--- Nucleus log ---"
    ssh_cmd "$NUCLEUS" "sudo docker logs omni-nucleus --tail 10 2>&1 || echo 'No container'"
    echo ""
    echo "--- Edge A log ---"
    ssh_cmd "$NODE_A" "sudo docker logs omni-edge --tail 10 2>&1 || echo 'No container'"
    echo ""
    echo "--- Edge B log ---"
    ssh_cmd "$NODE_B" "sudo docker logs omni-edge --tail 10 2>&1 || echo 'No container'"
    echo ""
    
    # Check interfaces on edges
    print_step "Verifying TUN interfaces..."
    echo "Edge A interfaces:"
    ssh_cmd "$NODE_A" "ip addr show omni0 2>/dev/null || echo 'omni0 not found'"
    echo ""
    echo "Edge B interfaces:"
    ssh_cmd "$NODE_B" "ip addr show omni0 2>/dev/null || echo 'omni0 not found'"
    
    # Network tests over P2P tunnel
    print_header "Network Metrics (P2P Tunnel: A → B)"
    
    # Ping test over tunnel
    print_step "Ping over tunnel ($VIP_A → $VIP_B)..."
    local ping_output
    ping_output=$(ssh_cmd "$NODE_A" "ping -c 10 -W 2 $VIP_B 2>&1" || echo "PING_FAILED")
    local avg_latency="N/A"
    if echo "$ping_output" | grep -q "rtt"; then
        avg_latency=$(echo "$ping_output" | grep "rtt" | awk -F'/' '{print $5}')
        echo -e "  ✅ Ping: ${YELLOW}${avg_latency} ms${NC}"
    else
        echo -e "  ❌ Ping failed over tunnel"
        echo "     (This may be expected if tunnel not fully established)"
    fi
    
    # iperf3 over tunnel
    print_step "Starting iperf3 server on Edge B..."
    ssh_cmd "$NODE_B" "nohup iperf3 -s -p 5201 --bind $VIP_B > iperf_server.log 2>&1 &"
    sleep 2
    
    print_step "Running iperf3 throughput test ($TEST_DURATION seconds) over tunnel..."
    local iperf_json
    iperf_json=$(ssh_cmd "$NODE_A" "iperf3 -c $VIP_B -p 5201 -t $TEST_DURATION --json 2>/dev/null" || echo "{}")
    
    local throughput_bps
    throughput_bps=$(echo "$iperf_json" | jq '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
    local throughput_mbps
    throughput_mbps=$(echo "scale=2; $throughput_bps / 1000000" | bc 2>/dev/null || echo "N/A")
    
    if [[ "$throughput_mbps" != "N/A" && "$throughput_mbps" != "0" ]]; then
        echo -e "  ✅ Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
    else
        echo -e "  ❌ iperf3 test failed (tunnel may not be active)"
    fi
    
    # Collect logs
    print_step "Collecting logs..."
    ssh_cmd "$NUCLEUS" "cat ~/omni-test/nucleus.log" > "$RESULTS_DIR/nucleus.log" 2>/dev/null || true
    ssh_cmd "$NODE_A" "cat ~/omni-test/edge_a.log" > "$RESULTS_DIR/edge_a.log" 2>/dev/null || true
    ssh_cmd "$NODE_B" "cat ~/omni-test/edge_b.log" > "$RESULTS_DIR/edge_b.log" 2>/dev/null || true
    
    # Create results JSON
    cat > "$result_file" << EOF
{
  "timestamp": "$timestamp",
  "architecture": "3-node (Nucleus + 2 Edges)",
  "nucleus": "$NUCLEUS",
  "edge_a": {"public_ip": "$NODE_A", "vip": "$VIP_A"},
  "edge_b": {"public_ip": "$NODE_B", "vip": "$VIP_B"},
  "cluster": "$CLUSTER_NAME",
  "authenticated": $([ -n "$CLUSTER_SECRET" ] && echo "true" || echo "false"),
  "test_duration_sec": $TEST_DURATION,
  "results": {
    "tunnel_ping_ms": "$avg_latency",
    "tunnel_throughput_mbps": $throughput_mbps
  }
}
EOF
    
    # Cleanup
    print_step "Cleaning up remote processes..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo pkill -f omni-daemon || true; pkill -f iperf3 || true" 2>/dev/null || true
    done
    
    # Summary
    print_header "Test Complete"
    
    echo -e "┌──────────────────────────────────────────────┐"
    echo -e "│  ${GREEN}3-NODE P2P TEST RESULTS${NC}                      │"
    echo -e "├──────────────────────────────────────────────┤"
    echo -e "│  Nucleus:     $NUCLEUS"
    echo -e "│  Edge A:      $NODE_A → $VIP_A"
    echo -e "│  Edge B:      $NODE_B → $VIP_B"
    echo -e "├──────────────────────────────────────────────┤"
    echo -e "│  Tunnel Latency:    ${YELLOW}${avg_latency} ms${NC}"
    echo -e "│  Tunnel Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
    echo -e "└──────────────────────────────────────────────┘"
    echo ""
    echo -e "Results saved to: ${CYAN}$result_file${NC}"
    echo -e "Logs: ${CYAN}$RESULTS_DIR/*.log${NC}"
}

# =============================================================================
# Main
# =============================================================================

SKIP_BUILD=false
SKIP_DEPLOY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --nucleus)
            NUCLEUS="$2"
            shift 2
            ;;
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
        --cluster)
            CLUSTER_NAME="$2"
            shift 2
            ;;
        --secret)
            CLUSTER_SECRET="$2"
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
if [[ -z "$NUCLEUS" || -z "$NODE_A" || -z "$NODE_B" ]]; then
    print_error "--nucleus, --node-a, and --node-b are all required"
    show_help
    exit 1
fi

print_header "OmniNervous 3-Node Cloud Test"
echo "Nucleus:   $NUCLEUS (signaling)"
echo "Edge A:    $NODE_A → VIP $VIP_A"
echo "Edge B:    $NODE_B → VIP $VIP_B"
echo "Cluster:   $CLUSTER_NAME"
echo "Auth:      $([ -n "$CLUSTER_SECRET" ] && echo "PSK enabled" || echo "OPEN (⚠️)")"

# Build locally if needed
if ! $SKIP_BUILD; then
    print_header "Building Binary for Linux x86_64"
    
    # Try cross-compilation first (requires cross-compilation toolchain)
    if cargo build -p omni-daemon --release --target x86_64-unknown-linux-gnu 2>/dev/null; then
        BINARY_PATH="./target/x86_64-unknown-linux-gnu/release/omni-daemon"
        echo "✅ Cross-compiled for Linux x86_64"
    else
        echo "⚠️  Cross-compilation failed, using native build"
        echo "   Install: rustup target add x86_64-unknown-linux-gnu"
        echo "   macOS: brew install SergioBenitez/osxct/x86_64-unknown-linux-gnu"
        cargo build -p omni-daemon --release
        BINARY_PATH="./target/release/omni-daemon"
        echo "⚠️  WARNING: Native binary may not work on Linux cloud instances!"
    fi
fi

# Run test sequence
preflight_check

if ! $SKIP_DEPLOY; then
    deploy_binaries
fi

run_test

echo -e "\n${GREEN}✅ 3-Node cloud test completed!${NC}"
