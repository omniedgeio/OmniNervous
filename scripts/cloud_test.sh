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

# Virtual IPs for P2P tunnel
VIP_A="10.200.0.10"
VIP_B="10.200.0.20"
CLUSTER_NAME="${CLUSTER_NAME:-omni-test}"
CLUSTER_SECRET="${CLUSTER_SECRET:-}"
CIPHER="${CIPHER:-chacha}"

show_help() {
    cat << EOF
OmniNervous 3-Node Cloud Test Orchestrato

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
   --cipher        Cipher: 'aes' (AES256-GCM) or 'chacha' (ChaCha20-Poly1305, default)
  --skip-build    Skip local cargo build
  --skip-deploy   Skip binary deployment
  --help          Show this help

Environment Variables:
  SSH_USER        SSH username
  OMNI_PORT       UDP port
  CLUSTER_SECRET  Cluster authentication secret

 Example:
   $0 --nucleus 104.x.x.x --node-a 54.x.x.x --node-b 35.x.x.x \\
      --ssh-key ~/.ssh/cloud.pem --secret "my-secure-secret-16" --cipher aes

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
    print_header "Pre-flight Checks"
    
    local errors=0
    
    # Get scripts directory
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check for pre-built binary
    local LINUX_BINARY="$SCRIPT_DIR/omni-daemon-linux-amd64"
    if [[ -f "$LINUX_BINARY" ]]; then
        # Verify it's actually an x86_64 ELF binary
        if file "$LINUX_BINARY" | grep -q "ELF 64-bit.*x86-64"; then
            local binary_size
            binary_size=$(ls -lh "$LINUX_BINARY" | awk '{print $5}')
            echo -e "✅ Pre-built binary found: $LINUX_BINARY ($binary_size)"
            echo "   Architecture: x86-64 ELF (correct for cloud deployment)"
        else
            echo -e "❌ Binary exists but is NOT x86-64 ELF!"
            echo "   Found: $(file "$LINUX_BINARY" | cut -d: -f2)"
            echo "   Run: ./scripts/build_linux_amd64.sh to build correct binary"
            errors=$((errors + 1))
        fi
    else
        echo -e "❌ Pre-built binary not found: $LINUX_BINARY"
        echo ""
        echo "   To build the binary, run:"
        echo "   ${CYAN}./scripts/build_linux_amd64.sh${NC}"
        echo ""
        echo "   This will cross-compile for linux-amd64 using Docker."
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
# Deploy Pre-built Binary
# =============================================================================

deploy_binaries() {
    print_header "Deploying Binary"
    
    # Get the scripts directory
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check for pre-built binary in same folde
    local LINUX_BINARY="$SCRIPT_DIR/omni-daemon-linux-amd64"
    
    if [ ! -f "$LINUX_BINARY" ]; then
        print_error "Pre-built binary not found: $LINUX_BINARY"
        echo "   Download from GitHub releases or build with:"
        echo "   docker build -t omni-daemon:latest . && docker cp \$(docker create omni-daemon:latest):/usr/local/bin/omni-daemon $LINUX_BINARY"
        exit 1
    fi
    
    echo -e "✅ Using pre-built binary: $LINUX_BINARY"
    file "$LINUX_BINARY" 2>/dev/null | grep -q "x86-64" && echo "   Architecture: x86_64" || echo "   Architecture: $(file "$LINUX_BINARY" | awk -F: '{print $2}')"
    
    # Deploy to all nodes
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        print_step "Deploying to $node..."
        
        # Clean up and create remote directory
        ssh_cmd "$node" "rm -rf ~/omni-test && mkdir -p ~/omni-test"
        
        # Copy binary
        scp_to "$LINUX_BINARY" "$node" "~/omni-test/omni-daemon"
        
        # Make executable
        ssh_cmd "$node" "chmod +x ~/omni-test/omni-daemon"
        
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
        secret_args="--secret '$CLUSTER_SECRET'"
        echo -e "🔐 Cluster authentication enabled"
    else
        echo -e "⚠️  No secret specified, running in OPEN mode"
    fi
    
    # Kill any existing processes
    print_step "Cleaning up old processes and logs..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo pkill -9 -f omni-daemon 2>/dev/null; sudo pkill -9 -f iperf3 2>/dev/null; sudo rm -f /tmp/omni-*.log" || true
    done
    sleep 2
    
    # Start Nucleus (signaling server)
    print_step "Starting Nucleus on $NUCLEUS..."
    ssh_cmd "$NUCLEUS" "sudo sh -c \"RUST_LOG=debug nohup ./omni-test/omni-daemon --mode nucleus --port $OMNI_PORT > /tmp/omni-nucleus.log 2>&1 &\" < /dev/null"
    sleep 2
    
    # Start Edge A with VIP
    print_step "Starting Edge A on $NODE_A (VIP: $VIP_A)..."
    ssh_cmd "$NODE_A" "sudo sh -c \"RUST_LOG=info nohup ./omni-test/omni-daemon --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args --vip $VIP_A --port $OMNI_PORT --cipher $CIPHER > /tmp/omni-edge-a.log 2>&1 &\" < /dev/null"
    sleep 2
    
    # Start Edge B with VIP
    print_step "Starting Edge B on $NODE_B (VIP: $VIP_B)..."
    ssh_cmd "$NODE_B" "sudo sh -c \"RUST_LOG=info nohup ./omni-test/omni-daemon --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args --vip $VIP_B --port $((OMNI_PORT + 1)) --cipher $CIPHER > /tmp/omni-edge-b.log 2>&1 &\" < /dev/null"
    sleep 2
    
    # Wait for P2P tunnel establishment (heartbeat cycle is 30s)
    print_step "Waiting for P2P tunnel establishment (60s for heartbeat cycle)..."
    echo "   This includes registration, heartbeat + delta update, and handshake."
    sleep 60
    
    # Check if daemons are running
    print_step "Checking daemon processes..."
    echo "Nucleus process:"
    ssh_cmd "$NUCLEUS" "pgrep -a omni-daemon || echo 'NOT RUNNING'"
    echo "Edge A process:"
    ssh_cmd "$NODE_A" "pgrep -a omni-daemon || echo 'NOT RUNNING'"
    echo "Edge B process:"
    ssh_cmd "$NODE_B" "pgrep -a omni-daemon || echo 'NOT RUNNING'"
    echo ""
    
    # Show logs for debugging
    print_step "Daemon logs (last 15 lines from /tmp)..."
    echo "--- Nucleus log ---"
    ssh_cmd "$NUCLEUS" "tail -15 /tmp/omni-nucleus.log 2>/dev/null || echo 'No log in /tmp/omni-nucleus.log'"
    echo ""
    echo "--- Edge A log ---"
    ssh_cmd "$NODE_A" "tail -15 /tmp/omni-edge-a.log 2>/dev/null || echo 'No log in /tmp/omni-edge-a.log'"
    echo ""
    echo "--- Edge B log ---"
    ssh_cmd "$NODE_B" "tail -15 /tmp/omni-edge-b.log 2>/dev/null || echo 'No log in /tmp/omni-edge-b.log'"
    echo ""
    
    # ==========================================================================
    # BASELINE TESTS: Public IP (before VPN comparison)
    # ==========================================================================
    print_header "Baseline Network Metrics (Public IP: A → B)"
    echo "   These tests use public IPs WITHOUT the VPN tunnel."
    echo "   Results will be compared against VPN tunnel performance."
    echo ""
    
    # Baseline ping test (public IP)
    print_step "Baseline ping over public IP ($NODE_A → $NODE_B)..."
    local baseline_ping_output
    baseline_ping_output=$(ssh_cmd "$NODE_A" "ping -c 5 -W 5 $NODE_B 2>&1" || echo "PING_FAILED")
    local baseline_latency="N/A"
    if echo "$baseline_ping_output" | grep -q "rtt"; then
        baseline_latency=$(echo "$baseline_ping_output" | grep "rtt" | awk -F'/' '{print $5}')
        echo -e "  ✅ Baseline Ping: ${YELLOW}${baseline_latency} ms${NC}"
    else
        echo -e "  ⚠️ Baseline ping failed (firewall may be blocking ICMP)"
    fi
    
    # Baseline iperf3 test (public IP)
    print_step "Starting iperf3 server on Edge B (public IP)..."
    ssh_cmd "$NODE_B" "pkill iperf3 2>/dev/null; nohup iperf3 -s -p 5201 > /tmp/iperf_baseline.log 2>&1 &"
    sleep 3
    
    print_step "Baseline iperf3 throughput test ($TEST_DURATION seconds) over public IP..."
    local baseline_iperf_json
    baseline_iperf_json=$(ssh_cmd "$NODE_A" "iperf3 -c $NODE_B -p 5201 -t $TEST_DURATION --json 2>/dev/null" || echo "{}")
    
    local baseline_throughput_bps
    baseline_throughput_bps=$(echo "$baseline_iperf_json" | jq '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
    local baseline_throughput_mbps
    baseline_throughput_mbps=$(echo "scale=2; $baseline_throughput_bps / 1000000" | bc 2>/dev/null || echo "N/A")
    
    if [[ "$baseline_throughput_mbps" != "N/A" && "$baseline_throughput_mbps" != "0" && "$baseline_throughput_mbps" != ".00" ]]; then
        echo -e "  ✅ Baseline Throughput: ${YELLOW}${baseline_throughput_mbps} Mbps${NC}"
    else
        echo -e "  ⚠️ Baseline iperf3 failed (port 5201 may be blocked)"
        baseline_throughput_mbps="N/A"
    fi
    
    # Stop baseline iperf3 serve
    ssh_cmd "$NODE_B" "pkill iperf3 2>/dev/null" || true
    
    # ==========================================================================
    # VPN TUNNEL TESTS
    # ==========================================================================
    
    # Check interfaces on edges
    print_step "Verifying TUN interfaces..."
    echo "Edge A interfaces:"
    ssh_cmd "$NODE_A" "ip addr show omni0 2>/dev/null || echo 'omni0 not found'"
    echo ""
    echo "Edge B interfaces:"
    ssh_cmd "$NODE_B" "ip addr show omni0 2>/dev/null || echo 'omni0 not found'"
    
    # Network tests over P2P tunnel
    print_header "VPN Tunnel Metrics (Encrypted P2P: A → B)"
    echo "   These tests use VPN IPs ($VIP_A → $VIP_B) over encrypted tunnel."
    echo ""
    # Ping test over tunnel with retry
    print_step "Ping over tunnel ($VIP_A → $VIP_B) with retries..."
    local ping_output=""
    local avg_latency="N/A"
    for attempt in 1 2 3; do
        echo "   Attempt $attempt/3..."
        ping_output=$(ssh_cmd "$NODE_A" "ping -c 5 -W 5 $VIP_B 2>&1" || echo "PING_FAILED")
        if echo "$ping_output" | grep -q "rtt"; then
            avg_latency=$(echo "$ping_output" | grep "rtt" | awk -F'/' '{print $5}')
            echo -e "  ✅ Ping: ${YELLOW}${avg_latency} ms${NC}"
            break
        else
            echo "   Ping failed, retrying in 10s..."
            sleep 10
        fi
    done
    if [[ "$avg_latency" == "N/A" ]]; then
        echo "     Diagnostics (IP):"
        ssh_cmd "$NODE_A" "ip addr show omni0" || true
        ssh_cmd "$NODE_B" "ip addr show omni0" || true
        echo "     Diagnostics (Route):"
        ssh_cmd "$NODE_A" "ip route" || true
        ssh_cmd "$NODE_B" "ip route" || true
        echo "     Check logs for handshake/session errors"
    fi
    
    # Check TUN interfaces are up before iperf3
    print_step "Verifying TUN interfaces before iperf3..."
    local tun_a_up=false
    local tun_b_up=false
    if ssh_cmd "$NODE_A" "ip addr show omni0 2>/dev/null | grep -E -q 'state UP|state UNKNOWN'"; then
        tun_a_up=true
        echo "  ✅ Edge A omni0: UP"
    else
        echo "  ⚠️ Edge A omni0: DOWN or not found"
    fi
    if ssh_cmd "$NODE_B" "ip addr show omni0 2>/dev/null | grep -E -q 'state UP|state UNKNOWN'"; then
        tun_b_up=true
        echo "  ✅ Edge B omni0: UP"
    else
        echo "  ⚠️ Edge B omni0: DOWN or not found"
    fi
    
    # iperf3 over tunnel (only if TUN is up)
    if [[ "$tun_a_up" == "true" && "$tun_b_up" == "true" ]]; then
        print_step "Starting iperf3 server on Edge B..."
        ssh_cmd "$NODE_B" "nohup iperf3 -s -p 5201 --bind $VIP_B > iperf_server.log 2>&1 &"
        sleep 3
    
        print_step "Running iperf3 throughput test ($TEST_DURATION seconds) over tunnel..."
        local iperf_json
        iperf_json=$(ssh_cmd "$NODE_A" "iperf3 -c $VIP_B -p 5201 -t $TEST_DURATION --json 2>/dev/null" || echo "{}")
        
        local throughput_bps
        throughput_bps=$(echo "$iperf_json" | jq '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
        local throughput_mbps
        throughput_mbps=$(echo "scale=2; $throughput_bps / 1000000" | bc 2>/dev/null || echo "N/A")
        
        if [[ "$throughput_mbps" != "N/A" && "$throughput_mbps" != "0" && "$throughput_mbps" != ".00" ]]; then
            echo -e "  ✅ Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
        else
            echo -e "  ❌ iperf3 test failed (tunnel may not be active)"
            throughput_mbps="0"
        fi
    else
        echo -e "  ⚠️ Skipping iperf3 test - TUN interfaces not ready"
        local throughput_mbps="0"
    fi
    
    # Collect logs
    print_step "Collecting logs..."
    ssh_cmd "$NUCLEUS" "cat /tmp/omni-nucleus.log" > "$RESULTS_DIR/nucleus.log" 2>/dev/null || true
    ssh_cmd "$NODE_A" "cat /tmp/omni-edge-a.log" > "$RESULTS_DIR/edge_a.log" 2>/dev/null || true
    ssh_cmd "$NODE_B" "cat /tmp/omni-edge-b.log" > "$RESULTS_DIR/edge_b.log" 2>/dev/null || true
    
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
  "baseline": {
    "ping_ms": "$baseline_latency",
    "throughput_mbps": "$baseline_throughput_mbps"
  },
  "vpn_tunnel": {
    "ping_ms": "$avg_latency",
    "throughput_mbps": "$throughput_mbps"
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
    
    echo -e "┌─────────────────────────────────────────────────────────┐"
    echo -e "│  ${GREEN}3-NODE P2P TEST RESULTS${NC}                                 │"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  Nucleus:     $NUCLEUS"
    echo -e "│  Edge A:      $NODE_A → $VIP_A"
    echo -e "│  Edge B:      $NODE_B → $VIP_B"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  ${CYAN}BASELINE (Public IP)${NC}                                    │"
    echo -e "│    Latency:    ${YELLOW}${baseline_latency} ms${NC}"
    echo -e "│    Throughput: ${YELLOW}${baseline_throughput_mbps} Mbps${NC}"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  ${CYAN}VPN TUNNEL (Encrypted P2P)${NC}                              │"
    echo -e "│    Latency:    ${YELLOW}${avg_latency} ms${NC}"
    echo -e "│    Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
    echo -e "└─────────────────────────────────────────────────────────┘"
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
        --cipher)
            CIPHER="$2"
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
echo "Cipher:    $CIPHER"

# Run test sequence
preflight_check

if ! $SKIP_DEPLOY; then
    deploy_binaries
fi

run_test

echo -e "\n${GREEN}✅ 3-Node cloud test completed!${NC}"

