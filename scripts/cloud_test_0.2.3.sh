#!/bin/bash
# =============================================================================
# OmniNervous Cloud-to-Cloud Test Orchestrator (v0.2.3 - Custom Noise Protocol)
# Run from LOCAL machine, orchestrates tests between cloud instances
# Architecture: Nucleus (signaling) + Edge A + Edge B (Custom Noise VPN)
#
# NOTE: This script tests the v0.2.3 Custom Noise protocol (NOT WireGuard)
#       Uses binaries: omninervous-0.2.3-linux-amd64, omninervous-0.2.3-linux-arm64
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
STUN_SERVERS=""
CIPHER="aesgcm"  # Default to AES-GCM for best performance on cloud instances

show_help() {
    cat << EOF
OmniNervous v0.2.3 Cloud Test Orchestrator (Custom Noise Protocol)

Architecture:
   ┌──────────┐      ┌──────────┐      ┌──────────┐
   │ Nucleus  │◄────►│  Edge A  │◄────►│  Edge B  │
   │ Signaling│      │ $VIP_A │      │ $VIP_B │
   └──────────┘      └──────────┘      └──────────┘

   Data Plane: Custom Noise_IKpsk1 (ChaCha20-Poly1305 or AES-256-GCM)
   Signaling:  HMAC-SHA256 authenticated (v0.2.3+)

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
  --secret        Cluster secret (min 16 chars, required for v0.2.3)
  --cipher        Cipher type: aesgcm or chachapoly (default: aesgcm)
  --stun          Custom STUN server(s) for edge nodes
  --skip-deploy   Skip binary deployment
  --help          Show this help

Environment Variables:
  SSH_USER        SSH username
  OMNI_PORT       UDP port
  CLUSTER_SECRET  Cluster authentication secret

  Example:
    $0 --nucleus 104.x.x.x --node-a 54.x.x.x --node-b 35.x.x.x \\
       --ssh-key ~/.ssh/cloud.pem --secret "my-secure-secret-16" --cipher aesgcm

Prerequisites:
   - iperf3 installed on edge nodes
   - UDP port $OMNI_PORT open in firewalls
   - SSH access with key authentication
   - Root access for TUN interface creation
   - TUN kernel module (modprobe tun)

Binary Requirements:
   - omninervous-0.2.3-linux-amd64 (for x86_64 nodes)
   - omninervous-0.2.3-linux-arm64 (for ARM64 nodes)
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
    
    # Check for local dependencies
    print_step "Checking local dependencies..."
    for cmd in ssh scp jq bc file; do
        if which "$cmd" &>/dev/null; then
            echo -e "  ✅ Local $cmd found"
        else
            echo -e "  ❌ Local $cmd NOT found. Please install it."
            errors=$((errors + 1))
        fi
    done

    # Get scripts directory
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check for v0.2.3 binaries
    local LINUX_AMD64="$SCRIPT_DIR/omninervous-0.2.3-linux-amd64"
    local LINUX_ARM64="$SCRIPT_DIR/omninervous-0.2.3-linux-arm64"
    local found_binary=false
    
    if [[ -f "$LINUX_AMD64" ]]; then
        if file "$LINUX_AMD64" | grep -q "ELF 64-bit.*x86-64"; then
            local binary_size
            binary_size=$(ls -lh "$LINUX_AMD64" | awk '{print $5}')
            echo -e "✅ v0.2.3 AMD64 binary found: $(basename "$LINUX_AMD64") ($binary_size)"
            found_binary=true
        else
            echo -e "⚠️  AMD64 binary exists but architecture mismatch"
        fi
    fi
    
    if [[ -f "$LINUX_ARM64" ]]; then
        if file "$LINUX_ARM64" | grep -q "ELF 64-bit.*aarch64\|ARM aarch64"; then
            local binary_size
            binary_size=$(ls -lh "$LINUX_ARM64" | awk '{print $5}')
            echo -e "✅ v0.2.3 ARM64 binary found: $(basename "$LINUX_ARM64") ($binary_size)"
            found_binary=true
        else
            echo -e "⚠️  ARM64 binary exists but architecture mismatch"
        fi
    fi
    
    if [[ "$found_binary" == "false" ]]; then
        echo -e "❌ No v0.2.3 binaries found in $SCRIPT_DIR"
        echo "   Required: omninervous-0.2.3-linux-amd64 and/or omninervous-0.2.3-linux-arm64"
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
    
    # Check iperf3 on edge nodes (will be installed if missing)
    print_step "Checking iperf3 and sudo on edge nodes..."
    for node in "$NODE_A" "$NODE_B"; do
        if ssh_cmd "$node" "which iperf3" &>/dev/null; then
            echo -e "  ✅ iperf3 installed on $node"
        else
            echo -e "  ⚠️ iperf3 not installed on $node (will be installed)"
        fi
        
        if ssh_cmd "$node" "sudo -n true" &>/dev/null; then
            echo -e "  ✅ Passwordless sudo available on $node"
        else
            echo -e "  ⚠️  Sudo might require password on $node (script may hang)"
        fi
    done
    
    # Check networking tools on edge nodes (TUN module, not WireGuard for v0.2.3)
    print_step "Checking networking tools (iproute2, TUN support) on edge nodes..."
    for node in "$NODE_A" "$NODE_B"; do
        if ssh_cmd "$node" "which ip" &>/dev/null; then
            echo -e "  ✅ ip command found on $node"
        else
            echo -e "  ⚠️ ip command NOT found on $node (will be installed)"
        fi
        
        # Check TUN device availability
        if ssh_cmd "$node" "test -c /dev/net/tun" &>/dev/null; then
            echo -e "  ✅ TUN device available on $node"
        else
            echo -e "  ⚠️ TUN device not found on $node (will try modprobe)"
        fi
    done

    if [[ $errors -gt 0 ]]; then
        print_error "Pre-flight checks failed with $errors errors"
        exit 1
    fi
    
    echo -e "\n${GREEN}All pre-flight checks passed!${NC}"
}

# =============================================================================
# Install Missing Dependencies
# =============================================================================

install_dependencies() {
    print_header "Installing Missing Dependencies"
    
    for node in "$NODE_A" "$NODE_B"; do
        print_step "Checking and installing dependencies on $node..."
        
        # Detect package manager
        local pkg_manager=""
        if ssh_cmd "$node" "which apt-get" &>/dev/null; then
            pkg_manager="apt"
        elif ssh_cmd "$node" "which dnf" &>/dev/null; then
            pkg_manager="dnf"
        elif ssh_cmd "$node" "which yum" &>/dev/null; then
            pkg_manager="yum"
        else
            echo -e "  ⚠️ Unknown package manager on $node, skipping auto-install"
            continue
        fi
        echo -e "  📦 Detected package manager: $pkg_manager"
        
        # Ensure TUN module is loaded (v0.2.3 uses userspace TUN, not kernel WireGuard)
        echo -e "  ⚙️ Ensuring TUN module is loaded..."
        ssh_cmd "$node" "sudo modprobe tun" || echo "  ⚠️ Failed to modprobe tun (might be builtin)"
        
        # Install iperf3
        if ! ssh_cmd "$node" "which iperf3" &>/dev/null; then
            echo -e "  📥 Installing iperf3..."
            case $pkg_manager in
                apt)
                    ssh_cmd "$node" "sudo apt-get update -qq && sudo apt-get install -y -qq iperf3"
                    ;;
                dnf|yum)
                    ssh_cmd "$node" "sudo $pkg_manager install -y iperf3"
                    ;;
            esac
        else
            echo -e "  ✅ iperf3 already installed"
        fi
        
        # Install iproute2, jq, bc
        ssh_cmd "$node" "which ip &>/dev/null || (sudo $pkg_manager update -qq 2>/dev/null; sudo $pkg_manager install -y iproute2 || sudo $pkg_manager install -y iproute || true)" || true
        ssh_cmd "$node" "which jq &>/dev/null || (sudo $pkg_manager install -y jq || true)" || true
        ssh_cmd "$node" "which bc &>/dev/null || (sudo $pkg_manager install -y bc || true)" || true
        
        echo -e "  ✅ Dependencies installed on $node"
    done
    
    echo -e "\n${GREEN}Dependency installation complete!${NC}"
}

# =============================================================================
# Deploy Pre-built Binary (v0.2.3)
# =============================================================================

deploy_binaries() {
    print_header "Deploying v0.2.3 Binary"
    
    # Get the scripts directory
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Define v0.2.3 binaries
    local LINUX_AMD64="$SCRIPT_DIR/omninervous-0.2.3-linux-amd64"
    local LINUX_ARM64="$SCRIPT_DIR/omninervous-0.2.3-linux-arm64"
    
    # Check at least one exists
    if [[ ! -f "$LINUX_AMD64" && ! -f "$LINUX_ARM64" ]]; then
        print_error "No v0.2.3 binaries found in $SCRIPT_DIR"
        echo "   Required: omninervous-0.2.3-linux-amd64 and/or omninervous-0.2.3-linux-arm64"
        exit 1
    fi
    
    # Deploy to all nodes
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        print_step "Deploying to $node..."
        
        # Detect remote architecture
        local remote_arch
        remote_arch=$(ssh_cmd "$node" "uname -m")
        
        local TARGET_BINARY=""
        if [[ "$remote_arch" == "x86_64" || "$remote_arch" == "amd64" ]]; then
            TARGET_BINARY="$LINUX_AMD64"
            echo -e "  🖥️  Architecture: x86_64"
        elif [[ "$remote_arch" == "aarch64" || "$remote_arch" == "arm64" ]]; then
            TARGET_BINARY="$LINUX_ARM64"
            echo -e "  🖥️  Architecture: ARM64"
        else
            echo -e "  ⚠️ Unknown architecture: $remote_arch, trying AMD64"
            TARGET_BINARY="$LINUX_AMD64"
        fi
        
        if [[ ! -f "$TARGET_BINARY" ]]; then
            # Fallback to whatever is available
            if [[ -f "$LINUX_AMD64" ]]; then
                TARGET_BINARY="$LINUX_AMD64"
            elif [[ -f "$LINUX_ARM64" ]]; then
                TARGET_BINARY="$LINUX_ARM64"
            else
                print_error "No suitable binary for $node"
                continue
            fi
            echo -e "  ⚠️ Using fallback binary: $(basename "$TARGET_BINARY")"
        fi
        
        # Clean up and create remote directory
        ssh_cmd "$node" "rm -rf ~/omni-test && mkdir -p ~/omni-test"
        
        # Copy binary
        scp_to "$TARGET_BINARY" "$node" "~/omni-test/omninervous"
        
        # Make executable
        ssh_cmd "$node" "chmod +x ~/omni-test/omninervous"
        
        echo -e "✅ Deployed v0.2.3 to $node ($(basename "$TARGET_BINARY"))"
    done
}

# =============================================================================
# Run Test
# =============================================================================

run_test() {
    print_header "Running 3-Node Custom Noise Test (v0.2.3)"
    
    # Create local results directory
    mkdir -p "$RESULTS_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local result_file="$RESULTS_DIR/cloud_test_v0.2.3_$timestamp.json"
    
    # Build secret args (required for v0.2.3 HMAC signaling)
    local secret_args=""
    if [[ -n "$CLUSTER_SECRET" ]]; then
        if [[ ${#CLUSTER_SECRET} -lt 16 ]]; then
            print_error "Secret must be at least 16 characters"
            exit 1
        fi
        secret_args="--secret '$CLUSTER_SECRET'"
        echo -e "🔐 Cluster authentication enabled (HMAC-SHA256)"
    else
        echo -e "⚠️  No secret specified, running in OPEN mode (not recommended)"
    fi

    # Build STUN args
    local stun_args=""
    if [[ -n "$STUN_SERVERS" ]]; then
        stun_args="--stun '$STUN_SERVERS'"
        echo -e "🌐 Custom STUN discovery enabled"
    fi
    
    # Build cipher args
    local cipher_args="--cipher $CIPHER"
    echo -e "🔒 Cipher: $CIPHER"
    
    # Kill any existing processes
    print_step "Cleaning up old processes and logs..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo pkill -9 -f omninervous 2>/dev/null; sudo pkill -9 -f iperf3 2>/dev/null; \
                         if command -v fuser &>/dev/null; then sudo fuser -k $OMNI_PORT/udp 2>/dev/null; fi; \
                         # Delete any TUN interface starting with 'omni'
                         for dev in \$(ip link show 2>/dev/null | grep -o 'omni[0-9]*'); do \
                            sudo ip link set \$dev down 2>/dev/null || true; \
                            sudo ip link delete \$dev 2>/dev/null || true; \
                         done; \
                         sudo rm -f /tmp/omni-*.log" || true
    done
    sleep 3
    
    # Start Nucleus (signaling server)
    print_step "Starting Nucleus on $NUCLEUS..."
    ssh_cmd "$NUCLEUS" "sudo sh -c \"RUST_LOG=debug nohup \$HOME/omni-test/omninervous --mode nucleus --port $OMNI_PORT $secret_args > /tmp/omni-nucleus.log 2>&1 &\" < /dev/null"
    sleep 2
    
    # Start Edge A with VIP (use same port for P2P)
    print_step "Starting Edge A on $NODE_A (VIP: $VIP_A)..."
    ssh_cmd "$NODE_A" "sudo sh -c \"RUST_LOG=info nohup \$HOME/omni-test/omninervous --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args $stun_args --vip $VIP_A --port $OMNI_PORT > /tmp/omni-edge-a.log 2>&1 &\" < /dev/null"
    sleep 2

    # Start Edge B with VIP (use same port for P2P)
    print_step "Starting Edge B on $NODE_B (VIP: $VIP_B)..."
    ssh_cmd "$NODE_B" "sudo sh -c \"RUST_LOG=info nohup \$HOME/omni-test/omninervous --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args $stun_args --vip $VIP_B --port $OMNI_PORT > /tmp/omni-edge-b.log 2>&1 &\" < /dev/null"
    sleep 2
    
    # Wait for tunnel establishment (heartbeat cycle is 30s)
    print_step "Waiting for Custom Noise tunnel establishment (60s for peer discovery + handshake)..."
    echo "   This includes registration, heartbeat + delta update, and Noise handshake."
    sleep 60
    
    # Check if daemons are running
    print_step "Checking daemon processes..."
    echo "Nucleus process:"
    ssh_cmd "$NUCLEUS" "pgrep -a omninervous || echo 'NOT RUNNING'"
    echo "Edge A process:"
    ssh_cmd "$NODE_A" "pgrep -a omninervous || echo 'NOT RUNNING'"
    echo "Edge B process:"
    ssh_cmd "$NODE_B" "pgrep -a omninervous || echo 'NOT RUNNING'"
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
    baseline_iperf_json=$(ssh_cmd "$NODE_A" "iperf3 -c $NODE_B -p 5201 -t $TEST_DURATION -M 1300 -P 2 --json 2>/dev/null" || echo "{}")
    
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
    
    # Network tests over Custom Noise tunnel
    print_header "VPN Tunnel Metrics (Custom Noise: A → B)"
    echo "   These tests use VPN IPs ($VIP_A → $VIP_B) over encrypted tunnel."
    echo "   Protocol: Noise_IKpsk1 + $CIPHER"
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
        echo "     Check logs for peer discovery errors"
    fi
    
    # Check TUN interfaces are up before iperf3
    print_step "Verifying TUN interfaces before iperf3..."
    local wg_a_up=false
    local wg_b_up=false
    if ssh_cmd "$NODE_A" "ip addr show omni0 2>/dev/null | grep -E -q 'state UP|state UNKNOWN'"; then
        wg_a_up=true
        echo "  ✅ Edge A omni0: UP"
    else
        echo "  ⚠️ Edge A omni0: DOWN or not found"
    fi
    if ssh_cmd "$NODE_B" "ip addr show omni0 2>/dev/null | grep -E -q 'state UP|state UNKNOWN'"; then
        wg_b_up=true
        echo "  ✅ Edge B omni0: UP"
    else
        echo "  ⚠️ Edge B omni0: DOWN or not found"
    fi

    # Initialize throughput
    local throughput_mbps="0"
    
    # iperf3 over tunnel (only if TUN is up)
    if [[ "$wg_a_up" == "true" && "$wg_b_up" == "true" ]]; then
        print_step "Starting iperf3 server on Edge B..."
        ssh_cmd "$NODE_B" "nohup iperf3 -s -p 5201 > iperf_server.log 2>&1 &"
        sleep 3
    
        print_step "Running iperf3 throughput test ($TEST_DURATION seconds) over tunnel..."
        local iperf_json
        iperf_json=$(ssh_cmd "$NODE_A" "iperf3 -c $VIP_B -p 5201 -t $TEST_DURATION -M 1300 -P 2 --json 2>/dev/null" || echo "{}")
        
        local throughput_bps
        throughput_bps=$(echo "$iperf_json" | jq '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
        throughput_mbps=$(echo "scale=2; $throughput_bps / 1000000" | bc 2>/dev/null || echo "N/A")
        
        if [[ "$throughput_mbps" != "N/A" && "$throughput_mbps" != "0" && "$throughput_mbps" != ".00" ]]; then
            echo -e "  ✅ Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
        else
            echo -e "  ❌ iperf3 test failed (tunnel may not be active)"
            throughput_mbps="0"
        fi
    else
        echo -e "  ⚠️ Skipping iperf3 test - TUN interfaces not ready"
    fi
    
    # Calculate efficiency
    local efficiency="N/A"
    if [[ "$baseline_throughput_mbps" != "N/A" && "$throughput_mbps" != "0" && "$throughput_mbps" != "N/A" ]]; then
        efficiency=$(echo "scale=1; $throughput_mbps / $baseline_throughput_mbps * 100" | bc 2>/dev/null || echo "N/A")
    fi
    
    # Collect logs
    print_step "Collecting logs..."
    ssh_cmd "$NUCLEUS" "cat /tmp/omni-nucleus.log" > "$RESULTS_DIR/nucleus_v0.2.3.log" 2>/dev/null || true
    ssh_cmd "$NODE_A" "cat /tmp/omni-edge-a.log" > "$RESULTS_DIR/edge_a_v0.2.3.log" 2>/dev/null || true
    ssh_cmd "$NODE_B" "cat /tmp/omni-edge-b.log" > "$RESULTS_DIR/edge_b_v0.2.3.log" 2>/dev/null || true
    
    # Create results JSON
    cat > "$result_file" << EOF
{
  "version": "0.2.3",
  "protocol": "Custom Noise (Noise_IKpsk1)",
  "cipher": "$CIPHER",
  "timestamp": "$timestamp",
  "architecture": "3-node (Nucleus + Custom Noise Edges)",
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
  "custom_noise_tunnel": {
    "ping_ms": "$avg_latency",
    "throughput_mbps": "$throughput_mbps",
    "efficiency_percent": "$efficiency"
  }
}
EOF
    
    # Cleanup
    print_step "Cleaning up remote processes and interfaces..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo pkill -9 -f omninervous 2>/dev/null || true; pkill -f iperf3 2>/dev/null || true; \
                         # Delete TUN interfaces
                         for dev in \$(ip link show 2>/dev/null | grep -o 'omni[0-9]*'); do \
                            sudo ip link set \$dev down 2>/dev/null || true; \
                            sudo ip link delete \$dev 2>/dev/null || true; \
                         done" 2>/dev/null || true
    done
    
    # Summary
    print_header "Test Complete"
    
    echo -e "┌─────────────────────────────────────────────────────────┐"
    echo -e "│  ${GREEN}v0.2.3 CUSTOM NOISE TEST RESULTS${NC}                       │"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  Protocol:    Noise_IKpsk1 + $CIPHER"
    echo -e "│  Nucleus:     $NUCLEUS"
    echo -e "│  Edge A:      $NODE_A → $VIP_A"
    echo -e "│  Edge B:      $NODE_B → $VIP_B"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  ${CYAN}BASELINE (Public IP)${NC}                                    │"
    echo -e "│    Latency:    ${YELLOW}${baseline_latency} ms${NC}"
    echo -e "│    Throughput: ${YELLOW}${baseline_throughput_mbps} Mbps${NC}"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  ${CYAN}CUSTOM NOISE TUNNEL${NC}                                     │"
    echo -e "│    Latency:    ${YELLOW}${avg_latency} ms${NC}"
    echo -e "│    Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
    echo -e "│    Efficiency: ${YELLOW}${efficiency}%${NC}"
    echo -e "└─────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "Results saved to: ${CYAN}$result_file${NC}"
    echo -e "Logs: ${CYAN}$RESULTS_DIR/*_v0.2.3.log${NC}"
}

# =============================================================================
# Main
# =============================================================================

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
        --stun)
            STUN_SERVERS="$2"
            shift 2
            ;;
        --cipher)
            CIPHER="$2"
            shift 2
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

# Validate cipher
if [[ "$CIPHER" != "aesgcm" && "$CIPHER" != "chachapoly" && "$CIPHER" != "chacha" ]]; then
    print_error "Invalid cipher: $CIPHER (must be aesgcm, chachapoly, or chacha)"
    exit 1
fi

print_header "OmniNervous v0.2.3 Cloud Test (Custom Noise Protocol)"
echo "Nucleus:   $NUCLEUS (signaling)"
echo "Edge A:    $NODE_A → VIP $VIP_A"
echo "Edge B:    $NODE_B → VIP $VIP_B"
echo "Cluster:   $CLUSTER_NAME"
echo "Cipher:    $CIPHER"
echo "Auth:      $([ -n "$CLUSTER_SECRET" ] && echo "HMAC-SHA256 enabled" || echo "OPEN (⚠️)")"

# Run test sequence
preflight_check
install_dependencies

if ! $SKIP_DEPLOY; then
    deploy_binaries
fi

run_test

echo -e "\n${GREEN}✅ v0.2.3 Custom Noise cloud test completed!${NC}"