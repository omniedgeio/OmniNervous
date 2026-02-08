#!/bin/bash
# =============================================================================
# OmniNervous Cloud-to-Cloud Test Orchestrator (v0.6.0)
# Run from LOCAL machine, orchestrates tests between cloud instances
# Architecture: Nucleus (signaling/relay) + Edge A + Edge B (WireGuard VPN)
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

# Virtual IPs for P2P tunnel (IPv4)
VIP_A="10.200.0.10"
VIP_B="10.200.0.20"
# Virtual IPs for P2P tunnel (IPv6 - ULA range)
VIP6_A="fd00:200::10"
VIP6_B="fd00:200::20"
TEST_IPV6=true
CLUSTER_NAME="${CLUSTER_NAME:-omni-test}"
CLUSTER_SECRET="${CLUSTER_SECRET:-}"
STUN_SERVERS=""
USERSPACE=false

show_help() {
    cat << EOF
OmniNervous 3-Node Cloud Test Orchestrator

Architecture:
   ┌──────────┐      ┌──────────┐      ┌──────────┐
   │ Nucleus  │◄────►│  Edge A  │◄────►│  Edge B │
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
  --no-ipv6       Skip IPv6 tests
  --cluster       Cluster name (default: omni-test)
  --secret        Cluster secret (min 16 chars, recommended)
  --userspace     Use userspace WireGuard mode (BoringTun)
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
   - Root access for WireGuard/TUN interface creation
   - WireGuard kernel module (if NOT using --userspace)
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
    
    # Check for pre-built binary
    local LINUX_BINARY="$SCRIPT_DIR/omninervous-linux-amd64"
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
    
    # Check networking tools on edge nodes (will be installed if missing)
    print_step "Checking networking tools (iproute2) on edge nodes..."
    for node in "$NODE_A" "$NODE_B"; do
        for cmd in ip; do
            if ssh_cmd "$node" "which $cmd" &>/dev/null; then
                echo -e "  ✅ $cmd command found on $node"
            else
                echo -e "  ⚠️ $cmd command NOT found on $node (will be installed)"
            fi
        done
        
        if [[ "$USERSPACE" == "false" ]]; then
            if ! ssh_cmd "$node" "which wg" &>/dev/null; then
                echo -e "  ⚠️ wg command NOT found on $node (will be installed for kernel mode)"
            else
                echo -e "  ✅ wg command found on $node"
            fi
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
        
        # Install wireguard-tools (for kernel mode)
        if [[ "$USERSPACE" == "false" ]]; then
            if ! ssh_cmd "$node" "which wg" &>/dev/null; then
                echo -e "  📥 Installing wireguard-tools..."
                case $pkg_manager in
                    apt)
                        ssh_cmd "$node" "sudo apt-get update -qq && sudo apt-get install -y -qq wireguard-tools"
                        ;;
                    dnf|yum)
                        ssh_cmd "$node" "sudo $pkg_manager install -y wireguard-tools"
                        ;;
                esac
            else
                echo -e "  ✅ wireguard-tools already installed"
            fi
        fi
        
        # Install iperf3
        if ! ssh_cmd "$node" "which iperf3" &>/dev/null; then
            echo -e "  📥 Installing iperf3..."
            case $pkg_manager in
                apt)
                    ssh_cmd "$node" "sudo apt-get install -y -qq iperf3"
                    ;;
                dnf|yum)
                    ssh_cmd "$node" "sudo $pkg_manager install -y iperf3"
                    ;;
            esac
        else
            echo -e "  ✅ iperf3 already installed"
        fi
        
        # Install netperf (optional, for latency testing)
        if ! ssh_cmd "$node" "which netperf" &>/dev/null; then
            echo -e "  📥 Installing netperf..."
            case $pkg_manager in
                apt)
                    ssh_cmd "$node" "sudo apt-get install -y -qq netperf" || echo "  ⚠️ netperf not available"
                    ;;
                dnf|yum)
                    ssh_cmd "$node" "sudo $pkg_manager install -y netperf" || echo "  ⚠️ netperf not available"
                    ;;
            esac
        else
            echo -e "  ✅ netperf already installed"
        fi
        
        # Install iproute2 (for ip command)
        if ! ssh_cmd "$node" "which ip" &>/dev/null; then
            echo -e "  📥 Installing iproute2..."
            case $pkg_manager in
                apt)
                    ssh_cmd "$node" "sudo apt-get install -y -qq iproute2"
                    ;;
                dnf|yum)
                    ssh_cmd "$node" "sudo $pkg_manager install -y iproute"
                    ;;
            esac
        else
            echo -e "  ✅ iproute2 already installed"
        fi
        
        echo -e "  ✅ Dependencies installed on $node"
    done
    
    echo -e "\n${GREEN}Dependency installation complete!${NC}"
}

# =============================================================================
# Deploy Pre-built Binary
# =============================================================================

deploy_binaries() {
    print_header "Deploying Binary"
    
    # Get the scripts directory
    local SCRIPT_DIR
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check for pre-built binary in same folder
    local LINUX_BINARY="$SCRIPT_DIR/omninervous-linux-amd64"
    
    if [ ! -f "$LINUX_BINARY" ]; then
        print_error "Pre-built binary not found: $LINUX_BINARY"
        echo "   Download from GitHub releases or build with:"
        echo "   docker build -t omninervous:latest . && docker cp \$(docker create omninervous:latest):/usr/local/bin/omninervous $LINUX_BINARY"
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
        scp_to "$LINUX_BINARY" "$node" "~/omni-test/omninervous"
        
        # Make executable
        ssh_cmd "$node" "chmod +x ~/omni-test/omninervous"
        
        echo -e "✅ Deployed to $node"
    done
}

# =============================================================================
# Run Test
# =============================================================================

run_test() {
    print_header "Running 3-Node WireGuard Test"
    
    # Create local results directory
    mkdir -p "$RESULTS_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local result_file="$RESULTS_DIR/cloud_test_$timestamp.json"
    
    # Build secret args
    local secret_args=""
    if [[ -n "$CLUSTER_SECRET" ]]; then
        if [[ ${#CLUSTER_SECRET} -lt 16 ]]; then
            print_error "Secret must be at least 16 characters (v0.6.0 requirement)"
            exit 1
        fi
        secret_args="--secret '$CLUSTER_SECRET'"
        echo -e "🔐 Cluster authentication enabled"
    else
        print_error "v0.6.0 REQUIRES --secret (min 16 chars) for signaling security."
        exit 1
    fi

    # Build STUN args
    local stun_args=""
    if [[ -n "$STUN_SERVERS" ]]; then
        stun_args="--stun '$STUN_SERVERS'"
        echo -e "🌐 Custom STUN discovery enabled"
    fi
    
    # Build userspace flag
    local user_flag=""
    if [[ "$USERSPACE" == "true" ]]; then
        user_flag="--userspace"
        echo -e "🚀 Using Userspace (BoringTun) mode"
    fi

    # Kill any existing processes
    print_step "Cleaning up old processes, interfaces and logs..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo pkill -9 -f omninervous 2>/dev/null; sudo pkill -9 -f iperf3 2>/dev/null; sudo ip link delete omni0 2>/dev/null; sudo rm -f /tmp/omni-*.log" || true
    done
    sleep 3
    
    # Start Nucleus (signaling server)
    print_step "Starting Nucleus on $NUCLEUS..."
    ssh_cmd "$NUCLEUS" "sudo sh -c \"RUST_LOG=debug nohup ./omni-test/omninervous --mode nucleus --port $OMNI_PORT $secret_args > /tmp/omni-nucleus.log 2>&1 &\" < /dev/null"
    sleep 2
    
    # Build IPv6 args if enabled
    local vip6_args_a=""
    local vip6_args_b=""
    if [[ "$TEST_IPV6" == "true" ]]; then
        vip6_args_a="--vip6 $VIP6_A"
        vip6_args_b="--vip6 $VIP6_B"
        echo -e "🌐 IPv6 enabled: Edge A=$VIP6_A, Edge B=$VIP6_B"
    fi

    # Start Edge A with VIP (use RUST_LOG=info for better throughput)
    print_step "Starting Edge A on $NODE_A (VIP: $VIP_A)..."
    ssh_cmd "$NODE_A" "sudo sh -c \"RUST_LOG=info nohup ./omni-test/omninervous --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args $stun_args --vip $VIP_A $vip6_args_a --port $OMNI_PORT $user_flag > /tmp/omni-edge-a.log 2>&1 &\" < /dev/null"
    sleep 2

    # Start Edge B with VIP (IMPORTANT: use SAME port as Edge A for P2P to work)
    print_step "Starting Edge B on $NODE_B (VIP: $VIP_B)..."
    ssh_cmd "$NODE_B" "sudo sh -c \"RUST_LOG=info nohup ./omni-test/omninervous --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args $stun_args --vip $VIP_B $vip6_args_b --port $OMNI_PORT $user_flag > /tmp/omni-edge-b.log 2>&1 &\" < /dev/null"
    sleep 2
    
    # Wait for WireGuard tunnel establishment (heartbeat cycle is 30s)
    print_step "Waiting for WireGuard tunnel establishment (60s for peer discovery)..."
    echo "   This includes registration, heartbeat + delta update, and WireGuard peer configuration."
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
    
    # v0.6.0 Relay Check
    if ssh_cmd "$NUCLEUS" "grep -q 'Relay server enabled' /tmp/omni-nucleus.log 2>/dev/null"; then
        echo -e "  ✅ ${GREEN}Relay Server ACTIVE${NC} on Nucleus"
    fi
    
    echo ""
    echo "--- Edge A log ---"
    ssh_cmd "$NODE_A" "tail -15 /tmp/omni-edge-a.log 2>/dev/null || echo 'No log in /tmp/omni-edge-a.log'"
    
    # v0.6.0 Port Mapping Check
    if ssh_cmd "$NODE_A" "grep -q 'Performing STUN discovery' /tmp/omni-edge-a.log 2>/dev/null"; then
        echo -e "  ✅ ${GREEN}NAT Discovery STARTED${NC} on Edge A"
    fi

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
    print_step "Verifying WireGuard interfaces..."
    echo "Edge A interfaces:"
    ssh_cmd "$NODE_A" "ip addr show omni0 2>/dev/null || echo 'omni0 not found'"
    echo ""
    echo "Edge B interfaces:"
    ssh_cmd "$NODE_B" "ip addr show omni0 2>/dev/null || echo 'omni0 not found'"
    
    # Network tests over WireGuard tunnel
    print_header "VPN Tunnel Metrics (WireGuard: A → B)"
    echo "   These tests use VPN IPs ($VIP_A → $VIP_B) over encrypted tunnel."
    echo ""
    # Ping test over tunnel with retry
    print_step "Ping over tunnel ($VIP_A → $VIP_B) with retries..."
    local ping_output=""
    local avg_latency="N/A"
    local ping_success=false
    for attempt in 1 2 3; do
        echo "   Attempt $attempt/3..."
        ping_output=$(ssh_cmd "$NODE_A" "ping -c 5 -W 5 $VIP_B 2>&1" || echo "PING_FAILED")
        if echo "$ping_output" | grep -q "rtt"; then
            avg_latency=$(echo "$ping_output" | grep "rtt" | awk -F'/' '{print $5}')
            echo -e "  ✅ Ping: ${YELLOW}${avg_latency} ms${NC}"
            ping_success=true
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
    
    # Initialize throughput to 0 (will be updated if iperf3 runs)
    local throughput_mbps="0"
    
    # Only run iperf3 if ping succeeded
    if [[ "$ping_success" == "true" ]]; then
        # Check WireGuard interfaces are up before iperf3
        print_step "Verifying WireGuard interfaces before iperf3..."
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

        # iperf3 over tunnel (only if WG is up)
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
            echo -e "  ⚠️ Skipping iperf3: WireGuard interfaces not ready"
        fi
    else
        echo -e "  ⚠️ Skipping iperf3: Ping test failed (no connectivity)"
    fi
    
    # =======================================================================
    # IPv6 TUNNEL TESTS
    # =======================================================================
    local avg_latency_v6="N/A"
    local throughput_mbps_v6="N/A"
    
    if [[ "$TEST_IPV6" == "true" ]]; then
        print_header "IPv6 VPN Tunnel Metrics (WireGuard: A → B)"
        echo "   Testing IPv6 connectivity over VPN tunnel."
        echo ""
        
        # Get IPv6 VIPs from interface
        local VIP6_A_ACTUAL
        local VIP6_B_ACTUAL
        VIP6_A_ACTUAL=$(ssh_cmd "$NODE_A" "ip -6 addr show omni0 2>/dev/null | grep 'inet6' | grep -v 'fe80' | awk '{print \$2}' | cut -d/ -f1 | head -1" || echo "")
        VIP6_B_ACTUAL=$(ssh_cmd "$NODE_B" "ip -6 addr show omni0 2>/dev/null | grep 'inet6' | grep -v 'fe80' | awk '{print \$2}' | cut -d/ -f1 | head -1" || echo "")
        
        if [[ -n "$VIP6_A_ACTUAL" && -n "$VIP6_B_ACTUAL" ]]; then
            echo "Edge A IPv6: $VIP6_A_ACTUAL"
            echo "Edge B IPv6: $VIP6_B_ACTUAL"
            
            # IPv6 Ping test
            print_step "IPv6 Ping over tunnel ($VIP6_A_ACTUAL → $VIP6_B_ACTUAL)..."
            local ping6_output
            local ping6_success=false
            ping6_output=$(ssh_cmd "$NODE_A" "ping -6 -c 5 -W 5 $VIP6_B_ACTUAL 2>&1" || echo "PING_FAILED")
            if echo "$ping6_output" | grep -q "rtt"; then
                avg_latency_v6=$(echo "$ping6_output" | grep "rtt" | awk -F'/' '{print $5}')
                echo -e "  ✅ IPv6 Ping: ${YELLOW}${avg_latency_v6} ms${NC}"
                ping6_success=true
            else
                echo -e "  ⚠️ IPv6 ping failed"
            fi
            
            # IPv6 iperf3 test (only if ping succeeded)
            if [[ "$ping6_success" == "true" ]]; then
                print_step "Starting iperf3 server on Edge B (IPv6)..."
                ssh_cmd "$NODE_B" "pkill iperf3 2>/dev/null; nohup iperf3 -s -p 5202 > /tmp/iperf6_server.log 2>&1 &"
                sleep 3
                
                print_step "Running IPv6 iperf3 throughput test ($TEST_DURATION seconds)..."
                local iperf6_json
                iperf6_json=$(ssh_cmd "$NODE_A" "iperf3 -6 -c $VIP6_B_ACTUAL -p 5202 -t $TEST_DURATION -M 1300 -P 2 --json 2>/dev/null" || echo "{}")
                
                local throughput6_bps
                throughput6_bps=$(echo "$iperf6_json" | jq '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
                throughput_mbps_v6=$(echo "scale=2; $throughput6_bps / 1000000" | bc 2>/dev/null || echo "N/A")
                
                if [[ "$throughput_mbps_v6" != "N/A" && "$throughput_mbps_v6" != "0" && "$throughput_mbps_v6" != ".00" ]]; then
                    echo -e "  ✅ IPv6 Throughput: ${YELLOW}${throughput_mbps_v6} Mbps${NC}"
                else
                    echo -e "  ⚠️ IPv6 iperf3 test failed"
                    throughput_mbps_v6="N/A"
                fi
                
                ssh_cmd "$NODE_B" "pkill iperf3 2>/dev/null" || true
            else
                echo -e "  ⚠️ Skipping IPv6 iperf3: IPv6 ping failed (no connectivity)"
            fi
        else
            echo -e "  ⚠️ IPv6 not configured on VPN interfaces, skipping IPv6 tests"
        fi
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
  "architecture": "3-node (Nucleus + WireGuard Edges)",
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
  "wireguard_tunnel_ipv4": {
    "ping_ms": "$avg_latency",
    "throughput_mbps": "$throughput_mbps"
  },
  "wireguard_tunnel_ipv6": {
    "ping_ms": "${avg_latency_v6:-N/A}",
    "throughput_mbps": "${throughput_mbps_v6:-N/A}"
  }
}
EOF
    
    # Cleanup
    print_step "Cleaning up remote processes..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo pkill -f omninervous || true; pkill -f iperf3 || true" 2>/dev/null || true
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
    echo -e "│  ${CYAN}VPN TUNNEL (IPv4)${NC}                                       │"
    echo -e "│    Latency:    ${YELLOW}${avg_latency} ms${NC}"
    echo -e "│    Throughput: ${YELLOW}${throughput_mbps} Mbps${NC}"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  ${CYAN}VPN TUNNEL (IPv6)${NC}                                       │"
    echo -e "│    Latency:    ${YELLOW}${avg_latency_v6:-N/A} ms${NC}"
    echo -e "│    Throughput: ${YELLOW}${throughput_mbps_v6:-N/A} Mbps${NC}"
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
        --stun)
            STUN_SERVERS="$2"
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
        --userspace)
            USERSPACE=true
            shift
            ;;
        --no-ipv6)
            TEST_IPV6=false
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

# Run test sequence
preflight_check
install_dependencies

if ! $SKIP_DEPLOY; then
    deploy_binaries
fi

run_test

echo -e "\n${GREEN}✅ 3-Node WireGuard cloud test completed!${NC}"
