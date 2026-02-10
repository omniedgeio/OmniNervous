#!/bin/bash
# =============================================================================
# OmniNervous Cloud-to-Cloud Test Orchestrator (v0.9.4)
# Run from LOCAL machine, orchestrates tests between cloud instances
# Architecture: Nucleus (signaling/relay) + Edge A + Edge B (WireGuard VPN)
# 
# Features:
#   - P2P vs Relay connectivity detection
#   - Automatic WireGuard interface cleanup after test
#   - Docker container cleanup for local testing
#   - IPv4 and IPv6 tunnel testing
#   - Baseline vs VPN performance comparison
#   - Early exit on connectivity failures (fail-fast)
#   - Handles NAT/VPN scenarios where baseline tests may fail
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
LOCAL_DOCKER=false
LOCAL_DOCKER_NAME="omni-node-local"
SKIP_BASELINE_THROUGHPUT=false
FAIL_FAST=true

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
  --local-docker  Run local nodes (e.g. localhost) in Docker (ensures Linux environment parity)
  --skip-baseline-throughput  Skip baseline iperf3 (useful when Edge A is behind NAT/VPN)
  --no-fail-fast  Continue tests even if ping fails
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
# Host Helper Functions
# =============================================================================

is_local() {
    local host="$1"
    if [[ "$host" == "localhost" || "$host" == "127.0.0.1" ]]; then
        return 0
    fi
    # Check if host is one of our local IPs (macOS/Linux compatible)
    if command -v ifconfig &>/dev/null; then
        if ifconfig | grep -q "$host"; then return 0; fi
    elif command -v ip &>/dev/null; then
        if ip addr | grep -q "$host"; then return 0; fi
    fi
    return 1
}

ssh_cmd() {
    local host="$1"
    shift
    if is_local "$host"; then
        if [[ "$LOCAL_DOCKER" == "true" ]]; then
            # Run in local Docker container (no -t to avoid TTY issues when capturing output)
            docker exec "$LOCAL_DOCKER_NAME" sh -c "$*"
        else
            # Native local execution
            sudo sh -c "$*"
        fi
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            ${SSH_KEY:+-i "$SSH_KEY"} \
            "$SSH_USER@$host" "$@"
    fi
}

scp_to() {
    local src="$1"
    local host="$2"
    local dest="$3"
    if is_local "$host"; then
        if [[ "$LOCAL_DOCKER" == "true" ]]; then
            # Copy to local Docker container
            # Resolve ~/ to /root inside the container
            local container_dest="${dest/#\~//root}"
            docker exec "$LOCAL_DOCKER_NAME" mkdir -p "$(dirname "$container_dest")"
            docker cp "$src" "$LOCAL_DOCKER_NAME:$container_dest"
        else
            # Native local copy
            local real_dest="${dest/#\~/$HOME}"
            mkdir -p "$(dirname "$real_dest")"
            cp "$src" "$real_dest"
        fi
    else
        scp -o StrictHostKeyChecking=no \
            ${SSH_KEY:+-i "$SSH_KEY"} \
            "$src" "$SSH_USER@$host:$dest"
    fi
}

ensure_local_docker() {
    if [[ "$LOCAL_DOCKER" != "true" ]]; then return 0; fi
    
    if ! docker ps --format '{{.Names}}' | grep -q "^$LOCAL_DOCKER_NAME$"; then
        print_step "Setting up local Docker environment ($LOCAL_DOCKER_NAME)..."
        docker rm -f "$LOCAL_DOCKER_NAME" 2>/dev/null || true
        
        # Use a lightweight ubuntu image with necessary tools
        docker run -d --name "$LOCAL_DOCKER_NAME" \
            --privileged \
            --cap-add=NET_ADMIN \
            --device /dev/net/tun:/dev/net/tun \
            ubuntu:24.04 sleep infinity
            
        print_step "Installing dependencies in local Docker container..."
        docker exec "$LOCAL_DOCKER_NAME" apt-get update -qq
        docker exec "$LOCAL_DOCKER_NAME" apt-get install -y -qq iperf3 wireguard-tools iproute2 psmisc iputils-ping sudo >/dev/null 2>&1
        
        # Create same directory structure as cloud
        docker exec "$LOCAL_DOCKER_NAME" mkdir -p /root/omni-test
        # Symlink /root/omni-test to /home/ubuntu if needed or just use consistent paths
    fi
}

# =============================================================================
# Cleanup Functions
# =============================================================================

cleanup_local_docker() {
    if [[ "$LOCAL_DOCKER" != "true" ]]; then return 0; fi
    
    print_step "Cleaning up local Docker container ($LOCAL_DOCKER_NAME)..."
    if docker ps -a --format '{{.Names}}' | grep -q "^$LOCAL_DOCKER_NAME$"; then
        docker stop "$LOCAL_DOCKER_NAME" 2>/dev/null || true
        docker rm -f "$LOCAL_DOCKER_NAME" 2>/dev/null || true
        echo -e "  ✅ Docker container $LOCAL_DOCKER_NAME removed"
    else
        echo -e "  ℹ️  Docker container $LOCAL_DOCKER_NAME not found (already cleaned)"
    fi
}

cleanup_wireguard_interfaces() {
    local node="$1"
    print_step "Cleaning up WireGuard interfaces on $node..."
    
    local remote_os=$(ssh_cmd "$node" "uname" 2>/dev/null || echo "Unknown")
    
    if [[ "$remote_os" == "Linux" ]]; then
        # Linux: Delete all omni* interfaces (kernel WireGuard or userspace TUN)
        ssh_cmd "$node" "
            for dev in \$(ip link show 2>/dev/null | grep -oE 'omni[0-9]+' | sort -u); do
                echo \"  Deleting interface: \$dev\"
                sudo ip link set \$dev down 2>/dev/null || true
                sudo ip link delete \$dev 2>/dev/null || true
            done
            # Also try wg-quick down if it was used
            for conf in /etc/wireguard/omni*.conf; do
                if [[ -f \"\$conf\" ]]; then
                    sudo wg-quick down \"\$(basename \$conf .conf)\" 2>/dev/null || true
                fi
            done
        " 2>/dev/null || true
        echo -e "  ✅ WireGuard interfaces cleaned on $node (Linux)"
        
    elif [[ "$remote_os" == "Darwin" ]]; then
        # macOS: Delete utun interfaces (userspace WireGuard uses utun)
        # Note: We can't directly delete utun interfaces, but we can kill the process
        ssh_cmd "$node" "
            # Kill any wireguard-go or boringtun processes
            sudo pkill -9 wireguard-go 2>/dev/null || true
            sudo pkill -9 boringtun 2>/dev/null || true
            # Remove WireGuard config files
            sudo rm -f /etc/wireguard/omni*.conf 2>/dev/null || true
        " 2>/dev/null || true
        echo -e "  ✅ WireGuard processes cleaned on $node (macOS)"
        
    else
        echo -e "  ⚠️  Unknown OS on $node, skipping interface cleanup"
    fi
}

detect_connectivity_type() {
    local node="$1"
    local log_file="$2"
    
    # Check logs for relay usage indicators
    local using_relay=false
    local direct_p2p=false
    local disco_success=false
    
    # Check for relay session established (actual relay usage)
    if ssh_cmd "$node" "grep -q 'Relay session established' $log_file 2>/dev/null"; then
        using_relay=true
    fi
    
    # Check for successful disco (direct P2P)
    # Format: "Disco pong received from ..."
    if ssh_cmd "$node" "grep -q 'Disco pong received' $log_file 2>/dev/null"; then
        disco_success=true
        direct_p2p=true
    fi
    
    # Check for disco failure leading to relay
    # Format: "Disco ping to ... failed after ... retries, requesting relay fallback"
    if ssh_cmd "$node" "grep -q 'requesting relay fallback' $log_file 2>/dev/null"; then
        direct_p2p=false
    fi
    
    # Determine connectivity type
    if [[ "$using_relay" == "true" ]]; then
        echo "relay"
    elif [[ "$direct_p2p" == "true" && "$disco_success" == "true" ]]; then
        echo "direct_p2p"
    elif [[ "$disco_success" == "true" ]]; then
        echo "direct_p2p"
    else
        echo "unknown"
    fi
}

get_connectivity_details() {
    local node="$1"
    local log_file="$2"
    
    local details=""
    
    # Get public endpoint (from STUN discovery)
    # Format: "Public endpoint discovered via Nucleus STUN: 1.2.3.4:5678" or "Public endpoint: 1.2.3.4:5678"
    local endpoint=$(ssh_cmd "$node" "grep -oE 'Public endpoint[^:]*: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' $log_file 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+'" || echo "")
    
    # Get relay server if used
    # Format: "Relay client enabled, relay server at 1.2.3.4:5678"
    local relay_server=$(ssh_cmd "$node" "grep -oE 'relay server at [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' $log_file 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+'" || echo "")
    
    # Get disco RTT if available
    # Format: "Disco pong received from ... (VIP: ..., RTT: 123.456789ms, observed: ...)"
    local disco_rtt=$(ssh_cmd "$node" "grep -oE 'RTT: [0-9]+\.?[0-9]*m?s' $log_file 2>/dev/null | tail -1 | grep -oE '[0-9]+\.?[0-9]*'" || echo "")
    
    # Check if relay was used (session established)
    local relay_used="false"
    if ssh_cmd "$node" "grep -q 'Relay session established' $log_file 2>/dev/null"; then
        relay_used="true"
    fi
    
    echo "{\"endpoint\": \"${endpoint:-unknown}\", \"relay_server\": \"${relay_server:-none}\", \"relay_used\": $relay_used, \"disco_rtt_ms\": \"${disco_rtt:-N/A}\"}"
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight_check() {
    print_header "Pre-flight Checks"
    
    # Ensure local Docker if requested
    ensure_local_docker
    
    local errors=0
    
    # Check for local dependencies
    print_step "Checking local dependencies..."
    local deps="ssh scp jq bc file"
    if [[ "$LOCAL_DOCKER" == "true" ]]; then
        deps="$deps docker"
    fi
    for cmd in $deps; do
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
    
    # Check for linux binaries
    local found_linux=false
    for bin in "$SCRIPT_DIR/omninervous-linux-amd64" "$SCRIPT_DIR/omninervous-linux-arm64"; do
        if [[ -f "$bin" ]]; then
            echo -e "✅ Linux binary found: $(basename "$bin")"
            found_linux=true
        fi
    done
    
    if [[ "$found_linux" == "false" ]]; then
        print_error "No Linux binaries found in $SCRIPT_DIR"
        echo "   Requires omninervous-linux-amd64 and/or omninervous-linux-arm64"
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
        local node_os=$(ssh_cmd "$node" "uname")
        if [[ "$node_os" == "Darwin" ]]; then
            echo -e "  🍏 macOS detected on $node, using native TUN/utun (no 'ip' required)"
            continue
        fi
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
        
        # Detect remote platform
        local remote_os=$(ssh_cmd "$node" "uname")
        if [[ "$remote_os" == "Darwin" ]]; then
            echo -e "  🍏 macOS detected on $node, assuming dependencies (iperf3) are installed via brew"
            continue
        fi

        # Detect package manager (Linux)
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
        
        # Install wireguard-tools and load module (for kernel mode)
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
            
            # Ensure module is loaded
            echo -e "  ⚙️ Ensuring WireGuard kernel module is loaded..."
            ssh_cmd "$node" "sudo modprobe wireguard" || echo "  ⚠️ Failed to modprobe wireguard (might be builtin)"
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
        
        # Install iproute2, jq, bc, psmisc (for fuser)
        ssh_cmd "$node" "which ip &>/dev/null || (sudo $pkg_manager install -y iproute2 || sudo $pkg_manager install -y iproute || true)" || true
        ssh_cmd "$node" "which jq &>/dev/null || (sudo $pkg_manager install -y jq || true)" || true
        ssh_cmd "$node" "which bc &>/dev/null || (sudo $pkg_manager install -y bc || true)" || true
        ssh_cmd "$node" "which fuser &>/dev/null || (sudo $pkg_manager install -y psmisc || true)" || true
        ssh_cmd "$node" "which pkill &>/dev/null || (sudo $pkg_manager install -y procps || true)" || true
        
        echo -e "  ✅ Utility tools (ip, jq, bc, psmisc, procps) check complete"
        
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
    
    # Define linux binaries
    local LINUX_AMD64="$SCRIPT_DIR/omninervous-linux-amd64"
    local LINUX_ARM64="$SCRIPT_DIR/omninervous-linux-arm64"
    
    # Check at least one exists
    if [[ ! -f "$LINUX_AMD64" && ! -f "$LINUX_ARM64" ]]; then
        print_error "No Linux binaries found in $SCRIPT_DIR"
        echo "   Requires: omninervous-linux-amd64 and/or omninervous-linux-arm64"
        exit 1
    fi
    
    # Detect host architecture for local deployment choices
    local host_arch=$(uname -m)
    echo -e "✅ Host Architecture: ${YELLOW}$host_arch${NC}"
    
    # Deploy to all nodes
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        print_step "Deploying to $node..."
        
        # Detect remote platform
        local remote_os=$(ssh_cmd "$node" "uname")
        local TARGET_BINARY=""
        
        # Binary selection logic
        if is_local "$node" && [[ "$LOCAL_DOCKER" == "true" ]]; then
            # We are deploying to a local Linux Docker container
            if [[ "$host_arch" == "arm64" || "$host_arch" == "aarch64" ]]; then
                TARGET_BINARY="$LINUX_ARM64"
            else
                TARGET_BINARY="$LINUX_AMD64"
            fi
            
            # Fallback if preferred arch choice doesn't exist
            if [[ ! -f "$TARGET_BINARY" ]]; then
                TARGET_BINARY="${LINUX_AMD64:-$LINUX_ARM64}"
                [[ ! -f "$TARGET_BINARY" ]] && TARGET_BINARY="$LINUX_ARM64"
            fi
            echo -e "  🐳 Local Docker detected: using Linux binary for $host_arch"
        elif [[ "$remote_os" == "Linux" ]]; then
            # Standard cloud Linux node (usually amd64, but we could be smarter here too)
            TARGET_BINARY="$LINUX_AMD64"
            if [[ ! -f "$TARGET_BINARY" ]]; then TARGET_BINARY="$LINUX_ARM64"; fi
        fi
        
        if [[ "$remote_os" == "Darwin" ]]; then
            # Look for macOS binary in order of preference
            if [[ -f "$SCRIPT_DIR/omninervous-macos-arm64" ]]; then
                TARGET_BINARY="$SCRIPT_DIR/omninervous-macos-arm64"
            elif [[ -f "$SCRIPT_DIR/omninervous-macos" ]]; then
                TARGET_BINARY="$SCRIPT_DIR/omninervous-macos"
            elif is_local "$node" && [[ -f "$SCRIPT_DIR/../target/release/omninervous" ]]; then
                # Local build artifact
                TARGET_BINARY="$SCRIPT_DIR/../target/release/omninervous"
            else
                echo "  ⚠️ macOS binary not found in $SCRIPT_DIR. Skipping deployment to $node."
                echo "  💡 Place 'omninervous-macos-arm64' or 'omninervous-macos' in scripts/ folder."
                continue
            fi
            
            # If local macOS, fix 'killed: 137' (signature issues)
            if is_local "$node"; then
                echo "  🛡️  Fixing macOS binary permissions and signature for local run..."
                sudo xattr -rd com.apple.quarantine "$TARGET_BINARY" 2>/dev/null || true
                codesign -s - -f "$TARGET_BINARY" 2>/dev/null || true
            fi
        fi

        if [[ -z "$TARGET_BINARY" ]]; then
            echo -e "  ❌ Could not determine target binary for $node (OS: $remote_os)"
            continue
        fi

        # Clean up and create remote directory
        ssh_cmd "$node" "rm -rf ~/omni-test && mkdir -p ~/omni-test"
        
        # Copy binary
        scp_to "$TARGET_BINARY" "$node" "~/omni-test/omninervous"
        
        # Make executable
        ssh_cmd "$node" "chmod +x ~/omni-test/omninervous"
        
        echo -e "✅ Deployed to $node ($(basename "$TARGET_BINARY"))"
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

    # Kill any existing processes and clean up interfaces
    print_step "Cleaning up old processes, interfaces and logs..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        # Aggressive cleanup: kill processes, clear port, delete all omni* interfaces
        ssh_cmd "$node" "sudo pkill -9 -f omninervous 2>/dev/null; \
                         sudo pkill -9 -f iperf3 2>/dev/null; \
                         if command -v fuser &>/dev/null; then sudo fuser -k $OMNI_PORT/udp 2>/dev/null; fi; \
                         # Delete any interface starting with 'omni' (Platform aware)
                         if [[ \$(uname) == 'Linux' ]]; then \
                             for dev in \$(ip link show | grep -o 'omni[0-9]*'); do \
                                sudo ip link set \$dev down 2>/dev/null || true; \
                                sudo ip link delete \$dev 2>/dev/null || true; \
                             done; \
                         fi; \
                         sudo rm -f /tmp/omni-*.log" || true
    done
    
    # Give the OS a bit more time to release sockets and cleanup interfaces
    echo "   Waiting for resource release..."
    sleep 5
    
    # Start Nucleus (signaling server)
    print_step "Starting Nucleus on $NUCLEUS..."
    ssh_cmd "$NUCLEUS" "sudo sh -c \"RUST_LOG=debug nohup \$HOME/omni-test/omninervous --mode nucleus --port $OMNI_PORT $secret_args --mtu auto> /tmp/omni-nucleus.log 2>&1 &\" < /dev/null"
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
    ssh_cmd "$NODE_A" "sudo sh -c \"RUST_LOG=debug nohup \$HOME/omni-test/omninervous --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args $stun_args --vip $VIP_A $vip6_args_a --port $OMNI_PORT $user_flag --mtu auto > /tmp/omni-edge-a.log 2>&1 &\" < /dev/null"
    sleep 2

    # Start Edge B with VIP (IMPORTANT: use SAME port as Edge A for P2P to work)
    print_step "Starting Edge B on $NODE_B (VIP: $VIP_B)..."
    ssh_cmd "$NODE_B" "sudo sh -c \"RUST_LOG=debug nohup \$HOME/omni-test/omninervous --nucleus $NUCLEUS:$OMNI_PORT --cluster $CLUSTER_NAME $secret_args $stun_args --vip $VIP_B $vip6_args_b --port $OMNI_PORT $user_flag --mtu auto > /tmp/omni-edge-b.log 2>&1 &\" < /dev/null"
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
    local baseline_ping_success=false
    baseline_ping_output=$(ssh_cmd "$NODE_A" "ping -c 5 -W 5 $NODE_B 2>&1" || echo "PING_FAILED")
    local baseline_latency="N/A"
    if echo "$baseline_ping_output" | grep -q "rtt"; then
        baseline_latency=$(echo "$baseline_ping_output" | grep "rtt" | awk -F'/' '{print $5}')
        echo -e "  ✅ Baseline Ping: ${YELLOW}${baseline_latency} ms${NC}"
        baseline_ping_success=true
    else
        echo -e "  ⚠️ Baseline ping failed (Edge A may be behind NAT/VPN, or firewall blocking ICMP)"
        echo "     This is expected if Edge A is behind NAT and cannot reach Edge B's public IP directly."
    fi
    
    # Baseline iperf3 test (public IP) - only if ping succeeded and not skipped
    local baseline_throughput_mbps="N/A"
    if [[ "$baseline_ping_success" == "true" && "$SKIP_BASELINE_THROUGHPUT" == "false" ]]; then
        print_step "Starting iperf3 server on Edge B (public IP)..."
        ssh_cmd "$NODE_B" "pkill iperf3 2>/dev/null; nohup iperf3 -s -p 5201 > /tmp/iperf_baseline.log 2>&1 &"
        sleep 3
        
        print_step "Baseline iperf3 throughput test ($TEST_DURATION seconds) over public IP..."
        local baseline_iperf_json
        baseline_iperf_json=$(ssh_cmd "$NODE_A" "iperf3 -c $NODE_B -p 5201 -t $TEST_DURATION -M 1300 -P 2 --json 2>/dev/null" || echo "{}")
        
        local baseline_throughput_bps
        baseline_throughput_bps=$(echo "$baseline_iperf_json" | jq '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
        baseline_throughput_mbps=$(echo "scale=2; $baseline_throughput_bps / 1000000" | bc 2>/dev/null || echo "N/A")
        
        if [[ "$baseline_throughput_mbps" != "N/A" && "$baseline_throughput_mbps" != "0" && "$baseline_throughput_mbps" != ".00" ]]; then
            echo -e "  ✅ Baseline Throughput: ${YELLOW}${baseline_throughput_mbps} Mbps${NC}"
        else
            echo -e "  ⚠️ Baseline iperf3 failed (port 5201 may be blocked)"
            baseline_throughput_mbps="N/A"
        fi
        
        # Stop baseline iperf3 server
        ssh_cmd "$NODE_B" "pkill iperf3 2>/dev/null" || true
    elif [[ "$SKIP_BASELINE_THROUGHPUT" == "true" ]]; then
        echo -e "  ⏭️  Skipping baseline throughput test (--skip-baseline-throughput)"
    else
        echo -e "  ⏭️  Skipping baseline throughput test (ping failed)"
    fi
    
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
            echo -e "  ✅ Tunnel Ping: ${YELLOW}${avg_latency} ms${NC}"
            ping_success=true
            break
        else
            echo "   Ping failed, retrying in 10s..."
            sleep 10
        fi
    done
    
    # Initialize throughput to 0 (will be updated if iperf3 runs)
    local throughput_mbps="0"
    
    if [[ "$ping_success" == "false" ]]; then
        echo -e "  ${RED}❌ Tunnel ping FAILED after 3 attempts${NC}"
        echo ""
        echo "     Diagnostics (IP):"
        ssh_cmd "$NODE_A" "ip addr show omni0 2>/dev/null" || echo "     omni0 not found on Edge A"
        ssh_cmd "$NODE_B" "ip addr show omni0 2>/dev/null" || echo "     omni0 not found on Edge B"
        echo ""
        echo "     Diagnostics (Route):"
        ssh_cmd "$NODE_A" "ip route | grep omni 2>/dev/null" || echo "     No omni routes on Edge A"
        ssh_cmd "$NODE_B" "ip route | grep omni 2>/dev/null" || echo "     No omni routes on Edge B"
        echo ""
        echo "     Check logs for peer discovery errors"
        
        if [[ "$FAIL_FAST" == "true" ]]; then
            echo ""
            echo -e "  ${YELLOW}⚠️  Fail-fast enabled: Skipping throughput tests${NC}"
            echo "     Use --no-fail-fast to continue despite ping failures"
        fi
    fi
    
    # Only run iperf3 if ping succeeded (or fail-fast is disabled)
    if [[ "$ping_success" == "true" ]] || [[ "$FAIL_FAST" == "false" && "$ping_success" == "false" ]]; then
        # Check WireGuard interfaces are up before iperf3
        if [[ "$ping_success" == "true" ]]; then
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
        fi
    fi
    
    # =======================================================================
    # IPv6 TUNNEL TESTS
    # =======================================================================
    local avg_latency_v6="N/A"
    local throughput_mbps_v6="N/A"
    
    if [[ "$TEST_IPV6" == "true" ]]; then
        # Skip IPv6 tests if IPv4 tunnel failed and fail-fast is enabled
        if [[ "$ping_success" == "false" && "$FAIL_FAST" == "true" ]]; then
            echo -e "\n  ${YELLOW}⏭️  Skipping IPv6 tests (IPv4 tunnel ping failed, fail-fast enabled)${NC}"
        else
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
    fi
    
    # Collect logs
    print_step "Collecting logs..."
    ssh_cmd "$NUCLEUS" "cat /tmp/omni-nucleus.log" > "$RESULTS_DIR/nucleus.log" 2>/dev/null || true
    ssh_cmd "$NODE_A" "cat /tmp/omni-edge-a.log" > "$RESULTS_DIR/edge_a.log" 2>/dev/null || true
    ssh_cmd "$NODE_B" "cat /tmp/omni-edge-b.log" > "$RESULTS_DIR/edge_b.log" 2>/dev/null || true
    
    # ==========================================================================
    # Connectivity Type Detection (P2P vs Relay)
    # ==========================================================================
    print_header "Connectivity Analysis"
    
    # Detect connectivity type from Edge A's perspective
    local conn_type_a=$(detect_connectivity_type "$NODE_A" "/tmp/omni-edge-a.log")
    local conn_details_a=$(get_connectivity_details "$NODE_A" "/tmp/omni-edge-a.log")
    
    # Detect connectivity type from Edge B's perspective
    local conn_type_b=$(detect_connectivity_type "$NODE_B" "/tmp/omni-edge-b.log")
    local conn_details_b=$(get_connectivity_details "$NODE_B" "/tmp/omni-edge-b.log")
    
    # Determine overall connectivity type
    local overall_conn_type="unknown"
    if [[ "$conn_type_a" == "relay" || "$conn_type_b" == "relay" ]]; then
        overall_conn_type="relay"
        echo -e "  🔄 Connectivity Type: ${YELLOW}RELAY${NC} (traffic routed via Nucleus)"
    elif [[ "$conn_type_a" == "direct_p2p" && "$conn_type_b" == "direct_p2p" ]]; then
        overall_conn_type="direct_p2p"
        echo -e "  ✅ Connectivity Type: ${GREEN}DIRECT P2P${NC} (UDP hole punching successful)"
    elif [[ "$conn_type_a" == "direct_p2p" || "$conn_type_b" == "direct_p2p" ]]; then
        overall_conn_type="direct_p2p"
        echo -e "  ✅ Connectivity Type: ${GREEN}DIRECT P2P${NC} (asymmetric, one side confirmed)"
    else
        echo -e "  ⚠️  Connectivity Type: ${RED}UNKNOWN${NC} (check logs for details)"
    fi
    
    echo ""
    echo "  Edge A details: $conn_details_a"
    echo "  Edge B details: $conn_details_b"
    
    # Create results JSON with connectivity info
    cat > "$result_file" << EOF
{
  "timestamp": "$timestamp",
  "architecture": "3-node (Nucleus + WireGuard Edges)",
  "nucleus": "$NUCLEUS",
  "edge_a": {"public_ip": "$NODE_A", "vip": "$VIP_A"},
  "edge_b": {"public_ip": "$NODE_B", "vip": "$VIP_B"},
  "cluster": "$CLUSTER_NAME",
  "authenticated": $([ -n "$CLUSTER_SECRET" ] && echo "true" || echo "false"),
  "userspace_wireguard": $USERSPACE,
  "test_duration_sec": $TEST_DURATION,
  "connectivity": {
    "type": "$overall_conn_type",
    "edge_a": {
      "type": "$conn_type_a",
      "details": $conn_details_a
    },
    "edge_b": {
      "type": "$conn_type_b",
      "details": $conn_details_b
    }
  },
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
    
    # ==========================================================================
    # Cleanup: Processes, Interfaces, and Docker
    # ==========================================================================
    print_header "Cleanup"
    
    # Stop processes
    print_step "Stopping remote processes..."
    for node in "$NUCLEUS" "$NODE_A" "$NODE_B"; do
        ssh_cmd "$node" "sudo pkill -9 -f omninervous 2>/dev/null || true; pkill -f iperf3 2>/dev/null || true" 2>/dev/null || true
    done
    
    # Clean up WireGuard interfaces
    print_step "Cleaning up WireGuard interfaces..."
    for node in "$NODE_A" "$NODE_B"; do
        cleanup_wireguard_interfaces "$node"
    done
    
    # Clean up local Docker container if used
    cleanup_local_docker
    
    # Summary
    print_header "Test Complete"
    
    # Connectivity type color
    local conn_color="${RED}"
    local conn_icon="❓"
    if [[ "$overall_conn_type" == "direct_p2p" ]]; then
        conn_color="${GREEN}"
        conn_icon="✅"
    elif [[ "$overall_conn_type" == "relay" ]]; then
        conn_color="${YELLOW}"
        conn_icon="🔄"
    fi
    
    echo -e "┌─────────────────────────────────────────────────────────┐"
    echo -e "│  ${GREEN}3-NODE P2P TEST RESULTS${NC}                                 │"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  Nucleus:     $NUCLEUS"
    echo -e "│  Edge A:      $NODE_A → $VIP_A"
    echo -e "│  Edge B:      $NODE_B → $VIP_B"
    echo -e "├─────────────────────────────────────────────────────────┤"
    echo -e "│  ${CYAN}CONNECTIVITY${NC}                                            │"
    echo -e "│    Type:       $conn_icon ${conn_color}$(echo "$overall_conn_type" | tr '[:lower:]' '[:upper:]')${NC}"
    echo -e "│    Mode:       $([ "$USERSPACE" == "true" ] && echo "Userspace (BoringTun)" || echo "Kernel WireGuard")"
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
        --local-docker)
            LOCAL_DOCKER=true
            shift
            ;;
        --skip-baseline-throughput)
            SKIP_BASELINE_THROUGHPUT=true
            shift
            ;;
        --no-fail-fast)
            FAIL_FAST=false
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
