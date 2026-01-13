#!/bin/bash
# =============================================================================
# OmniNervous Cloud-to-Cloud Test Script
# Tests P2P connectivity between two cloud instances
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "\n${GREEN}=== $1 ===${NC}\n"
}

print_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

# =============================================================================
# Configuration
# =============================================================================

OMNI_PORT=${OMNI_PORT:-51820}
OMNI_BINARY=${OMNI_BINARY:-"./target/release/omni-daemon"}
TEST_DURATION=${TEST_DURATION:-10}

show_help() {
    cat << EOF
OmniNervous Cloud-to-Cloud Test

Usage:
  On Node A (initiator):
    $0 --role initiator --peer-ip <NODE_B_IP> --peer-pubkey <NODE_B_PUBKEY>
  
  On Node B (responder):
    $0 --role responder
  
  Pre-flight check only:
    $0 --check

Options:
  --role          Role: 'initiator' or 'responder'
  --peer-ip       IP address of peer (required for initiator)
  --peer-pubkey   Public key of peer (required for initiator)
  --port          UDP port (default: 51820)
  --duration      iperf3 test duration in seconds (default: 10)
  --check         Run pre-flight checks only
  --help          Show this help

Environment Variables:
  OMNI_PORT       UDP port (default: 51820)
  OMNI_BINARY     Path to omni-daemon binary
  TEST_DURATION   iperf3 test duration

Example (Real-world test):
  # On Node B (AWS us-west-2):
  ./cloud_test.sh --role responder
  # Note the public key output
  
  # On Node A (GCP us-central1):
  ./cloud_test.sh --role initiator --peer-ip 54.x.x.x --peer-pubkey abc123...
EOF
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight_check() {
    print_header "Pre-flight Checks"
    
    local errors=0
    
    # Check binary exists
    if [[ -f "$OMNI_BINARY" ]]; then
        echo -e "✅ omni-daemon binary found: $OMNI_BINARY"
    else
        echo -e "❌ omni-daemon binary not found: $OMNI_BINARY"
        echo "   Run: cargo build -p omni-daemon --release"
        errors=$((errors + 1))
    fi
    
    # Check iperf3
    if command -v iperf3 &> /dev/null; then
        echo -e "✅ iperf3 installed"
    else
        echo -e "❌ iperf3 not installed"
        echo "   Install: apt-get install iperf3 / brew install iperf3"
        errors=$((errors + 1))
    fi
    
    # Check port availability
    if ! lsof -i :$OMNI_PORT &> /dev/null; then
        echo -e "✅ Port $OMNI_PORT available"
    else
        echo -e "❌ Port $OMNI_PORT in use"
        errors=$((errors + 1))
    fi
    
    # Check firewall (best effort)
    echo -e "⚠️  Ensure UDP port $OMNI_PORT is open in cloud firewall/security group"
    
    # Check public IP
    local public_ip
    public_ip=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "unknown")
    echo -e "📍 Public IP: $public_ip"
    
    if [[ $errors -gt 0 ]]; then
        print_error "Pre-flight checks failed with $errors errors"
        exit 1
    fi
    
    echo -e "\n${GREEN}All pre-flight checks passed!${NC}"
}

# =============================================================================
# Responder Mode
# =============================================================================

run_responder() {
    print_header "Starting Responder (Node B)"
    
    preflight_check
    
    echo "Generating identity..."
    local pubkey
    pubkey=$($OMNI_BINARY --init 2>/dev/null | grep "Public" | awk '{print $NF}')
    
    if [[ -z "$pubkey" ]]; then
        # Fallback: generate mock key for testing
        pubkey=$(openssl rand -hex 16)
        print_warning "Using mock public key (daemon --init not implemented yet)"
    fi
    
    echo -e "\n${GREEN}Your Public Key:${NC}"
    echo -e "${YELLOW}$pubkey${NC}"
    echo -e "\nShare this with the initiator node.\n"
    
    # Get public IP
    local public_ip
    public_ip=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_IP")
    echo -e "Your Public IP: $public_ip"
    echo -e "\nCommand for initiator:"
    echo -e "${YELLOW}./cloud_test.sh --role initiator --peer-ip $public_ip --peer-pubkey $pubkey${NC}\n"
    
    echo "Starting daemon in responder mode..."
    echo "Press Ctrl+C to stop"
    
    # Start daemon
    $OMNI_BINARY --port $OMNI_PORT &
    DAEMON_PID=$!
    
    # Start iperf3 server
    echo "Starting iperf3 server..."
    iperf3 -s -p 5201 &
    IPERF_PID=$!
    
    trap "kill $DAEMON_PID $IPERF_PID 2>/dev/null; exit" INT TERM
    
    echo -e "\n${GREEN}Responder ready. Waiting for connections...${NC}"
    wait $DAEMON_PID
}

# =============================================================================
# Initiator Mode
# =============================================================================

run_initiator() {
    local peer_ip="$1"
    local peer_pubkey="$2"
    
    print_header "Starting Initiator (Node A)"
    
    if [[ -z "$peer_ip" || -z "$peer_pubkey" ]]; then
        print_error "--peer-ip and --peer-pubkey required for initiator"
        exit 1
    fi
    
    preflight_check
    
    echo "Peer IP: $peer_ip"
    echo "Peer Public Key: $peer_pubkey"
    
    echo -e "\nStarting daemon and connecting to peer..."
    $OMNI_BINARY --port $OMNI_PORT --peer $peer_pubkey --endpoint $peer_ip:$OMNI_PORT &
    DAEMON_PID=$!
    
    # Wait for handshake
    echo "Waiting for Noise handshake..."
    sleep 5
    
    # Run connectivity test
    print_header "Connectivity Test"
    
    echo "Testing ping to peer..."
    if ping -c 3 -W 5 $peer_ip &> /dev/null; then
        echo -e "✅ Ping to $peer_ip successful"
    else
        print_warning "Ping failed (may be blocked by firewall)"
    fi
    
    # Run iperf3 test
    print_header "Throughput Test (iperf3)"
    
    echo "Running iperf3 for $TEST_DURATION seconds..."
    if iperf3 -c $peer_ip -p 5201 -t $TEST_DURATION --json > /tmp/iperf_result.json 2>/dev/null; then
        local bps
        bps=$(jq '.end.sum_sent.bits_per_second // 0' /tmp/iperf_result.json 2>/dev/null || echo "0")
        local mbps
        mbps=$(echo "scale=2; $bps / 1000000" | bc 2>/dev/null || echo "N/A")
        
        echo -e "\n${GREEN}Results:${NC}"
        echo -e "  Throughput: ${YELLOW}$mbps Mbps${NC}"
        
        local retransmits
        retransmits=$(jq '.end.sum_sent.retransmits // 0' /tmp/iperf_result.json 2>/dev/null || echo "0")
        echo -e "  Retransmits: $retransmits"
    else
        print_warning "iperf3 test failed (peer iperf3 server may not be running)"
    fi
    
    # Latency test
    print_header "Latency Test"
    
    echo "Running latency test..."
    if command -v ping &> /dev/null; then
        local latency
        latency=$(ping -c 10 $peer_ip 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
        if [[ -n "$latency" ]]; then
            echo -e "  Average Latency: ${YELLOW}${latency}ms${NC}"
        else
            print_warning "Could not measure latency"
        fi
    fi
    
    # Cleanup
    kill $DAEMON_PID 2>/dev/null || true
    
    print_header "Test Complete"
    echo "Results saved to /tmp/iperf_result.json"
}

# =============================================================================
# Main
# =============================================================================

ROLE=""
PEER_IP=""
PEER_PUBKEY=""
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --role)
            ROLE="$2"
            shift 2
            ;;
        --peer-ip)
            PEER_IP="$2"
            shift 2
            ;;
        --peer-pubkey)
            PEER_PUBKEY="$2"
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
        --check)
            CHECK_ONLY=true
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

if $CHECK_ONLY; then
    preflight_check
    exit 0
fi

case $ROLE in
    responder)
        run_responder
        ;;
    initiator)
        run_initiator "$PEER_IP" "$PEER_PUBKEY"
        ;;
    *)
        print_error "Please specify --role (initiator or responder)"
        show_help
        exit 1
        ;;
esac
