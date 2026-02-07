#!/bin/bash
# =============================================================================
# OmniNervous AWS Lightsail Auto-Test
# Automatically creates 3 Lightsail instances, runs cloud_test.sh, then cleans up
#
# Prerequisites:
#   - AWS CLI v2 configured with Lightsail permissions
#   - SSH key pair created in Lightsail (or will use default)
#   - omninervous-linux-amd64 binary in scripts/ folder
#
# Usage:
#   ./scripts/cloud_test_aws.sh --secret "my-secure-secret-16" [--keep-instances]
#
# Cost: ~$0.02 per test run (3x $5/month instances for ~10 minutes)
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

# Instance naming
INSTANCE_PREFIX="omni-test-$(date +%Y%m%d%H%M%S)"
NUCLEUS_NAME="${INSTANCE_PREFIX}-nucleus"
NODE_A_NAME="${INSTANCE_PREFIX}-edge-a"
NODE_B_NAME="${INSTANCE_PREFIX}-edge-b"

# AWS Lightsail configuration
NUCLEUS_REGION="us-west-2"
NUCLEUS_AZ="us-west-2a"
NODE_A_REGION="us-west-2"
NODE_A_AZ="us-west-2a"
NODE_B_REGION="us-east-2"
NODE_B_AZ="us-east-2a"

# $5/month = nano_3_0 bundle (0.5GB RAM, 1 vCPU, 20GB SSD)
BUNDLE_ID="nano_3_0"
# Ubuntu 24.04 LTS
BLUEPRINT_ID="ubuntu_24_04"

# SSH Key - uses Lightsail default key pair
SSH_KEY_PAIR_NAME="${LIGHTSAIL_KEY_PAIR:-default}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/lightsail_default.pem}"

# Test configuration
CLUSTER_SECRET=""
TEST_DURATION="${TEST_DURATION:-10}"
USERSPACE="${USERSPACE:-true}"
KEEP_INSTANCES=false
NO_IPV6=false

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
    cat << EOF
OmniNervous AWS Lightsail Auto-Test

Automatically provisions 3 Lightsail instances, runs the P2P VPN test, 
and cleans up afterwards.

Instance Placement:
  - Nucleus:  us-west-2a  (signaling server)
  - Edge A:   us-west-2a  (same region as nucleus)
  - Edge B:   us-east-2a  (cross-region P2P test)

Usage:
  $0 --secret <CLUSTER_SECRET> [OPTIONS]

Required:
  --secret          Cluster secret (min 16 chars)

Options:
  --ssh-key-name    Lightsail key pair name (default: default)
  --ssh-key-path    Path to SSH private key (default: ~/.ssh/lightsail_default.pem)
  --duration        iperf3 test duration in seconds (default: 10)
  --no-ipv6         Skip IPv6 tests
  --keep-instances  Don't delete instances after test (for debugging)
  --help            Show this help

Environment Variables:
  LIGHTSAIL_KEY_PAIR   Lightsail SSH key pair name
  SSH_KEY_PATH         Path to SSH private key
  TEST_DURATION        iperf3 test duration
  USERSPACE            Use userspace WireGuard (default: true)

Prerequisites:
  - AWS CLI v2 configured: aws configure
  - Lightsail permissions: lightsail:CreateInstances, lightsail:DeleteInstance, etc.
  - Pre-built binary: scripts/omninervous-linux-amd64

Example:
  $0 --secret "omni-test-secret-2026" --duration 30

Cost Estimate:
  3x \$5/month instances × 15 minutes ≈ \$0.02 per test run
EOF
}

# =============================================================================
# AWS Lightsail Functions
# =============================================================================

check_aws_cli() {
    print_step "Checking AWS CLI..."
    
    if ! command -v aws &>/dev/null; then
        print_error "AWS CLI not found. Install with: brew install awscli"
        exit 1
    fi
    
    # Check if configured
    if ! aws sts get-caller-identity &>/dev/null; then
        print_error "AWS CLI not configured. Run: aws configure"
        exit 1
    fi
    
    local account_id
    account_id=$(aws sts get-caller-identity --query 'Account' --output text)
    echo -e "  ✅ AWS CLI configured (Account: $account_id)"
}

create_instance() {
    local name="$1"
    local region="$2"
    local az="$3"
    
    print_step "Creating instance: $name in $az..."
    
    aws lightsail create-instances \
        --region "$region" \
        --instance-names "$name" \
        --availability-zone "$az" \
        --blueprint-id "$BLUEPRINT_ID" \
        --bundle-id "$BUNDLE_ID" \
        --key-pair-name "$SSH_KEY_PAIR_NAME" \
        --tags "key=project,value=omninervous" "key=test,value=cloud-test" \
        --output text >/dev/null
    
    echo -e "  ✅ Instance $name created"
}

wait_for_instance() {
    local name="$1"
    local region="$2"
    local max_wait=300
    local waited=0
    
    print_step "Waiting for instance $name to be running..."
    
    while [[ $waited -lt $max_wait ]]; do
        local state
        state=$(aws lightsail get-instance --region "$region" --instance-name "$name" \
            --query 'instance.state.name' --output text 2>/dev/null || echo "pending")
        
        if [[ "$state" == "running" ]]; then
            echo -e "  ✅ Instance $name is running"
            return 0
        fi
        
        echo -n "."
        sleep 5
        waited=$((waited + 5))
    done
    
    print_error "Timeout waiting for instance $name"
    return 1
}

get_instance_ip() {
    local name="$1"
    local region="$2"
    
    aws lightsail get-instance --region "$region" --instance-name "$name" \
        --query 'instance.publicIpAddress' --output text
}

open_all_ports() {
    local name="$1"
    local region="$2"
    
    print_step "Opening all ports on $name..."
    
    # Open all TCP and UDP ports
    aws lightsail open-instance-public-ports \
        --region "$region" \
        --instance-name "$name" \
        --port-info "fromPort=0,toPort=65535,protocol=all" \
        --output text >/dev/null 2>&1 || true
    
    # Also open ICMP for ping tests
    aws lightsail open-instance-public-ports \
        --region "$region" \
        --instance-name "$name" \
        --port-info "fromPort=-1,toPort=-1,protocol=icmp" \
        --output text >/dev/null 2>&1 || true
    
    echo -e "  ✅ All ports opened on $name"
}

enable_ipv6() {
    local name="$1"
    local region="$2"
    
    print_step "Enabling IPv6 on $name..."
    
    aws lightsail set-ip-address-type \
        --region "$region" \
        --resource-name "$name" \
        --resource-type Instance \
        --ip-address-type dualstack \
        --output text >/dev/null 2>&1 || true
    
    echo -e "  ✅ IPv6 enabled on $name"
}

wait_for_ssh() {
    local ip="$1"
    local max_wait=120
    local waited=0
    
    print_step "Waiting for SSH on $ip..."
    
    while [[ $waited -lt $max_wait ]]; do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            -o BatchMode=yes -i "$SSH_KEY_PATH" \
            ubuntu@"$ip" "echo ok" &>/dev/null; then
            echo -e "  ✅ SSH ready on $ip"
            return 0
        fi
        
        echo -n "."
        sleep 5
        waited=$((waited + 5))
    done
    
    print_error "Timeout waiting for SSH on $ip"
    return 1
}

install_dependencies() {
    local ip="$1"
    
    print_step "Installing dependencies on $ip..."
    
    ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" ubuntu@"$ip" << 'REMOTE_SCRIPT'
        set -e
        sudo apt-get update -qq
        sudo apt-get install -y -qq iperf3 wireguard-tools iproute2 >/dev/null 2>&1
        echo "Dependencies installed"
REMOTE_SCRIPT
    
    echo -e "  ✅ Dependencies installed on $ip"
}

delete_instance() {
    local name="$1"
    local region="$2"
    
    print_step "Deleting instance: $name..."
    
    aws lightsail delete-instance \
        --region "$region" \
        --instance-name "$name" \
        --output text >/dev/null 2>&1 || true
    
    echo -e "  ✅ Instance $name deleted"
}

cleanup_instances() {
    print_header "Cleaning Up Instances"
    
    if [[ "$KEEP_INSTANCES" == "true" ]]; then
        echo -e "${YELLOW}--keep-instances specified, skipping cleanup${NC}"
        echo "Instances:"
        echo "  - $NUCLEUS_NAME ($NUCLEUS_REGION)"
        echo "  - $NODE_A_NAME ($NODE_A_REGION)"
        echo "  - $NODE_B_NAME ($NODE_B_REGION)"
        return
    fi
    
    delete_instance "$NUCLEUS_NAME" "$NUCLEUS_REGION"
    delete_instance "$NODE_A_NAME" "$NODE_A_REGION"
    delete_instance "$NODE_B_NAME" "$NODE_B_REGION"
    
    echo -e "\n${GREEN}All instances cleaned up!${NC}"
}

# =============================================================================
# Main
# =============================================================================

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --secret)
            CLUSTER_SECRET="$2"
            shift 2
            ;;
        --ssh-key-name)
            SSH_KEY_PAIR_NAME="$2"
            shift 2
            ;;
        --ssh-key-path)
            SSH_KEY_PATH="$2"
            shift 2
            ;;
        --duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        --keep-instances)
            KEEP_INSTANCES=true
            shift
            ;;
        --no-ipv6)
            NO_IPV6=true
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
if [[ -z "$CLUSTER_SECRET" ]]; then
    print_error "--secret is required (min 16 chars)"
    show_help
    exit 1
fi

if [[ ${#CLUSTER_SECRET} -lt 16 ]]; then
    print_error "Cluster secret must be at least 16 characters"
    exit 1
fi

# Trap to ensure cleanup on exit
trap cleanup_instances EXIT

print_header "OmniNervous AWS Lightsail Auto-Test"
echo "Instance Prefix: $INSTANCE_PREFIX"
echo "Nucleus:         $NUCLEUS_AZ"
echo "Edge A:          $NODE_A_AZ"
echo "Edge B:          $NODE_B_AZ"
echo "Bundle:          $BUNDLE_ID (~\$5/month)"
echo "SSH Key:         $SSH_KEY_PAIR_NAME"

# Pre-flight checks
print_header "Pre-flight Checks"
check_aws_cli

# Check for binary
if [[ ! -f "$SCRIPT_DIR/omninervous-linux-amd64" ]]; then
    print_error "Binary not found: $SCRIPT_DIR/omninervous-linux-amd64"
    echo "Build with: docker build --platform linux/amd64 -t omninervous-builder ."
    exit 1
fi
echo -e "  ✅ Binary found: omninervous-linux-amd64"

# Check SSH key
if [[ ! -f "$SSH_KEY_PATH" ]]; then
    print_error "SSH key not found: $SSH_KEY_PATH"
    echo "Download from Lightsail console or set SSH_KEY_PATH"
    exit 1
fi
echo -e "  ✅ SSH key found: $SSH_KEY_PATH"

# =============================================================================
# Create Instances
# =============================================================================

print_header "Creating Lightsail Instances"

create_instance "$NUCLEUS_NAME" "$NUCLEUS_REGION" "$NUCLEUS_AZ"
create_instance "$NODE_A_NAME" "$NODE_A_REGION" "$NODE_A_AZ"
create_instance "$NODE_B_NAME" "$NODE_B_REGION" "$NODE_B_AZ"

# Wait for all instances to be running
echo ""
wait_for_instance "$NUCLEUS_NAME" "$NUCLEUS_REGION"
wait_for_instance "$NODE_A_NAME" "$NODE_A_REGION"
wait_for_instance "$NODE_B_NAME" "$NODE_B_REGION"

# Get IPs
NUCLEUS_IP=$(get_instance_ip "$NUCLEUS_NAME" "$NUCLEUS_REGION")
NODE_A_IP=$(get_instance_ip "$NODE_A_NAME" "$NODE_A_REGION")
NODE_B_IP=$(get_instance_ip "$NODE_B_NAME" "$NODE_B_REGION")

print_header "Instance IPs"
echo "Nucleus: $NUCLEUS_IP ($NUCLEUS_AZ)"
echo "Edge A:  $NODE_A_IP ($NODE_A_AZ)"
echo "Edge B:  $NODE_B_IP ($NODE_B_AZ)"

# Open all ports
print_header "Configuring Firewalls"
open_all_ports "$NUCLEUS_NAME" "$NUCLEUS_REGION"
open_all_ports "$NODE_A_NAME" "$NODE_A_REGION"
open_all_ports "$NODE_B_NAME" "$NODE_B_REGION"

# Enable IPv6 (unless --no-ipv6 specified)
if [[ "$NO_IPV6" != "true" ]]; then
    print_header "Enabling IPv6 Networking"
    enable_ipv6 "$NUCLEUS_NAME" "$NUCLEUS_REGION"
    enable_ipv6 "$NODE_A_NAME" "$NODE_A_REGION"
    enable_ipv6 "$NODE_B_NAME" "$NODE_B_REGION"
fi

# Wait for SSH
print_header "Waiting for SSH Access"
wait_for_ssh "$NUCLEUS_IP"
wait_for_ssh "$NODE_A_IP"
wait_for_ssh "$NODE_B_IP"

# Install dependencies
print_header "Installing Dependencies"
install_dependencies "$NUCLEUS_IP"
install_dependencies "$NODE_A_IP"
install_dependencies "$NODE_B_IP"

# =============================================================================
# Run Cloud Test
# =============================================================================

print_header "Running OmniNervous Cloud Test"

USERSPACE_FLAG=""
if [[ "$USERSPACE" == "true" ]]; then
    USERSPACE_FLAG="--userspace"
fi

IPV6_FLAG=""
if [[ "$NO_IPV6" == "true" ]]; then
    IPV6_FLAG="--no-ipv6"
fi

"$SCRIPT_DIR/cloud_test.sh" \
    --nucleus "$NUCLEUS_IP" \
    --node-a "$NODE_A_IP" \
    --node-b "$NODE_B_IP" \
    --ssh-key "$SSH_KEY_PATH" \
    --ssh-user ubuntu \
    --secret "$CLUSTER_SECRET" \
    --duration "$TEST_DURATION" \
    $USERSPACE_FLAG \
    $IPV6_FLAG

# =============================================================================
# Summary
# =============================================================================

print_header "Test Complete"
echo -e "┌─────────────────────────────────────────────────────────┐"
echo -e "│  ${GREEN}AWS LIGHTSAIL AUTO-TEST COMPLETE${NC}                        │"
echo -e "├─────────────────────────────────────────────────────────┤"
echo -e "│  Nucleus: $NUCLEUS_IP ($NUCLEUS_AZ)"
echo -e "│  Edge A:  $NODE_A_IP ($NODE_A_AZ)"
echo -e "│  Edge B:  $NODE_B_IP ($NODE_B_AZ)"
echo -e "├─────────────────────────────────────────────────────────┤"
echo -e "│  Results: ./test_results/cloud_test_*.json"
echo -e "│  Logs:    ./test_results/*.log"
echo -e "└─────────────────────────────────────────────────────────┘"

echo -e "\n${GREEN}✅ AWS Lightsail auto-test completed!${NC}"
echo -e "${YELLOW}Instances will be deleted automatically...${NC}"
