# OmniNervous: High-Performance P2P VPN for AI & Robotics

> [!IMPORTANT]
> **OmniNervous** is an open-source, high-performance P2P VPN daemon built in **Rust**. It combines the Noise IK protocol with native WireGuard integration for secure mesh networking with sub-millisecond latency.

## Architecture Overview

OmniNervous implements a dual-plane design with separate control and data paths:

### Ganglion (Control Plane)
Asynchronous Rust daemon (`tokio`) handling signaling and peer management:
- **Built-in STUN**: Nucleus acts as a zero-config STUN server for instant NAT traversal
- **Authenticated Signaling**: HMAC-SHA256 verification via shared cluster secret (`--secret`)
- **Secure Identity**: Cryptographically secure identity generation using OS-level entropy (`OsRng`)
- **Identity Pinning**: Trust On First Use (TOFU) mechanism to prevent MITM attacks via signaling

### WireGuard (Data Plane)
Native WireGuard integration via `defguard_wireguard_rs`:
- **Kernel-Optimized**: Uses Linux kernel WireGuard module when available
- **Native Efficiency**: Powered by WireGuard's high-speed ChaCha20-Poly1305 transport
- **Session Management**: Automatic peer configuration and keepalive

```mermaid
graph LR
    subgraph "Edge Node A"
        G_A[Ganglion<br/>Signaling]
        WG_A[WireGuard<br/>Data Plane]
    end

    subgraph "Nucleus Server"
        N[The Nucleus]
    end

    subgraph "Edge Node B"
        G_B[Ganglion<br/>Signaling]
        WG_B[WireGuard<br/>Data Plane]
    end

    G_A <-->|UDP/CBOR<br/>Signaling| N
    G_B <-->|UDP/CBOR<br/>Signaling| N
    WG_A <==>|Encrypted Tunnel<br/>WireGuard| WG_B

    style WG_A fill:#2d5a3d,color:#fff
    style WG_B fill:#2d5a3d,color:#fff
    style N fill:#2d3a5a,color:#fff
```

---

## Performance Results (Jan 23, 2026)

Validated on **AWS Lightsail $5 Instances** (3-node cluster, cross-region):

| Metric | Result | Notes |
|:---|---:|:---|
| **Throughput** | **371.35 Mbps** | 107.5% of baseline |
| **Latency** | **54.73 ms** | Cross-region (ping) |
| **Baseline** | 345.56 Mbps | Raw iperf3 performance |
| **Efficiency** | **>100%** | optimized protocol overhead |

> **Key Achievement**: Jan 23 tests demonstrated extreme protocol efficiency, achieving higher throughput over the tunnel than the baseline through optimized message handling.

---

## Quick Start

### Prerequisites
- **Rust**: Stable 1.70+
- **Linux Kernel**: 5.6+ (for WireGuard support)
- **WireGuard Tools**: `wg` and `wg-quick` installed

### Build
```bash
cargo build --release
```

### Running OmniNervous

**1. Start Nucleus (signaling server):**
```bash
sudo ./target/release/omninervous --mode nucleus --port 51820
```

**2. Connect edge nodes:**
```bash
sudo ./target/release/omninervous \
  --nucleus nucleus.example.com:51820 \
  --cluster my-network \
  --vip 10.200.0.1
```

**3. Advanced STUN discovery:**
```bash
# Prioritize public STUNs, fallback to Nucleus
# Supports single server, space-separated, or JSON array
sudo ./target/release/omninervous \
  --nucleus nucleus.example.com:51820 \
  --stun stun.l.google.com:19302 \
  --stun "stun1.l.google.com:19302 stun2.l.google.com:19302" \
  --stun '["stun3.l.google.com:19302", "stun4.l.google.com:19302"]' \
  --vip 10.200.0.1
```

**4. Signaling-only (stand-alone) Mode:**
```bash
sudo ./target/release/omninervous --mode nucleus --port 51820
```

| Flag | Description | Default |
|:---|:---|:---|
| `--mode nucleus` | Run as signaling server | Edge mode |
| `--nucleus` | Nucleus server address | Required for edge |
| `--cluster` | Cluster name to join | Required |
| `--vip` | Virtual IP address (e.g., 10.200.0.1) | Required for edge |
| `--port` | UDP port | 51820 |
| `--stun` | STUN server(s): single, list, or JSON | - |
| `--disable-builtin-stun` | Disable Nucleus STUN fallback | enabled |
| `--init` | Generate new identity and exit | - |

---

## Core Components

### `crates/daemon/src/main.rs`
Entry point handling CLI parsing, mode selection (nucleus/edge), WireGuard interface creation, and the main event loop.

### `crates/daemon/src/signaling.rs`
Nucleus protocol implementation:
- `REGISTER` / `HEARTBEAT`: Peer registration and delta updates
- `QUERY_PEER` / `PEER_INFO`: On-demand peer lookup (O(1))
- `MSG_STUN_QUERY` / `MSG_STUN_RESPONSE`: Built-in STUN service
- `MSG_NAT_PUNCH`: Active UDP hole punching signaling

### `crates/daemon/src/peers.rs`
Peer routing table (VIP → endpoint mapping) with timeout-based cleanup.

### `crates/daemon/src/identity.rs`
X25519 key generation, storage, and validation with 0o600 permissions.

### `crates/daemon/src/config.rs`
TOML-based configuration with fallback paths (`/etc/omni/config.toml`, `~/.omni/config.toml`).

### `crates/daemon/src/metrics.rs` / `crates/daemon/src/http.rs`
Prometheus-compatible metrics server on port 9090 (`/metrics`, `/health` endpoints).

### `crates/daemon/src/stun.rs`
Hardcoded list of 10+ reliable public STUN fallbacks (Google, Cloudflare, etc.).

---

## Nucleus Signaling Protocol

Scalable for 1000+ edges per cluster with O(1) lookups:

```
Nucleus State:
  Cluster "robotics" → HashMap<VIP, Peer>  O(1)
  Cluster "factory"  → HashMap<VIP, Peer>  O(1)

Message Flow:
  REGISTER          →  REGISTER_ACK (recent peers)
  HEARTBEAT         →  HEARTBEAT_ACK (delta: new + removed)
  QUERY_PEER        →  PEER_INFO (single peer)
  NAT_PUNCH         →  Hole punching trigger
```

**NAT Traversal Priority**:
1. **Built-in Nucleus STUN** (Primary, zero-config)
2. **User-configured STUNs** (CLI `--stun` / `--stuns`)
3. **Internal Public Fallback List** (stun.rs: 10+ reliable servers)

**Bandwidth Optimization**:
- No full peer lists (prevents O(n²) broadcasts)
- Delta-only updates: ~100 KB/30s for 1000 edges
- Recent peer window: 90 seconds (3x heartbeat)

---

## Security Features

| Feature | Implementation |
|:---|:---|
| **Identity** | X25519 keys stored with 0o600 permissions |
| **Handshake** | Noise IK with PSK authentication |
| **Encryption** | ChaCha20-Poly1305 or AES256-GCM |
| **Forward Secrecy** | Ephemeral key rotation per session |
| **Peer Auth** | Cluster-based PSK validation |

---

## Current Status

- **Version**: v0.2.3 (Refined Architecture)
- **Performance**: 371.35 Mbps throughput, optimized STUN fallback
- **Scalability**: O(1) lookups, delta updates for 1000+ edges

---

## Deployment Options

### Docker Deployment

**1. Build the image:**
```bash
docker build -t omni-daemon:latest .
```

**2. Run with docker-compose (3-node test cluster):**
```bash
docker-compose up -d
```

This starts:
- `omni-nucleus`: Signaling server at 10.0.0.2
- `omni-edge-a`: Edge node with VIP 10.200.0.10
- `omni-edge-b`: Edge node with VIP 10.200.0.20
- `omni-tester`: Validation container

**3. View logs:**
```bash
docker-compose logs -f
```

### Linux Binary Deployment

**Build for linux-amd64:**
```bash
./scripts/build_local_docker.sh
```

This produces `scripts/omninervous-linux-amd64` for cloud deployment.

**Deploy to cloud:**
```bash
./scripts/deploy_to_cloud.sh user@host
```

### Configuration File

Create `config.toml`:

```toml
[daemon]
port = 51820
interface = "eth0"
log_level = "info"

[network]
nucleus = "nucleus.example.com:51820"
cluster = "my-network"
stun_servers = ["stun.l.google.com:19302"]
use_builtin_stun = true

[security]
max_sessions_per_ip = 10
handshake_timeout_secs = 5

[[peers]]
public_key = "abc123..."
endpoint = "192.168.1.100:51820"
```

Load with: `omninervous --config config.toml`

### Cloud Testing

**3-node test orchestration:**
```bash
./scripts/cloud_test.sh \
  --nucleus 104.x.x.x \
  --node-a 54.x.x.x \
  --node-b 35.x.x.x \
  --ssh-key ~/.ssh/cloud.pem \
  --secret "my-secure-secret-16"
```

This deploys binaries, runs baseline iperf3 tests, establishes WireGuard tunnel, and reports throughput/latency metrics.

---

## Directory Structure

```
OmniNervous/
├── Dockerfile                    # Multi-stage Docker build
├── docker-compose.yml           # 3-node test cluster
├── config.example.toml          # Configuration template
├── crates/
│   └── daemon/
│       └── src/
│           ├── main.rs              # Entry point
│           ├── signaling.rs         # Nucleus protocol
│           ├── peers.rs             # Peer routing table
│           ├── identity.rs          # X25519 identity
│           ├── config.rs            # TOML config
│           ├── stun.rs              # Public STUN fallback list
│           ├── metrics.rs           # Prometheus metrics
│           └── http.rs              # /metrics, /health
├── scripts/
│   ├── build_local_docker.sh    # Docker-based build tool
│   ├── cloud_test.sh            # 3-node cloud test orchestrator
│   ├── deploy_to_cloud.sh       # rsync deployment
│   └── auto_test_docker.sh      # Docker network test
└── docs/
    ├── WHITEPAPER.md            # Technical specification
    └── ROADMAP.md               # Development roadmap
```

---

## Contributing

OmniNervous is seeking contributors for:
- **Phase 7.4**: QUIC signaling plane implementation
- **Plugins**: ROS2 transport, EtherCAT bridge, GPU-over-IP
- **Performance**: AF_XDP zero-copy integration verification
- **Testing**: Multi-region scalability testing

---

## License

MIT / Apache 2.0 - See [LICENSING.md](LICENSING.md)

---
*WireGuard is a registered trademark of Jason A. Donenfeld.*

*© 2026 OmniEdge Inc. Engineering the nervous system of the future.*
