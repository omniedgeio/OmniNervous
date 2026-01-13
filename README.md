# OmniNervous: The 2026 AI Fabric L2 Protocol

> [!IMPORTANT]
> **OmniNervous** is a next-generation, identity-driven Layer 2 fabric implemented entirely in **Rust**. It is designed for AI clusters and real-time humanoid robotics where low latency and cryptographic certainty are non-negotiable.

## 🧠 Architecture Overview

OmniNervous dissolves the "Network Tax" by splitting the protocol into two specialized layers:

- **Ganglion (Control Plane)**: An asynchronous Rust daemon (`tokio`) that handles high-level "Intellectual" tasks—Identity management, Noise handshakes, and NAT traversal.
- **Synapse (Data Plane)**: A zero-copy XDP engine (`aya`) that intercepts and process packets at the driver level, providing **Cryptographic Silence** (stealth mode).

```mermaid
graph TB
    subgraph Peer_A["🤖 Robot A"]
        GA[Ganglion<br/>Control Plane]
        SA[Synapse<br/>XDP Engine]
    end
    
    subgraph Nucleus["☁️ Nucleus"]
        NR[Rendezvous<br/>Server]
    end
    
    subgraph Peer_B["🤖 Robot B"]
        GB[Ganglion<br/>Control Plane]
        SB[Synapse<br/>XDP Engine]
    end
    
    GA -.->|1. Register| NR
    GB -.->|1. Register| NR
    NR -.->|2. Exchange Endpoints| GA
    NR -.->|2. Exchange Endpoints| GB
    SA <-->|3. Direct P2P<br/>Encrypted L2| SB
    
    style SA fill:#2d5a3d
    style SB fill:#2d5a3d
    style NR fill:#4a4a6a

```

## 🚀 Getting Started

### Prerequisites

| Component | Requirement |
| :--- | :--- |
| **Rust** | Stable 1.79.0+ |
| **Linux Kernel** | 5.15+ (with BPF/XDP support) |
| **BPF Linker** | `cargo install bpf-linker` |

### 🛠️ Building

#### 1. The Ganglion Daemon
The userspace daemon is gated and can be verified across platforms (macOS/Linux).
```bash
cargo build -p omni-daemon
```

#### 2. The Synapse Engine (Linux Only)
To compile the eBPF kernel program:
```bash
cargo build -p omni-ebpf-core
```
The resulting binary will be found in `target/bpfel-unknown-none/debug/omni-ebpf`.

### 🧪 Testing & Deployment

#### 🖥️ Platform Support

- **Linux (High-Performance)**:
  Uses the **Synapse XDP Engine** for zero-copy data paths. Direct frame injection bypasses the kernel network stack.
  ```bash
  sudo ./target/release/omni-daemon --iface eth0
  ```
- **macOS (Development/Fallback)**:
  Operates in **Userspace Mode** via a Virtual TUN/TAP interface. Suitable for control-plane verification and remote management.
  ```bash
  ./target/release/omni-daemon --iface utun0
  ```

#### 🌐 Remote Testing (Peer-to-Peer)

To establish a link between two remote devices (e.g., Robot A and Cloud Node B):

1.  **Identity Exchange**: Both peers generate an Ed25519 keypair.
2.  **Configuration**:
    - **Peer A**: `./omni-daemon --peer <PUBKEY_B> --endpoint <IP_B>:51820`
    - **Peer B**: `./omni-daemon --peer <PUBKEY_A> --endpoint <IP_A>:51820`
3.  **Verification**: Once the Noise handshake completes, Ping the virtual L2 addresses.

#### 📡 The Nucleus (Rendezvous Server)

OmniNervous uses a **Nucleus** to facilitate connectivity behind NAT/Firewalls:
- Unlike an L3 VPN, the Nucleus only handles **Signaling** (discovery and hole-punching).
- Data traffic is strictly **P2P** via the Synapse engine.
- If P2P is impossible, the Nucleus can act as a fallback relay (Transparent L2 Relay).

#### 🧪 Local Cluster Simulation (Docker)

To verify the "Neural Path" of a full cluster on your local machine:
```bash
./scripts/run_local_autotest.sh
```
This single command handles the entire lifecycle:
1.  **Cleanup**: Removes any legacy containers/networks.
2.  **Startup**: Spawns a `Nucleus` and two `Edge` nodes.
3.  **Verification**: Runs the `tester` suite (Handshake + iperf3).
4.  **Teardown**: Gracefully stops and cleans up the test environment.

##### ✅ Latest Test Results (2026-01-13)

> **Note**: These results are from Docker containers on localhost.
> Real-world WAN performance will differ based on network conditions.

| Test | Status |
|:---|:---|
| **Nucleus Rendezvous** | ✅ ONLINE |
| **Edge A Registration** | ✅ Registered |
| **Edge B Registration** | ✅ Registered |
| **NAT Traversal** | ✅ UDP Hole Punch SUCCESS |
| **Direct P2P Channel** | ✅ ESTABLISHED |
| **Noise_IK Handshake** | ✅ COMPLETED |
| **FDB Learning** | ✅ 2 entries learned |
| **iperf3 (localhost)** | ✅ Functional* |

*\* Localhost benchmarks validate functionality, not production throughput.*

#### ☁️ Hybrid Cloud Connectivity

To test connectivity between your local machine and a remote cloud service:

1.  **Deploy Nucleus to Cloud**: Use the helper script to set up a signaling node on a VPS (e.g., AWS, GCP, DigitalOcean).
    ```bash
    ./scripts/deploy_nucleus.sh <user@remote-ip> [ssh-key-path]
    ```
2.  **Connect Local Edge**: Launch the daemon on your local machine pointing to the remote IP.
    ```bash
    ./omni-daemon --nucleus <REMOTE_PUBLIC_IP> --cluster cloud-test
    ```
3.  **Verify Handshake**: Monitor logs to confirm the Noise session is established through the public internet.

### 🪜 Peer Usage Flow

Using OmniNervous is designed to be as simple as plugging in a physical cable:

1.  **Initialization**: Run the daemon to generate your identity.
    ```bash
    omni-daemon --init
    # Your Public Identity: 8yYx...9a2z
    ```
2.  **Joining a Cluster**: Point your daemon to the Nucleus or a known peer.
    ```bash
    omni-daemon --nucleus nucleus.omni.io --cluster ai-robot-fleet
    ```
3.  **Discovery**: OmniNervous automatically performs the Noise handshake with authorized peers in the cluster.
4.  **Network Interaction**: A new virtual interface `omni0` appears.
    - Your applications (ROS2, etc.) use `omni0`.
    - Routing is handled by the **Synapse Engine** based on the peer's public key.

## ⚙️ Configuration

OmniNervous supports TOML configuration files. Create `~/.omni/config.toml` or use `--config`:

```toml
[daemon]
port = 51820
interface = "eth0"

[network]
nucleus = "nucleus.omni.io"
cluster = "ai-robot-fleet"

[security]
max_sessions_per_ip = 10
handshake_timeout_secs = 5

[[peers]]
public_key = "abc123..."
endpoint = "192.168.1.100:51820"
```

See [config.example.toml](config.example.toml) for all options.

## 📊 Observability

Built-in Prometheus metrics (accessible via API):
- `omni_sessions_active` — Current active sessions
- `omni_packets_rx_total` — Total packets received
- `omni_handshakes_completed_total` — Successful handshakes
- `omni_sessions_dropped_ratelimit_total` — Rate-limited connections

## 🛡️ Rate Limiting

DoS protection is enabled by default:
- **10 new sessions per IP per second**
- **5 second handshake timeout**
- **1 hour session expiration**

## 🔒 Security DNA

- **Identity-as-Address**: Routing is derived from Ed25519 Public Keys.
- **Stealth Mode**: Unauthorized packets are dropped at the XDP level, leaving no trace in OS logs or `dmesg`.
- **Memory Safety**: 100% Rust implementation provides a mathematical guarantee against buffer overflows and use-after-free vulnerabilities.

---
*© 2026 OmniEdge Inc. Engineering the Nervous System of the Future.*
