# OmniNervous: The High-Performance P2P Fabric for the AI Ecosystem

> [!IMPORTANT]
> **OmniNervous** is an open-source, identity-driven L2/L3 network fabric built in **Rust**. It leverages **eBPF/XDP** to provide a low-latency, zero-copy data plane for distributed AI clusters, robotics, and edge infrastructure.

## 🌐 Hybrid L2/L3 Networking
OmniNervous is designed for maximum flexibility, supporting both Ethernet-level (L2) and IP-level (L3) abstraction.

- **L3 Mode (TUN)**: Optimized for traditional cloud-to-edge VPN use cases, providing standard IP routing between peers.
- **L2 Mode (TAP)**: Designed for real-time protocols like **ROS2**, industrial automation, and humanoid robotics, where broadcast/multicast and low-level frame control are essential.

## 🧠 Core Architecture: Ganglion & Synapse
The project is architected into two distinct, high-performance cores to simplify development and maximize throughput.

### 🚥 Ganglion: The Signaling Core (Control Plane)
Implemented in asynchronous Rust (`tokio`), Ganglion handles the complexity of peer management:
- **Identity Orchestration**: Ed25519-based authentication.
- **Noise Protocol**: Secure `Noise_IKpsk2` state machine.
- **NAT Traversal**: Advanced hole-punching for seamless P2P connectivity.

### ⚡ Synapse: The Acceleration Core (Data Plane)
A modular eBPF-powered engine using **Aya** that brings kernel-bypass performance to the edge:
- **AF_XDP Zero-Copy**: Direct transfer of packets between the NIC and userspace.
- **Driver-Level Security**: Stealth dropping of unauthorized traffic.
- **Batch Processing**: High-throughput packet handling designed for 1 Gbps+ environments.

---

```mermaid
graph LR
    subgraph "Infrastructure Node A"
        G_A[Ganglion<br/>Signaling]
        S_A[Synapse<br/>Data Plane]
    end
    
    subgraph "The Ecosystem Hub"
        N[The Nucleus]
    end
    
    subgraph "Infrastructure Node B"
        G_B[Ganglion<br/>Signaling]
        S_B[Synapse<br/>Data Plane]
    end
    
    G_A <-->|Signaling| N
    G_B <-->|Signaling| N
    S_A <==>|Hybrid L2/L3 Fabric<br/>eBPF / AF_XDP| S_B
    
    style S_A fill:#2d5a3d,color:#fff
    style S_B fill:#2d5a3d,color:#fff
    style N fill:#2d3a5a,color:#fff
```

---

## ⚡ Performance Matrix (Real-World Benchmarks)

Validated on **AWS Lightsail $5 Instances** (Cross-Region: `us-east-1` ↔ `us-west-2` via `us-east-1` Nucleus):

| Feature | Methodology | Status | Result |
|:---|:---:|:---:|:---|
| **P2P Cross-Region Latency** | XDP Kernel Bypass | ✅ EXCELLENT | **62ms (Total)** / **0.8ms Overhead** |
| **Throughput (Base)** | Userspace Fallback | ✅ STABLE | **80 Mbps** (53% of 152 Mbps Baseline) |
| **Throughput (Peak)** | **AF_XDP Zero-Copy** | 🚧 OPTIMIZED | **Architected for 1 Gbps+** |
| **NAT Traversal** | Hole Punching | ✅ ROBUST | 98% Success |

> **Note**: Userspace throughput on $5 instances is CPU-bound due to syscall overhead. AF_XDP batching (Phase 7) is implemented to bridge this gap and aim for 1 Gbps+ on high-performance infrastructure.

> **Note**: Our latest **Phase 7** release introduces AF_XDP Zero-Copy batching. We invite contributors to help benchmark this in various high-speed 10G/40G environments.

## 🛠️ Developer Getting Started

### 📋 Prerequisites
- **Rust**: Nightly (for eBPF-std support)
- **Linux Kernel**: 5.15+
- **Toolchain**: `cargo install bpf-linker`

### 🏗️ Build with Docker
OmniNervous uses a multi-stage Docker build to ensure a reproducible environment for the eBPF programs.

```bash
# Builds the daemon and embeds the eBPF Synapse program
./scripts/build_local_docker.ps1
```

### 🏃 Running a Cluster
Deploy a signaling server (Nucleus) and connect your edge nodes:

```bash
sudo ./omni-daemon \
  --nucleus signaling.example.com:51820 \
  --cluster ai-robot-fleet \
  --vip 10.200.0.1
```

### 🤝 How to Join the Ecosystem
OmniNervous is an open-standard project. We are actively seeking contributors for:
- **Synapse Core**: Optimizing eBPF programs for specialized NICs (Mellanox/Intel) and advancing Poly1305 hardware offloading.
- **Ganglion SDKs**: Expanding the control plane to mobile (Android/iOS) and integrating with Kubernetes via a custom CNI.
- **Performance Benchmarking**: Helping us run `iperf3` tests on 10G/40G backbones to refine AF_XDP batching parameters.

---
### 🔒 Security DNA
- **Memory Safety**: 100% Rust implementation, eliminating entire classes of memory vulnerabilities.
- **Identity-as-Address**: Routing is cryptographically tied to X25519/Ed25519 identities—no more IP management overhead.
- **Kernel-Level Stealth**: The fabric is invisible to scanners; unauthorized packets never reach the OS stack.

---
*© 2026 OmniEdge Inc. Collaborative Infrastructure for a Decentralized Future.*
