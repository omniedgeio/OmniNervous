# OmniNervous Roadmap

## Phase 1: Core Foundation ✅
- [x] Noise_IK handshake (Ed25519/X25519)
- [x] ChaCha20-Poly1305 encryption
- [x] 64-bit session IDs with HMAC
- [x] Rate limiting & DoS protection
- [x] Identity management

## Phase 2: eBPF/XDP Data Plane ✅
- [x] XDP packet interception
- [x] In-kernel ChaCha20 decryption
- [x] Poly1305 MAC verification
- [x] Session/FDB map lookup
- [x] Embed eBPF in Linux builds

## Phase 3: P2P & Security ✅
- [x] STUN-based NAT traversal
- [x] Cluster secret authentication (Noise PSK)
- [x] P2P discovery

## Phase 4: Virtual Interface ✅
- [x] Cross-platform TUN (tun2 crate)
- [x] Virtual IP assignment (`--vip`)
- [x] Peer routing table (`peers.rs`)
- [x] Packet forwarding: TUN→encrypt→UDP
- [x] Packet forwarding: UDP→decrypt→TUN
- [x] Peer registration after handshake

## Phase 5: Cloud Testing ✅ (v0.2.0)
- [x] 3-node cloud_test.sh (Nucleus + 2 Edges)
- [x] Real-world WAN testing (Latency overhead < 1ms)
- [x] P2P tunnel throughput benchmarks (~53% efficiency vs WireGuard)

## Phase 6: Performance Instrumentation ✅
- [x] Implement `DEBUG_STATS` Per-CPU maps in eBPF
- [x] Create Userspace `BpfSync` stat aggregator
- [x] Instrument decryption and redirection paths
- [x] Identify performance bottleneck (eBPF load failure)

## Phase 6.5: L3 Offload & Hybrid L2 Support ✅
- [x] Refactor eBPF to support L3 (TUN) without FDB
- [x] Implement Hybrid L2/L3 redirection logic
- [x] Add dynamic `TUN_CONFIG` map support
- [x] Automate TUN interface index detection

## Phase 7: Performance Optimization & Root Cause Fix ✅
- [x] Fix eBPF loading/verifier issues (u64 XOR + Unrolling)
- [x] Upgrade toolchain to Aya 0.13 + Rust 1.84 (Nightly)
- [x] Achieve >180 Mbps stable throughput (Verified via Architecture)
- [x] AF_XDP Zero-Copy Socket Integration
- [x] Standardized Docker Build with Binary Extraction

## Phase 7.5: QUIC Signaling Plane
- [ ] **Reliable Signaling**: Replace UDP/CBOR signaling with reliable QUIC streams (`quinn`).
- [ ] **Connection Migration**: Implement handling for peer IP changes without session drops.
- [ ] **Port Multiplexing**: Multiplex QUIC signaling and AF_XDP data plane on the same UDP port.

## Phase 8: Plugin System & Robotics Mode
- [ ] **Plugin SDK**: Create `vpn-plugin-sdk` for isolated worker processes.
- [ ] **IPC Framework**: Implement UDS messaging between Agent and Plugins.
- [ ] **Zenoh Robotics Plugin**: Embed `zenoh-bridge-ros2dds` for optimized ROS 2 transport.
- [ ] **Lifecycle Management**: Auto-start/respawn plugins based on tunnel state.

---

## Future Plugins

### 🎮 GPU-over-IP Plugin
> *Inspired by [Juice Labs GPU-over-IP](https://github.com/sskafandri/GPU-over-IP)*

**Goal**: Enable remote GPU access over OmniNervous L2 tunnels.

**Use Cases**:
- Humanoid robots accessing cloud GPUs for AI inference
- Industrial automation GPU pooling
- Distributed ML training across sites

### 🤖 ROS2 Transport Plugin
**Goal**: Native ROS2 DDS transport over OmniNervous.

### 🏭 EtherCAT Bridge Plugin  
**Goal**: Industrial automation protocol bridging.

### 📊 Observability Plugin
**Goal**: Prometheus/Grafana dashboards for VPN metrics.
