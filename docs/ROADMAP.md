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

## Phase 5: Cloud Testing ✅
- [x] 3-node cloud_test.sh (Nucleus + 2 Edges)
- [x] Real-world WAN testing (Latency overhead < 1ms)
- [x] P2P tunnel throughput benchmarks (~53% efficiency vs WireGuard)

## Phase 6: Performance Optimization (Current Focus) 🚀
- [ ] Fix eBPF/XDP loading (Currently falling back to userspace)
- [ ] Implement GRO/GSO in userspace (if XDP unavailable)
- [ ] Increase throughput extraction rate to >90% of wire speed

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
