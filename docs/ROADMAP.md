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
  - Linux: `/dev/net/tun`
  - macOS: utun (native)
  - Windows: Wintun
- [x] Virtual IP assignment (`--vip`)
- [ ] FDB learning & forwarding (TODO)
- [ ] TAP/Layer 2 for Windows (TODO: tap-windows6)

## Phase 5: Cloud Testing 🔄
- [x] 3-node cloud_test.sh (Nucleus + 2 Edges)
- [ ] Real-world WAN testing
- [ ] P2P tunnel throughput benchmarks

---

## Future Plugins

### 🎮 GPU-over-IP Plugin
> *Inspired by [Juice Labs GPU-over-IP](https://github.com/sskafandri/GPU-over-IP)*

**Goal**: Enable remote GPU access over OmniNervous L2 tunnels.

**Use Cases**:
- Humanoid robots accessing cloud GPUs for AI inference
- Industrial automation GPU pooling
- Distributed ML training across sites

**Architecture**:
```
┌─────────────┐    OmniNervous    ┌─────────────┐
│  Robot/Edge │    Encrypted     │  GPU Server │
│  (No GPU)   │ ═══════L2═════>  │  (NVIDIA)   │
│  CUDA Shim  │    P2P Tunnel    │  GPU Driver │
└─────────────┘                  └─────────────┘
```

**Features**:
- [ ] CUDA/OpenCL call interception (client-side shim)
- [ ] GPU memory transfer over L2 tunnel
- [ ] Dynamic GPU allocation & scheduling
- [ ] Sub-millisecond latency optimizations
- [ ] Multi-GPU pooling support

**Dependencies**: 
- Phase 4 (TUN interface) required ✅
- eBPF for low-latency memory transfers ✅

---

### 🤖 ROS2 Transport Plugin
**Goal**: Native ROS2 DDS transport over OmniNervous.

### 🏭 EtherCAT Bridge Plugin  
**Goal**: Industrial automation protocol bridging.

### 📊 Observability Plugin
**Goal**: Prometheus/Grafana dashboards for VPN metrics.
