# Release Notes

## v0.2.0: Synapse Activation - "eBPF/XDP"

**Date:** 2026-01-17

This release activates the **Synapse Data Plane** by successfully embedding and loading the compiled eBPF/XDP kernel program.

### 🚀 Performance Optimizations

*   **eBPF Compilation**: Integrated `bpf-linker` and Rust nightly toolchain into the Docker build process to compile the `omni-ebpf` kernel component.
*   **Embedded Bytecode**: `omni-daemon` now ships with the actual XDP bytecode matching the daemon version, replacing the previous placeholder.

### 📊 Benchmark Results (Cloud 3-Node)

| Metric | v0.1.0 (Userspace) | v0.2.0 (XDP Enabled*) | Improvement |
| :--- | :--- | :--- | :--- |
| **Throughput** | ~80 Mbps | **94.46 Mbps** | **+18%** |
| **Latency** | 55.40 ms | **55.24 ms** | Stable |
| **Efficiency** | ~53% | ~54% | Baseline dependant |

*> Note: Efficiency is currently similar to userspace, suggesting further optimization (batching/GRO) is needed in the XDP path for >100Mbps targets.*

### 🛠️ Changes

*   **Build System**: Multi-stage Dockerfile with `rust-nightly` and `llvm` dependencies.
*   **Infrastructure**: Fixed Docker build I/O errors and network timeouts.

---

## v0.1.0: Core Foundation - "Ganglion"

**Date:** 2026-01-16

This is the first stable release of **OmniNervous**, the identity-driven Layer 2 fabric for AI and Robotics. This release establishes the "Ganglion" control plane and userspace data path.

### 🌟 Key Features

*   **Secure P2P Signaling**: "Nucleus" server architecture for signaling and peer discovery behind NATs.
*   **Cryptographic Identity**: Ed25519-based identity generation and verification.
*   **Authenticated Handshake**: `Noise_IKpsk1` protocol (ChaCha20-Poly1305) with pre-shared key (PSK) cluster authentication.
*   **Session Stability**: Robust session management with automatic ID persistence and 64-bit replay protection.
*   **Cross-Platform Tunneling**: Userspace TUN support (Layer 3) for Linux, macOS, and Windows.

### 🐛 Bug Fixes & Stability

*   **Critical Session Fix**: Resolved an issue where session IDs would rotate unnecessarily on every heartbeat, causing connection drops.
*   **Handshake Reliability**: Fixed PSK index mismatch in Noise protocol implementation.
*   **Heartbeat Tuning**: optimized heartbeat interval to 30s for maximum network stability.

### ⚠️ Known Limitations

*   **Userspace Only**: eBPF/XDP hardware acceleration is implemented but currently disabled due to loading issues. Throughput is limited to ~80 Mbps (userspace CPU bottleneck).
*   **Throughput**: ~53% efficiency compared to kernel WireGuard. (Target for v0.2.0: >90%).

### 🧪 Validation

*   **Latency**: Verified <1ms overhead.
*   **Topology**: Validated detailed 3-node cloud topology (Nucleus + 2 Edges).
