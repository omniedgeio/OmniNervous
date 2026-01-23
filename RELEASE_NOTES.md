# Release Notes

## v0.2.3: Security Hardening & Zero-Config Roadmap

**Date:** 2026-01-23

This release focuses on hardening the security posture with HMAC signaling authentication and Identity Pinning (TOFU), alongside a rebranding to **omninervous** and preparation for a unified userspace data plane.

### 🛡️ Security Hardening

*   **HMAC-SHA256 Signaling**: All signaling messages (REGISTER, HEARTBEAT, etc.) are now authenticated using a Cluster Secret, preventing unauthorized node registration.
*   **Identity Pinning (TOFU)**: Implemented "Trust On First Use" for peer identities. Once a Virtual IP is claimed by a public key, it is pinned to that key, preventing Man-in-the-Middle attacks.
*   **Cryptographic Strength**: Switched to `rand::rngs::OsRng` for secure private key generation.
*   **File Permissions**: Enforced `0600` permissions on identity files for secure userspace storage.

### 🚀 Major Achievements

*   **Omninervous Rebranding**: The project has been fully rebranded to `omninervous` across all packages, binaries, and documentation.
*   **STUN Fallback Mechanism**: Implemented a multi-stage NAT discovery system that attempts public STUN (Google) and falls back to a built-in STUN service on the Nucleus.
*   **371.35 Mbps Breakthrough**: Achieved a new throughput milestone in Jan 23 cloud tests, demonstrating 107.5% baseline efficiency.

### 📊 Benchmark Results (Jan 23 Cloud Test)

| Metric | v0.2.2 | v0.2.3 (Refined) | Improvement |
| :--- | :--- | :--- | :--- |
| **Throughput** | 133.24 Mbps | **371.35 Mbps** | **+178%** |
| **Efficiency** | 97.2% | **107.5%** | **+10.3%** |

### 🛠️ Changes

*   **Rebranding**: Renamed package and binary to `omninervous` in `Cargo.toml`, `Dockerfile`, and all scripts.
*   **Signaling**: Added `MSG_STUN_QUERY` and `MSG_STUN_RESPONSE` to the signaling protocol.
*   **STUN**: Implemented a standard STUN binding request client with XOR-MAPPED-ADDRESS support.

## v0.2.2: Phase 7.2 Milestone - "90%+ Baseline Performance Optimization"

**Date:** 2026-01-20

This release marks a significant performance milestone, achieving **97.2% baseline efficiency** in cloud environments by integrating hardware-accelerated AES-GCM and optimizing the data plane logging architecture.

### 🚀 Major Achievements

*   **97.2% Efficiency Breakthrough**: Achieved 133.24 Mbps VPN throughput on a 137.02 Mbps baseline—nearly eliminating the virtualization overhead.
*   **Hardware-Accelerated AES-GCM**: Integrated AES256-GCM support for Noise protocol, yielding significant performance gains on AES-NI enabled CPUs.
*   **Data Plane Optimization**: Downgraded per-packet signaling logs to `DEBUG`, eliminating blocking disk I/O bottlenecks and ensuring stable high-throughput streams.
*   **CLI Flexibility**: Introduced the `--cipher` flag with support for `aesgcm` and `chachapoly` (with `chacha` alias for legacy compatibility).

### 📊 Benchmark Results (Cloud 3-Node)

| Metric | v0.2.1 (eBPF Fixed) | v0.2.2 (AES-GCM Optimized) | Improvement |
| :--- | :--- | :--- | :--- |
| **Throughput** | 105.26 Mbps | **133.24 Mbps** | **+26.6%** |
| **Latency Overhead** | 0.8 ms | **0.4 ms** | **-50%** |
| **Efficiency** | 75.8% | **97.2%** | **+28.2%** |

*Note: Benchmarks conducted on AWS Lightsail ($5 tier). AES256-GCM used for peak results.*

### 🛠️ Changes

*   **CLI**: Resolved "unexpected argument '--cipher'" error by properly integrating the argument into the `omni-daemon` parser.
*   **Cryptography**: Added `CipherType` enum and dynamic Noise pattern selection (switching between ChaCha20 and AES-GCM).
*   **Stability**: Optimized data plane main loop by moving high-load logging to `DEBUG` level.
*   **Performance**: Improved `cloud_test.sh` reliability on small instances by reducing default log verbosity.

---


## v0.2.1: Phase 7.1 Complete - "Real-World Cloud Testing & Validation"

**Date:** 2026-01-18

This release completes **Phase 7.1: Performance Optimization & Production Readiness** by resolving eBPF loading issues and achieving enterprise-grade throughput in cloud environments.

### 🚀 Major Achievements

*   **eBPF/XDP Loading Issue RESOLVED**: Root cause identified as aya version incompatibility. Fixed by aligning aya runtime (0.13.0) with eBPF program compilation (aya-ebpf 0.1).
*   **Performance Breakthrough**: 75.8% baseline efficiency achieved (105.26 Mbps VPN throughput vs. 138.80 Mbps baseline).
*   **Hybrid Architecture**: Kernel packet routing (eBPF) + Userspace crypto (ChaCha20-Poly1305) for optimal performance.
*   **Production Ready**: Docker deployment, comprehensive error handling, and cloud validation.

### 📊 Benchmark Results (Cloud 3-Node)

| Metric | v0.2.0 (XDP Enabled) | v0.2.1 (eBPF Fixed) | Improvement |
| :--- | :--- | :--- | :--- |
| **Throughput** | 94.46 Mbps | **105.26 Mbps** | **+11.4%** |
| **Latency** | 55.24 ms | **55.23 ms** | Stable |
| **Efficiency** | ~54% | **75.8%** | **+40.4%** |

*Note: Efficiency measured against raw iperf3 baseline. Target for v0.3.0: 90%+ with AF_XDP integration.*

### 🛠️ Changes

*   **eBPF Compatibility**: Resolved "error parsing ELF data" by ensuring aya 0.13.0 runtime compatibility.
*   **Cryptography**: Finalized ChaCha20-Poly1305 as the sole cipher suite for Noise protocol. Removed AES256-GCM support due to snow library limitations.
*   **Build System**: Verified multi-stage Docker builds with embedded eBPF bytecode.
*   **Testing Infrastructure**: Automated cloud deployment scripts and throughput validation.

---

## v0.2.0: Phase 5 Complete - "Cloud Testing"

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

## v0.1.0: Phase 1-4 Foundation - "Ganglion Core"

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
