# Release Notes

## v0.5.0: L2 VPN & Userspace Improvements

**Date:** 2026-02-04

This release introduces a Linux-only L2 VPN transport mode with TAP-based bridging, fragmentation/reassembly, and Prometheus metrics. It also improves userspace WireGuard integration and CI test coverage for L2/L3 modes.

### New Features

*   **L2 VPN Transport (Linux)**: New `--transport-mode l2` with TAP-based Layer 2 bridging (feature flag `l2-vpn`).
*   **L2 Fragmentation/Reassembly**: Robust L2 frame splitting and reassembly for MTU-safe transport.
*   **L2 Metrics**: New Prometheus counters for L2 TX/RX, fragments, and reassembly drops.
*   **Userspace WG Improvements**: Userspace key encoding fixes and socket binding updates.

### Configuration / CLI

*   `--transport-mode l2` enables L2 transport on Linux.
*   `--l2-mtu` sets the TAP MTU when L2 mode is enabled.

### CI / Testing

*   Added a dual-mode L3 + L2 Docker integration test flow in GitHub Actions.
*   Local script `scripts/local_l2_l3_docker_test.sh` mirrors CI behavior.

### Code Changes

| File | Change |
|:---|:---|
| `crates/daemon/src/l2.rs` | L2 TAP, encryption, fragmentation/reassembly, metrics |
| `crates/daemon/src/metrics.rs` | L2 counters exported to Prometheus |
| `crates/daemon/src/main.rs` | L2 transport wiring, userspace key handling |
| `crates/daemon/src/handler.rs` | Userspace WG peer key encoding |
| `.github/workflows/test.yml` | L2/L3 integration flow |
| `scripts/local_l2_l3_docker_test.sh` | Local Docker test harness |

---

## v0.4.0: IPv6 Dual-Stack & Enhanced Signaling

**Date:** 2026-02-02

This release delivers complete IPv6 dual-stack support with enhanced signaling protocol messages and configurable Happy Eyeballs connection racing. The release builds on v0.3.0's NAT traversal foundation to provide seamless IPv4/IPv6 connectivity.

### New Features

*   **IPv6 Signaling Support**: Extended `QueryPeerMessage` with `target_vip_v6` and `requester_vip_v6` fields for IPv6-first peer lookups.
*   **DiscoPong IPv6**: Added `responder_vip_v6` field to disco pong responses, enabling IPv6 endpoint discovery.
*   **Configurable Happy Eyeballs**: The `happy_eyeballs_delay_ms` config option now properly flows through to the connection racing algorithm.
*   **IPv6 Validation**: Added `is_private_ip_v6()` validation in MSG_QUERY_PEER handler to ensure only valid ULA addresses are used.

### API Changes

| Message | New Fields | Description |
|:---|:---|:---|
| `QueryPeerMessage` | `target_vip_v6`, `requester_vip_v6` | IPv6 VIPs for dual-stack peer queries |
| `DiscoPong` | `responder_vip_v6` | Responder's IPv6 VIP in pong replies |

### Configuration

New config options in `[network]` section:

```toml
[network]
prefer_ipv6 = true                # Prefer IPv6 when available
happy_eyeballs_delay_ms = 250     # Delay before IPv4 fallback (RFC 8305)
```

### Code Changes

| File | Change |
|:---|:---|
| `signaling.rs` | Added IPv6 fields to QueryPeerMessage and DiscoPong structs |
| `signaling.rs` | Added `query_peer_by_v6()` method to NucleusClient |
| `signaling.rs` | IPv6 validation in MSG_QUERY_PEER handler |
| `handler.rs` | Added `happy_eyeballs_delay_ms` to DiscoConfig |
| `handler.rs` | Use `ConnectionRace::with_delay()` for configurable racing |
| `main.rs` | Pass config's `happy_eyeballs_delay_ms` to MessageHandler |

### Tests

*   All 71 unit tests passing
*   Happy Eyeballs tests validate custom delay configuration

---

## v0.3.0: NAT Traversal Enhancement - Complete Implementation

**Date:** 2026-01-30

This major release delivers comprehensive NAT traversal capabilities, enabling reliable peer-to-peer connectivity across all NAT types including symmetric NAT. The release integrates 7 phases of development with extensive security hardening from code review.

### 🚀 Major Achievements

*   **Universal NAT Traversal**: Full support for all NAT types (Full Cone, Restricted, Port-Restricted, Symmetric) with automatic fallback strategies.
*   **Relay Infrastructure**: Production-ready relay server/client for symmetric NAT scenarios where direct P2P is impossible.
*   **Encrypted Signaling**: End-to-end encrypted signaling using X25519 key exchange + XSalsa20-Poly1305 AEAD.
*   **Dual-Stack IPv6**: Native IPv4/IPv6 dual-stack support with Happy Eyeballs (RFC 8305) connection racing.
*   **Prometheus Metrics**: Comprehensive observability with 20+ metrics covering NAT, relay, disco, and connection state.

### 🛡️ Security Hardening (Code Review)

*   **Timing Attack Protection**: HMAC verification uses constant-time comparison (`subtle::ConstantTimeEq`).
*   **DoS Protection**: LRU cache (1000 entries) for crypto boxes prevents unbounded memory growth.
*   **Secret Zeroization**: `ZeroizeOnDrop` ensures cryptographic secrets are cleared from memory.
*   **Rate Limiting**: Reduced initial rate limit bucket from 10MB to 1MB.
*   **Counter Safety**: Saturating subtraction prevents atomic counter underflow.

### 📊 New Modules

| Module | Description |
|:---|:---|
| `netcheck.rs` | NAT type detection using STUN servers |
| `portmap.rs` | NAT-PMP/UPnP port mapping client |
| `relay.rs` | Relay server and client for symmetric NAT |
| `endpoint.rs` | Multi-path endpoint management with latency tracking |
| `socket.rs` | Dual-stack IPv4/IPv6 socket abstraction |
| `happy_eyeballs.rs` | RFC 8305 connection racing implementation |

### 🛠️ Changes

*   **Dependencies**: Added `crypto_box`, `lru`, `subtle`, `zeroize` crates.
*   **API Surface**: Complete `lib.rs` rewrite with comprehensive documentation and re-exports.
*   **CI/CD**: Added lint job (rustfmt + clippy), cargo caching, updated security summary.
*   **Tests**: 49 unit tests covering all new functionality.

---

## v0.2.7: CI/CD Improvements & Clippy Compliance

**Date:** 2026-01-30

This release focuses on CI/CD pipeline improvements and code quality enforcement.

### 🛠️ CI/CD Improvements

*   **Lint Job**: Added new `lint` job with `rustfmt` and `clippy` checks (warnings as errors).
*   **Cargo Caching**: Added `actions/cache@v4` for cargo registry/git across all workflows.
*   **Job Dependencies**: Proper pipeline flow: `lint` → `unit-tests` → `vpn-integration`.
*   **Branch Triggers**: Added `feature/*` branch trigger for test workflow.
*   **Security Summary**: Updated job summary with NAT traversal security features.

### 🧹 Code Quality

*   Fixed all clippy warnings across the codebase:
    - Removed needless borrows in `BASE64.encode()` calls
    - Used `.clamp()` instead of `.max().min()` pattern
    - Used `.is_multiple_of()` for modulo checks
    - Used `.contains()` for range checks
    - Removed redundant imports
    - Prefixed intentionally unused variables with `_`
    - Added `#[allow(dead_code)]` for reserved fields

---

## v0.2.6: Code Review Security Fixes

**Date:** 2026-01-30

This release addresses all security and code quality issues identified in the comprehensive code review of the NAT traversal implementation.

### 🛡️ Security Fixes

*   **HMAC Constant-Time Comparison**: Replaced standard `!=` with `subtle::ConstantTimeEq` to prevent timing attacks on HMAC verification.
*   **LRU Cache for Crypto Boxes**: Added bounded LRU cache (1000 entries) to `SignalingEncryption.peer_boxes` to prevent memory exhaustion attacks.
*   **ZeroizeOnDrop**: Added `#[derive(ZeroizeOnDrop)]` to `SignalingEncryption` to ensure secrets are cleared on drop.
*   **Rate Limit Bucket**: Reduced initial relay rate limit bucket from 10MB to 1MB to prevent burst abuse.

### 🐛 Bug Fixes

*   **Atomic Counter Underflow**: Changed `dec_sessions()`, `dec_relay_sessions()`, `dec_portmap_active()` to use saturating subtraction.
*   **RTT Truncation**: Fixed potential u128→u64 truncation in Happy Eyeballs RTT calculation using saturating conversion.
*   **Error Context**: Added `.context()` to IPv4-only receive path for better error diagnostics.

### 🧹 Code Quality

*   **PeerInfo Rename**: Renamed `peers::PeerInfo` to `PeerEntry` to avoid collision with `signaling::PeerInfo`.
*   **Unused Constants**: Marked intentionally unused portmap constants with `#[allow(dead_code)]`.
*   **Improved Unwrap**: Added descriptive `.expect()` message to endpoint candidate sorting.
*   **lib.rs Rewrite**: Complete rewrite with crate-level documentation and comprehensive re-exports.

### 📦 Dependencies Added

```toml
crypto_box = "0.9"
lru = "0.12"
subtle = "2.5"
zeroize = { version = "1.7", features = ["derive"] }
```

---

## v0.2.5: Protocol Alignment & Master Dispatcher

**Date:** 2026-01-24

This release addresses critical architectural issues identified in the v0.2.4 rollout, specifically resolving protocol collisions between signaling and WireGuard traffic, and fixing multi-peer handshake selection in userspace mode.

### 🚀 Major Achievements

*   **Protocol Collision RESOLVED**: Re-indexed all signaling messages to `0x11`+ to eliminate overlap with the WireGuard protocol (1-4). This ensures 100% reliable packet routing on a shared UDP socket.
*   **Master UDP Dispatcher**: Refactored the daemon to use a single "Master" receiver loop, eliminating socket contention and non-deterministic packet delivery.
*   **Userspace Mesh Fix**: Corrected the handshake selection logic to support true P2P mesh connectivity in userspace mode by validating handshakes against all known peers.
*   **Signaling Security**: Enforced mandatory cluster secrets for all registration and heartbeat operations to prevent signaling spoofing.

### 🛠️ Changes

*   **Architecture**: Implemented `handle_incoming_packet` in `wg.rs` and a centralized dispatcher in `main.rs`.
*   **Security**: Added pre-flight root/sudo checks for KERNEL mode WireGuard on Linux.
*   **Reliability**: Added capacity limits to `RemovedPeer` tracking in `NucleusState` to prevent unbounded memory growth.
*   **Developer Experience**: Standardized the `Identity` initialization to support easier persistence in consumer applications.

---

## v0.2.4: Userspace WireGuard & Multi-Peer Mesh

**Date:** 2026-01-24

This release introduces a significant architectural shift with the integration of a fully userspace WireGuard data plane via **BoringTun**, enabling multi-peer mesh connectivity across platforms without requiring kernel-space WireGuard.

### 🚀 Major Achievements

*   **Userspace WireGuard Integration**: Integrated `boringtun` to provide a high-performance, memory-safe userspace WireGuard implementation.
*   **Multi-Peer Userspace Support**: The userspace data plane now fully supports multiple concurrent peer connections, enabling true mesh networking in userspace.
*   **Enhanced CI/CD Pipeline**: Expanded the CI matrix to include more platforms and streamlined the build process for better reliability.
*   **STUN Improvements**: Refined the STUN discovery logic for better NAT traversal reliability.

### 🛠️ Changes

*   **Data Plane**: Refactored `wg.rs` to support `WgInterface` unified enum, allowing seamless switching between Kernel (CLI) and Userspace (BoringTun) modes.
*   **Networking**: Implemented packet encapsulation/decapsulation loops for userspace mode and a simplified routing table for peer management.
*   **Build System**: Added `Dockerfile.local` and updated PowerShell build scripts for better local development workflows.
*   **Testing**: Improved `cloud_test.sh` to support the new userspace data plane validation.

---

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

*   **CLI**: Resolved "unexpected argument '--cipher'" error by properly integrating the argument into the `omninervous` parser.
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
*   **Embedded Bytecode**: `omninervous` now ships with the actual XDP bytecode matching the daemon version, replacing the previous placeholder.

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
