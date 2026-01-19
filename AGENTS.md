# OmniNervous Agent Configuration

This file contains build commands, coding standards, and development guidelines for AI agents working on the OmniNervous codebase.

## Current Status (Phase 7.1: Real-World Cloud Testing)
- 🔄 **eBPF Loading Investigation**: Added detailed error logging to diagnose kernel compatibility issues
- ✅ **Hybrid Architecture**: eBPF packet classification + userspace ChaCha20-Poly1305 crypto
- ✅ **Performance Improvement**: 44% efficiency (87.64 Mbps vs 61.75 Mbps previous)
- ✅ **P2P Connectivity**: Full 3-node cloud deployment with end-to-end encryption
- ✅ **Build System**: Automated Docker compilation with binary extraction

### Roadmap Status Update
- **Phase 7**: ✅ Complete (Performance optimizations, AF_XDP integration, hybrid crypto)
- **Phase 7.1**: 🔄 In Progress (Real-world testing, eBPF loading diagnostics)
- **Phase 7.5**: ⏳ Pending (QUIC signaling plane)

### Current Performance Results
- **Baseline**: 198.88 Mbps
- **VPN Performance**: 87.64 Mbps (44% of baseline)
- **Target**: 179.89+ Mbps (90%+ of baseline)
- **Gap**: ~92 Mbps improvement needed for target

### ✅ eBPF Loading Issue - RESOLVED
- **Problem**: "error parsing BPF object: error parsing ELF data"
- **Root Cause**: Complex ChaCha20 implementation causing verifier rejection
- **Solution**: Minimal eBPF program with userspace crypto processing
- **Status**: eBPF compiles and loads successfully ✅

### eBPF Loading Issue
- **Status**: Failing to load on all cloud nodes despite proper kernel support
- **Symptom**: "Failed to load eBPF program" with generic error
- **Investigation**: Enhanced error logging implemented for detailed diagnostics
- **Next Step**: Deploy updated binary to capture specific kernel error messages

## Build & Development Commands

### Core Build Commands
```bash
# Build entire project (userspace + eBPF)
cargo build --release

# Build with Docker (recommended for eBPF)
./scripts/build_local_docker.sh

# Cross-platform fast build
./scripts/build_cross_fast.sh

# Build only userspace daemon
cargo build --release -p omni-daemon

# Build only eBPF program
cargo build --release -p omni-ebpf-core
```

### Testing Commands
```bash
# Run all unit tests
cargo test

# Run tests for specific package
cargo test -p omni-common
cargo test -p omni-daemon

# Run single test file
cargo test --lib common::tests
cargo test --lib daemon::noise::tests

# Run integration tests with Docker
./scripts/cloud_test.sh

# Run specific test pattern
cargo test session_management
cargo test noise_handshake
```

### Linting & Formatting
```bash
# Format code
cargo fmt

# Run clippy lints
cargo clippy -- -D warnings

# Check for unused dependencies
cargo machete

# Run security audit
cargo audit
```

### Development Tools
```bash
# Install eBPF linker
cargo install bpf-linker

# Check eBPF compilation
cargo build -p omni-ebpf-core --target bpfel-unknown-none

# Run with debug stats
RUST_LOG=debug sudo ./target/release/omni-daemon --debug-stats
```

## Code Style Guidelines

### Import Organization
```rust
// Standard library imports first
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// External crates (alphabetical)
use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

// Local imports (relative path)
use crate::noise::NoiseSession;
use crate::session::SessionManager;
```

### Naming Conventions
- **Types/Structs/Enums**: `PascalCase` (e.g., `SessionManager`, `PacketHeader`)
- **Functions/Methods**: `snake_case` (e.g., `generate_session_id`, `handle_packet`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `OMNI_PORT`, `MAX_PEERS`)
- **Modules**: `snake_case` (e.g., `crypto_util`, `bpf_sync`)
- **Fields**: `snake_case` (e.g., `session_id`, `peer_address`)

### Error Handling
```rust
// Use anyhow::Result for most functions
pub async fn handle_connection(&mut self) -> Result<()> {
    let stream = self.tcp_stream
        .as_ref()
        .context("TCP stream not initialized")?;
    
    self.process_stream(stream).await
        .context("Failed to process stream")?;
    
    Ok(())
}

// For eBPF/kernel code, use Result<T, anyhow::Error> sparingly
// Prefer direct error returns for performance
```

### Async Patterns
```rust
// Use tokio::sync for concurrent data structures
use tokio::sync::{RwLock, Mutex};
use tokio::time::{timeout, Duration};

// Prefer async traits with ? Send bounds
#[async_trait::async_trait]
pub trait SignalingHandler: Send + Sync {
    async fn handle_message(&mut self, msg: SignalingMessage) -> Result<()>;
}
```

### Type Safety & Documentation
```rust
/// Represents a cryptographic session between two peers
/// 
/// This struct contains all necessary state for encrypted communication
/// using the Noise_IK protocol with ChaCha20-Poly1305.
#[derive(Debug, Clone)]
pub struct NoiseSession {
    /// Unique 64-bit session identifier
    session_id: u64,
    /// ChaCha20 cipher for encryption
    cipher: ChaCha20,
    /// Poly1305 MAC for authentication
    mac: Poly1305,
}
```

### eBPF Specific Guidelines
```rust
// eBPF code must be no_std
#![no_std]
#![no_main]

// Use safe pointer helpers from aya-ebpf
use aya_ebpf::{cty, programs::SkBuff};
use aya_ebpf_maps::PerfEventArray;

// Manual loop unrolling for performance
for i in 0..4 {
    // Unrolled ChaCha20 quarter round
    state[i] = state[i].wrapping_add(state[(i + 4) % 16]);
}

// Use Pod and Zeroable for shared structs
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct SessionEntry {
    pub session_id: u64,
    pub peer_ip: u32,
}
```

### Testing Patterns
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_session_creation() {
        let session = SessionManager::new();
        let result = session.create_peer_session(peer_id).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_crypto_operations() {
        let key = [0u8; 32];
        let cipher = ChaCha20::new(&key);
        // Test encryption/decryption
    }
}
```

## Architecture Guidelines

### Dual-Plane Separation
- **Ganglion (Control Plane)**: Async Rust daemon in `omni-daemon`
- **Synapse (Data Plane)**: eBPF/XDP program in `omni-ebpf-core`
- **Common Types**: Shared structures in `omni-common`

### Module Organization
```
omni-daemon/src/
├── main.rs              # Entry point and event loop
├── noise.rs             # Noise protocol implementation
├── session.rs           # Session state management
├── peers.rs             # Peer discovery and routing
├── signaling.rs         # Nucleus communication
├── tun.rs               # TUN interface management
├── bpf_sync.rs          # Userspace-kernel sync
└── crypto_util.rs       # Cryptographic utilities
```

### Performance Considerations
- Use `bytes::Bytes` for zero-copy packet handling
- Implement batch processing for eBPF maps
- Prefer `Arc<RwLock<T>>` over `Arc<Mutex<T>>` for read-heavy workloads
- Use `#[inline]` for hot path functions in eBPF

### Security Requirements
- All cryptographic operations must use constant-time algorithms
- Never log secret keys or nonces
- Implement rate limiting for all external interfaces
- Validate all packet lengths before processing

## Development Workflow

### Before Submitting Changes
1. Run `cargo fmt` and `cargo clippy`
2. Ensure all tests pass: `cargo test`
3. Test eBPF compilation: `cargo build -p omni-ebpf-core`
4. Run integration tests: `./scripts/cloud_test.sh`
5. Update documentation if needed

### Code Review Checklist
- [ ] Proper error handling with `anyhow::Result`
- [ ] Async/await used correctly with `Send` bounds
- [ ] No unsafe code outside eBPF modules
- [ ] Constants and magic numbers documented
- [ ] Tests cover critical paths
- [ ] No debug `println!` statements in production code

### Platform Support
- Primary: Linux (eBPF support required)
- Secondary: macOS, Windows (userspace only)
- Architecture: AMD64, ARM64 support
- Kernel: 5.15+ recommended for XDP features

## Testing Strategy

### Unit Tests
- Focus on cryptographic operations and session management
- Test async functions with `tokio_test`
- Mock external dependencies where appropriate

### Integration Tests
- Use Docker for multi-node testing
- Test P2P connectivity and tunnel establishment
- Validate performance with iperf3 benchmarks

### eBPF Testing
- Compile-time verification with Aya
- Runtime testing in Linux environment
- Performance testing with XDP benchmarks

---

*This configuration ensures consistent, high-quality code contributions to the OmniNervous high-performance P2P networking fabric.*