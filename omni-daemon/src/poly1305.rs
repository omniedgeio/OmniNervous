/// Poly1305 MAC - Re-exports from poly1305 crate
/// 
/// For direct Poly1305 usage, use the poly1305 crate directly.
/// OmniNervous uses ChaCha20-Poly1305 AEAD via the chacha20poly1305 or snow crates,
/// which provide RFC 8439 compliant authenticated encryption.
/// 
/// This module provides a simplified wrapper for standalone MAC verification
/// in the XDP/eBPF data plane.

pub use poly1305::Poly1305;

/// Constant-time comparison of two 16-byte tags
/// Uses XOR accumulation to prevent timing attacks
#[inline]
pub fn verify_tag(computed: &[u8; 16], received: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= computed[i] ^ received[i];
    }
    diff == 0
}

// Tests removed - Poly1305 implementation is provided by RustCrypto crate
// which has its own comprehensive test suite. The crate passes RFC 8439 tests.
// Our usage is via ChaCha20-Poly1305 AEAD in the snow/chacha20poly1305 crates.
