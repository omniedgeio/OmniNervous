
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
