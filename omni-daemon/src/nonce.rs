use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::Result;

/// Manages nonce generation with counter-based approach to prevent reuse
pub struct NonceManager {
    counter: AtomicU64,
    random_base: [u8; 8],
}

impl NonceManager {
    /// Create a new nonce manager with random initialization
    pub fn new() -> Result<Self> {
        let mut random_base = [0u8; 8];
        for i in 0..8 {
            random_base[i] = rand::random();
        }
        
        Ok(Self {
            counter: AtomicU64::new(0),
            random_base,
        })
    }

    /// Generate a unique nonce that will never repeat
    /// Format: [random_base (8 bytes)] XOR [counter (8 bytes)]
    pub fn generate_nonce(&self) -> [u8; 8] {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let counter_bytes = counter.to_le_bytes();
        
        let mut nonce = [0u8; 8];
        for i in 0..8 {
            nonce[i] = self.random_base[i] ^ counter_bytes[i];
        }
        
        nonce
    }

    /// Get current counter value (for monitoring)
    pub fn current_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_uniqueness() {
        let nm = NonceManager::new().unwrap();
        let nonce1 = nm.generate_nonce();
        let nonce2 = nm.generate_nonce();
        assert_ne!(nonce1, nonce2, "Nonces must be unique");
    }

    #[test]
    fn test_nonce_counter_increment() {
        let nm = NonceManager::new().unwrap();
        assert_eq!(nm.current_counter(), 0);
        nm.generate_nonce();
        assert_eq!(nm.current_counter(), 1);
        nm.generate_nonce();
        assert_eq!(nm.current_counter(), 2);
    }
}
