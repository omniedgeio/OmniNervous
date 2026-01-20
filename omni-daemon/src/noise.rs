use snow::params::NoiseParams;
use snow::Builder;
use anyhow::{Context, Result};
use sha2::{Sha256, Digest};
use std::sync::{Arc, Mutex};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::Cipher;



/// A shim that wraps a snow Cipher and "leaks" the key during set_key.
struct LeakyCipher {
    inner: Box<dyn Cipher>,
    keys: Arc<Mutex<Vec<[u8; 32]>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    ChaChaPoly,
    AesGcm,
}

impl std::str::FromStr for CipherType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chachapoly" | "chacha20poly1305" | "chacha" => Ok(CipherType::ChaChaPoly),
            "aesgcm" | "aes-gcm" | "aes" => Ok(CipherType::AesGcm),
            _ => anyhow::bail!("Unsupported cipher: {}", s),
        }
    }
}

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherType::ChaChaPoly => write!(f, "ChaCha20-Poly1305"),
            CipherType::AesGcm => write!(f, "AES-256-GCM"),
        }
    }
}

impl Cipher for LeakyCipher {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn set(&mut self, key: &[u8]) {
        if key.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(key);
            if let Ok(mut keys) = self.keys.lock() {
                keys.push(k);
            }
        }
        self.inner.set(key);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        self.inner.encrypt(nonce, authtext, plaintext, out)
    }

    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> std::result::Result<usize, snow::Error> {
        self.inner.decrypt(nonce, authtext, ciphertext, out)
    }

    fn rekey(&mut self) {
        self.inner.rekey();
    }
}

/// A resolver that use LeakyCipher for ChaChaPoly
struct LeakyResolver {
    inner: Box<dyn CryptoResolver>,
    keys: Arc<Mutex<Vec<[u8; 32]>>>,
}

unsafe impl Send for LeakyResolver {}

impl CryptoResolver for LeakyResolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        self.inner.resolve_rng()
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        self.inner.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn snow::types::Hash>> {
        self.inner.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn Cipher>> {
        let inner_cipher = self.inner.resolve_cipher(choice)?;
        Some(Box::new(LeakyCipher {
            inner: inner_cipher,
            keys: self.keys.clone(),
        }))
    }
}

pub struct PeerIdentity {
    pub public_key: [u8; 32],
}

/// Minimum secret length for security (128 bits of entropy minimum)
pub const MIN_SECRET_LENGTH: usize = 16;

/// Derive a 32-byte PSK from cluster name and secret
/// Uses SHA-256(cluster || ":" || secret) for key derivation
pub fn derive_psk(cluster: &str, secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cluster.as_bytes());
    hasher.update(b":");
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&result);
    // Log PSK fingerprint for debugging (first 4 bytes)
    log::debug!("Derived PSK for cluster '{}', fingerprint: {:02x}{:02x}{:02x}{:02x}", 
        cluster, psk[0], psk[1], psk[2], psk[3]);
    psk
}

/// Validate secret meets minimum length requirement
pub fn validate_secret(secret: &str) -> Result<()> {
    if secret.len() < MIN_SECRET_LENGTH {
        anyhow::bail!(
            "Secret too short: {} chars (minimum {} required for security)",
            secret.len(),
            MIN_SECRET_LENGTH
        );
    }
    Ok(())
}

pub struct NoiseSession {
    pub handshake: snow::HandshakeState,
    pub transport_keys: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl NoiseSession {
    /// Create initiator with optional PSK authentication
    pub fn new_initiator(
        local_priv_key: &[u8],
        remote_pub_key: &[u8],
        psk: Option<&[u8; 32]>,
        cipher: CipherType,
    ) -> Result<Self> {
        let pattern = match cipher {
            CipherType::ChaChaPoly => {
                if psk.is_some() {
                    "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s"
                } else {
                    "Noise_IK_25519_ChaChaPoly_BLAKE2s"
                }
            }
            CipherType::AesGcm => {
                if psk.is_some() {
                    "Noise_IKpsk1_25519_AESGCM_BLAKE2s"
                } else {
                    "Noise_IK_25519_AESGCM_BLAKE2s"
                }
            }
        };

        log::info!("Using Noise pattern: {} with PSK={}", pattern, psk.is_some());

        let params: NoiseParams = pattern.parse()
            .context("Failed to parse Noise pattern")?;

        let transport_keys = Arc::new(Mutex::new(Vec::new()));
        let inner_resolver: Box<dyn CryptoResolver> = Box::new(DefaultResolver::default());
        let resolver = LeakyResolver {
            inner: inner_resolver,
            keys: transport_keys.clone(),
        };

        let mut builder = Builder::with_resolver(params, Box::new(resolver))
            .local_private_key(local_priv_key)
            .remote_public_key(remote_pub_key);
        
        if let Some(key) = psk {
            log::debug!("Initiator using PSK with fingerprint: {:02x}{:02x}{:02x}{:02x}", 
                key[0], key[1], key[2], key[3]);
            builder = builder.psk(1, key);
        } else {
            log::debug!("Initiator NOT using PSK (open mode)");
        }
        
        let handshake = builder.build_initiator()
            .context("Failed to build Noise initiator")?;
        
        Ok(Self { handshake, transport_keys })
    }

    /// Create responder with optional PSK authentication
    pub fn new_responder(local_priv_key: &[u8], psk: Option<&[u8; 32]>, cipher: CipherType) -> Result<Self> {
        let pattern = match cipher {
            CipherType::ChaChaPoly => {
                if psk.is_some() {
                    "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s"
                } else {
                    "Noise_IK_25519_ChaChaPoly_BLAKE2s"
                }
            }
            CipherType::AesGcm => {
                if psk.is_some() {
                    "Noise_IKpsk1_25519_AESGCM_BLAKE2s"
                } else {
                    "Noise_IK_25519_AESGCM_BLAKE2s"
                }
            }
        };

        log::info!("Using Noise pattern: {} with PSK={}", pattern, psk.is_some());

        let params: NoiseParams = pattern.parse()
            .context("Failed to parse Noise pattern")?;

        let transport_keys = Arc::new(Mutex::new(Vec::new()));
        let inner_resolver: Box<dyn CryptoResolver> = Box::new(DefaultResolver::default());
        let resolver = LeakyResolver {
            inner: inner_resolver,
            keys: transport_keys.clone(),
        };

        let mut builder = Builder::with_resolver(params, Box::new(resolver))
            .local_private_key(local_priv_key);
        
        if let Some(key) = psk {
            log::debug!("Responder using PSK with fingerprint: {:02x}{:02x}{:02x}{:02x}", 
                key[0], key[1], key[2], key[3]);
            builder = builder.psk(1, key);
        } else {
            log::debug!("Responder NOT using PSK (open mode)");
        }
        
        let handshake = builder.build_responder()
            .context("Failed to build Noise responder")?;
        
        Ok(Self { handshake, transport_keys })
    }

    /// Process an incoming handshake message and return the response.
    pub fn process_handshake(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut read_buf = vec![0u8; 256];
        let mut write_buf = vec![0u8; 256];

        let _len = self.handshake.read_message(message, &mut read_buf)
            .context("Handshake failed - wrong secret or invalid message")?;
        let len = self.handshake.write_message(&[], &mut write_buf)?;

        write_buf.truncate(len);
        Ok(write_buf)
    }

    /// Process handshake and return both response and peer's payload (which may contain VIP)
    /// Note: For Noise IK, after initiator reads msg2, handshake is done - no msg3 needed.
    pub fn process_handshake_with_payload(&mut self, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut read_buf = vec![0u8; 256];

        // Read peer's message and extract payload
        let payload_len = self.handshake.read_message(message, &mut read_buf)
            .context("Handshake failed - wrong secret or invalid message")?;
        
        let peer_payload = read_buf[..payload_len].to_vec();
        
        // Only write a response if handshake is not yet finished
        // In Noise IK: Initiator finishes after reading msg2 (no msg3 to write)
        let response = if !self.handshake.is_handshake_finished() {
            let mut write_buf = vec![0u8; 256];
            let response_len = self.handshake.write_message(&[], &mut write_buf)?;
            write_buf.truncate(response_len);
            write_buf
        } else {
            vec![] // No response needed - handshake complete
        };
        
        Ok((response, peer_payload))
    }

    /// Check if the handshake is complete.
    pub fn is_handshake_finished(&self) -> bool {
        self.handshake.is_handshake_finished()
    }

    /// Finalize the handshake and return the transport state for encryption.
    pub fn into_transport(self) -> Result<snow::StatelessTransportState> {
        Ok(self.handshake.into_stateless_transport_mode()?)
    }

    /// Get the extracted transport keys (k1, k2)
    /// Only call this AFTER the handshake is finished and into_transport has likely been called internally
    /// or derived. In snow, keys are set on transition.
    pub fn get_transport_keys(&self) -> Vec<[u8; 32]> {
        self.transport_keys.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_psk_derivation() {
        let psk1 = derive_psk("my-cluster", "my-secret-password-123");
        let psk2 = derive_psk("my-cluster", "my-secret-password-123");
        let psk3 = derive_psk("my-cluster", "different-secret");
        
        assert_eq!(psk1, psk2); // Same inputs = same PSK
        assert_ne!(psk1, psk3); // Different secret = different PSK
    }
    
    #[test]
    fn test_secret_validation() {
        assert!(validate_secret("short").is_err());
        assert!(validate_secret("exactly16chars!!").is_ok());
        assert!(validate_secret("this-is-a-long-secure-password").is_ok());
    }

    #[test]
    fn test_handshake_all_ciphers() {
        let local_priv = [0u8; 32];
        let remote_priv = [0u8; 32];
        let mut remote_pub = [0u8; 32];
        // In a real test we'd derive this, but here we just want to see if builder fails
        
        for cipher in [CipherType::ChaChaPoly, CipherType::AesGcm] {
            let res = NoiseSession::new_initiator(&local_priv, &remote_pub, None, cipher);
            assert!(res.is_ok(), "Failed to create initiator with {}", cipher);
            
            let res = NoiseSession::new_responder(&remote_priv, None, cipher);
            assert!(res.is_ok(), "Failed to create responder with {}", cipher);
        }
    }
}
