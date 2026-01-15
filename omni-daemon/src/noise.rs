use snow::params::NoiseParams;
use snow::Builder;
use anyhow::{Context, Result};
use sha2::{Sha256, Digest};

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
}

impl NoiseSession {
    /// Create initiator with optional PSK authentication
    pub fn new_initiator(
        local_priv_key: &[u8], 
        remote_pub_key: &[u8],
        psk: Option<&[u8; 32]>
    ) -> Result<Self> {
        let pattern = if psk.is_some() {
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        } else {
            "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        };
        
        let params: NoiseParams = pattern.parse()
            .context("Failed to parse Noise pattern")?;
        
        let mut builder = Builder::new(params)
            .local_private_key(local_priv_key)
            .remote_public_key(remote_pub_key);
        
        if let Some(key) = psk {
            log::debug!("Initiator using PSK with fingerprint: {:02x}{:02x}{:02x}{:02x}", 
                key[0], key[1], key[2], key[3]);
            builder = builder.psk(2, key);
        } else {
            log::debug!("Initiator NOT using PSK (open mode)");
        }
        
        let handshake = builder.build_initiator()
            .context("Failed to build Noise initiator")?;
        
        Ok(Self { handshake })
    }

    /// Create responder with optional PSK authentication
    pub fn new_responder(local_priv_key: &[u8], psk: Option<&[u8; 32]>) -> Result<Self> {
        let pattern = if psk.is_some() {
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        } else {
            "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        };
        
        let params: NoiseParams = pattern.parse()
            .context("Failed to parse Noise pattern")?;
        
        let mut builder = Builder::new(params)
            .local_private_key(local_priv_key);
        
        if let Some(key) = psk {
            log::debug!("Responder using PSK with fingerprint: {:02x}{:02x}{:02x}{:02x}", 
                key[0], key[1], key[2], key[3]);
            builder = builder.psk(2, key);
        } else {
            log::debug!("Responder NOT using PSK (open mode)");
        }
        
        let handshake = builder.build_responder()
            .context("Failed to build Noise responder")?;
        
        Ok(Self { handshake })
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
}
