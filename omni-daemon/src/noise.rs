use snow::params::NoiseParams;
use snow::Builder;
use anyhow::Result;

pub struct PeerIdentity {
    pub public_key: [u8; 32],
}

pub struct NoiseSession {
    pub handshake: snow::HandshakeState,
}

impl NoiseSession {
    pub fn new_initiator(local_priv_key: &[u8], remote_pub_key: &[u8]) -> Result<Self> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?;
        let handshake = Builder::new(params)
            .local_private_key(local_priv_key)
            .remote_public_key(remote_pub_key)
            .build_initiator()?;
        
        Ok(Self { handshake })
    }

    pub fn new_responder(local_priv_key: &[u8]) -> Result<Self> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?;
        let handshake = Builder::new(params)
            .local_private_key(local_priv_key)
            .build_responder()?;
        
        Ok(Self { handshake })
    }

    /// Process an incoming handshake message and return the response.
    pub fn process_handshake(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut read_buf = vec![0u8; 256];
        let mut write_buf = vec![0u8; 256];

        let _len = self.handshake.read_message(message, &mut read_buf)?;
        let len = self.handshake.write_message(&[], &mut write_buf)?;

        write_buf.truncate(len);
        Ok(write_buf)
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
