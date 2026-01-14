use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;
use crate::noise::NoiseSession;
use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub enum SessionState {
    Handshaking(NoiseSession),
    Active(snow::StatelessTransportState),
}

pub struct SessionManager {
    sessions: HashMap<u64, SessionState>,  // Changed from u32 to u64
    secret: [u8; 32], // Server secret for HMAC
}

impl SessionManager {
    pub fn new() -> Self {
        // Generate a random server secret on startup
        let mut secret = [0u8; 32];
        secret.iter_mut().for_each(|b| *b = rand::random());
        
        Self {
            sessions: HashMap::new(),
            secret,
        }
    }

    /// Generate a cryptographically secure 64-bit session ID
    /// NOTE: First byte is always >= 0x10 to avoid collision with signaling message types (0x01-0x0F)
    pub fn generate_session_id(&self, src_ip: IpAddr) -> u64 {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC init failed");
        
        // Add source IP
        match src_ip {
            IpAddr::V4(v4) => mac.update(&v4.octets()),
            IpAddr::V6(v6) => mac.update(&v6.octets()),
        }
        
        // Add timestamp (nanoseconds)
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        mac.update(&nanos.to_le_bytes());
        
        // Take first 8 bytes of HMAC as 64-bit session ID
        let result = mac.finalize();
        let hash_bytes = result.into_bytes();
        let mut bytes: [u8; 8] = [
            hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3],
            hash_bytes[4], hash_bytes[5], hash_bytes[6], hash_bytes[7]
        ];
        
        // Ensure first byte >= 0x10 to avoid collision with signaling message types
        // Signaling uses 0x01-0x0F, so we reserve 0x00-0x0F for signaling
        if bytes[0] < 0x10 {
            bytes[0] = 0x10 | (bytes[0] & 0x0F); // Set high nibble to 1
        }
        
        u64::from_be_bytes(bytes)
    }

    pub fn create_session(&mut self, session_id: u64, state: SessionState) {
        self.sessions.insert(session_id, state);
    }

    pub fn get_session_mut(&mut self, session_id: u64) -> Option<&mut SessionState> {
        self.sessions.get_mut(&session_id)
    }

    /// Advance the handshake for a given session.
    /// Returns (response_to_send, peer_payload) where peer_payload may contain VIP
    pub fn advance_handshake(&mut self, session_id: u64, message: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if let Some(SessionState::Handshaking(ref mut session)) = self.sessions.get_mut(&session_id) {
            let (response, peer_payload) = session.process_handshake_with_payload(message)?;
            Ok(Some((response, peer_payload)))
        } else {
            Ok(None)
        }
    }

    /// Finalize a handshake and move the session to Active state.
    pub fn finalize_session(&mut self, session_id: u64) -> Result<bool> {
        if let Some(state) = self.sessions.remove(&session_id) {
            if let SessionState::Handshaking(session) = state {
                if session.is_handshake_finished() {
                    let transport = session.into_transport()?;
                    self.sessions.insert(session_id, SessionState::Active(transport));
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
