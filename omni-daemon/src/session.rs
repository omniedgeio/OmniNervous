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
    sessions: HashMap<u32, SessionState>,
    secret: [u8; 32], // Server secret for HMAC
}

impl SessionManager {
    pub fn new() -> Self {
        // Generate a random server secret on startup
        let mut secret = [0u8; 32];
        for i in 0..32 {
            secret[i] = rand::random();
        }
        
        Self {
            sessions: HashMap::new(),
            secret,
        }
    }

    /// Generate a cryptographically secure session ID based on source IP and timestamp.
    pub fn generate_session_id(&self, src_ip: IpAddr) -> u32 {
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
        
        // Take first 4 bytes of HMAC as session ID
        let result = mac.finalize();
        let bytes = result.into_bytes();
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    pub fn create_session(&mut self, session_id: u32, state: SessionState) {
        self.sessions.insert(session_id, state);
    }

    pub fn get_session_mut(&mut self, session_id: u32) -> Option<&mut SessionState> {
        self.sessions.get_mut(&session_id)
    }

    /// Advance the handshake for a given session.
    pub fn advance_handshake(&mut self, session_id: u32, message: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(SessionState::Handshaking(ref mut session)) = self.sessions.get_mut(&session_id) {
            let response = session.process_handshake(message)?;
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }

    /// Finalize a handshake and move the session to Active state.
    pub fn finalize_session(&mut self, session_id: u32) -> Result<bool> {
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
