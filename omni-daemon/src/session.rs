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
    last_seq: HashMap<u64, u64>, // Track last used sequence per session (for replay protection)
}

impl SessionManager {
    pub fn new() -> Self {
        // Generate a random server secret on startup
        let mut secret = [0u8; 32];
        secret.iter_mut().for_each(|b| *b = rand::random());
        Self {
            sessions: HashMap::new(),
            secret,
            last_seq: HashMap::new(),
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
        // Initialize last_seq for this session to 0 if not present
        self.last_seq.entry(session_id).or_insert(0);
    }
 
    pub fn get_session_mut(&mut self, session_id: u64) -> Option<&mut SessionState> {
        self.sessions.get_mut(&session_id)
    }
 
    pub fn get_session(&self, session_id: u64) -> Option<&SessionState> {
        self.sessions.get(&session_id)
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
    /// Returns (Success, Option<Key>)
    pub fn finalize_session(&mut self, session_id: u64) -> Result<(bool, Option<[u8; 32]>)> {
        if let Some(state) = self.sessions.remove(&session_id) {
            if let SessionState::Handshaking(session) = state {
                if session.is_handshake_finished() {
                    let is_initiator = session.handshake.is_initiator();
                    
                    // Extract keys BEFORE moving session to transport mode (to avoid borrow-after-move)
                    let keys = session.get_transport_keys();
                    
                    let transport = session.into_transport()?;
                    
                    // In Noise IK:
                    // Responder RX key = k1 (first key set)
                    // Initiator RX key = k2 (second key set)
                    let rx_key = if is_initiator {
                        keys.get(1).copied()
                    } else {
                        keys.get(0).copied()
                    };
                    
                    self.sessions.insert(session_id, SessionState::Active(transport));
                    // Initialize last_seq for this session if not already
                    self.last_seq.entry(session_id).or_insert(0);
                    return Ok((true, rx_key));
                }
            }
        }
        Ok((false, None))
    }

    /// Get/Set last sequence number for a session (replay protection helpers)
    pub fn get_last_seq(&self, session_id: u64) -> u64 {
        *self.last_seq.get(&session_id).unwrap_or(&0)
    }
    pub fn set_last_seq(&mut self, session_id: u64, seq: u64) {
        self.last_seq.insert(session_id, seq);
    }
    pub fn ensure_session_seq(&mut self, session_id: u64) -> u64 {
        let e = self.last_seq.entry(session_id).or_insert(0);
        *e += 1;
        *e
    }
}
 
#[cfg(test)]
mod tests {
    use super::*;
    use snow::params::DHChoice;
    use snow::resolvers::{DefaultResolver, CryptoResolver};
 
    #[test]
    fn test_handshake_and_transport() {
        let mut initiator_priv = [0u8; 32];
        let mut responder_priv = [0u8; 32];
        for i in 0..32 {
            initiator_priv[i] = i as u8;
            responder_priv[i] = (32 - i) as u8;
        }
 
        // Derive public keys using the same logic as the daemon
        fn derive_pk(priv_key: &[u8; 32]) -> [u8; 32] {
            let resolver = DefaultResolver;
            let mut dh = resolver.resolve_dh(&DHChoice::Curve25519).unwrap();
            dh.set(priv_key);
            let mut pk = [0u8; 32];
            pk.copy_from_slice(dh.pubkey());
            pk
        }
 
        let initiator_pub = derive_pk(&initiator_priv);
        let responder_pub = derive_pk(&responder_priv);
        let psk = Some([0x42u8; 32]);
 
        // 1. Create sessions
        let mut i_session = NoiseSession::new_initiator(&initiator_priv, &responder_pub, psk.as_ref(), noise::CipherType::ChaChaPoly).unwrap();
        let mut r_session = NoiseSession::new_responder(&responder_priv, psk.as_ref(), noise::CipherType::ChaChaPoly).unwrap();
 
        // 2. Handshake Step 1: Initiator -> Responder
        let mut buf1 = [0u8; 512];
        let len1 = i_session.handshake.write_message(b"hello", &mut buf1).unwrap();
        
        let mut r_payload = vec![0u8; 128];
        let res1 = r_session.handshake.read_message(&buf1[..len1], &mut r_payload).unwrap();
        assert_eq!(&r_payload[..res1], b"hello");
 
        // 3. Handshake Step 2: Responder -> Initiator
        let mut buf2 = [0u8; 512];
        let len2 = r_session.handshake.write_message(b"world", &mut buf2).unwrap();
        
        let mut i_payload = vec![0u8; 128];
        let res2 = i_session.handshake.read_message(&buf2[..len2], &mut i_payload).unwrap();
        assert_eq!(&i_payload[..res2], b"world");
 
        // 4. Finalize
        let i_transport = i_session.handshake.into_transport_mode().unwrap();
        let r_transport = r_session.handshake.into_transport_mode().unwrap();
 
        // 5. Encrypt/Decrypt
        let nonce = 12345u64;
        let msg = b"secret message";
        let mut encrypted = [0u8; 512];
        let enc_len = i_transport.write_message(nonce, msg, &mut encrypted).unwrap();
 
        let mut decrypted = [0u8; 512];
        let dec_len = r_transport.read_message(nonce, &encrypted[..enc_len], &mut decrypted).unwrap();
        assert_eq!(&decrypted[..dec_len], msg);
    }
  }
