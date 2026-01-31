//! Relay Server and Client for NAT Traversal Fallback
//!
//! When direct UDP hole punching fails (e.g., both peers behind symmetric NAT),
//! the relay provides guaranteed connectivity by forwarding encrypted WireGuard
//! packets between peers.
//!
//! Key features:
//! - Zero-knowledge: Only forwards encrypted packets, never decrypts
//! - Session-based: Each peer pair gets a unique session
//! - Rate-limited: Prevents abuse with configurable bandwidth limits
//! - Automatic cleanup: Sessions expire after inactivity timeout

use anyhow::{Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

// ============================================================================
// Message Type Constants
// ============================================================================

/// Request relay allocation for a target peer
pub const MSG_RELAY_BIND: u8 = 0x20;
/// Relay endpoint allocated successfully
pub const MSG_RELAY_BIND_ACK: u8 = 0x21;
/// Relayed WireGuard packet
pub const MSG_RELAY_DATA: u8 = 0x22;
/// Release relay session
pub const MSG_RELAY_UNBIND: u8 = 0x23;
/// Relay keepalive (prevents session timeout)
pub const MSG_RELAY_KEEPALIVE: u8 = 0x24;

// ============================================================================
// Data Structures
// ============================================================================

/// Unique session identifier for a relay session
pub type SessionId = [u8; 16];

/// A relay session between two peers
#[derive(Debug, Clone)]
pub struct RelaySession {
    /// Session identifier
    pub id: SessionId,
    /// First client's address
    pub client_a: SocketAddr,
    /// Second client's address (None until they connect)
    pub client_b: Option<SocketAddr>,
    /// First client's WireGuard public key
    pub pubkey_a: [u8; 32],
    /// Second client's WireGuard public key (target)
    pub pubkey_b: [u8; 32],
    /// Virtual IP of client A
    pub vip_a: Ipv4Addr,
    /// Virtual IP of client B
    pub vip_b: Ipv4Addr,
    /// When the session was created
    pub created_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Total bytes relayed A -> B
    pub bytes_a_to_b: u64,
    /// Total bytes relayed B -> A
    pub bytes_b_to_a: u64,
    /// Rate limit bucket (bytes remaining in current window)
    pub rate_limit_bucket: u64,
    /// Last rate limit refill time
    pub rate_limit_refill: Instant,
}

impl RelaySession {
    /// Create a new relay session
    pub fn new(
        id: SessionId,
        client_a: SocketAddr,
        pubkey_a: [u8; 32],
        pubkey_b: [u8; 32],
        vip_a: Ipv4Addr,
        vip_b: Ipv4Addr,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            client_a,
            client_b: None,
            pubkey_a,
            pubkey_b,
            vip_a,
            vip_b,
            created_at: now,
            last_activity: now,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            rate_limit_bucket: 1024 * 1024, // 1 MB initial bucket (reduced from 10 MB)
            rate_limit_refill: now,
        }
    }

    /// Check if session has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Update last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check and consume rate limit
    /// Returns true if packet is allowed, false if rate limited
    pub fn check_rate_limit(&mut self, packet_size: u64, rate_limit_bytes_per_sec: u64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.rate_limit_refill);

        // Refill bucket based on time elapsed
        let refill = (elapsed.as_secs_f64() * rate_limit_bytes_per_sec as f64) as u64;
        self.rate_limit_bucket =
            (self.rate_limit_bucket + refill).min(rate_limit_bytes_per_sec * 2);
        self.rate_limit_refill = now;

        // Check if we have enough in bucket
        if self.rate_limit_bucket >= packet_size {
            self.rate_limit_bucket -= packet_size;
            true
        } else {
            false
        }
    }
}

/// Relay bind request message
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RelayBindRequest {
    /// Requester's WireGuard public key
    pub requester_key: [u8; 32],
    /// Target peer's WireGuard public key
    pub target_key: [u8; 32],
    /// Requester's VIP
    pub requester_vip: Ipv4Addr,
    /// Target's VIP
    pub target_vip: Ipv4Addr,
}

/// Relay bind acknowledgement message
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RelayBindAck {
    /// Whether allocation succeeded
    pub success: bool,
    /// Session ID (if successful)
    pub session_id: Option<SessionId>,
    /// Relay endpoint to use
    pub relay_endpoint: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Relay data header (prepended to forwarded packets)
#[derive(Debug, Clone)]
pub struct RelayDataHeader {
    /// Session ID
    pub session_id: SessionId,
}

/// Configuration for relay server
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Whether relay is enabled
    pub enabled: bool,
    /// Session timeout (no activity)
    pub session_timeout: Duration,
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Rate limit per session (bytes/sec)
    pub rate_limit_bytes_per_sec: u64,
    /// Maximum packet size to relay
    pub max_packet_size: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_timeout: Duration::from_secs(120), // 2 minutes
            max_sessions: 1000,
            rate_limit_bytes_per_sec: 10 * 1024 * 1024 / 8, // 10 Mbps
            max_packet_size: 1500,
        }
    }
}

// ============================================================================
// Relay Server Implementation
// ============================================================================

/// Relay server for forwarding packets between peers that can't connect directly
pub struct RelayServer {
    /// Configuration
    config: RelayConfig,
    /// Active sessions indexed by session ID
    sessions_by_id: HashMap<SessionId, RelaySession>,
    /// Session lookup by peer pair (sorted pubkeys -> session ID)
    sessions_by_peers: HashMap<([u8; 32], [u8; 32]), SessionId>,
    /// Session lookup by client address
    sessions_by_addr: HashMap<SocketAddr, SessionId>,
}

impl RelayServer {
    /// Create a new relay server
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            sessions_by_id: HashMap::new(),
            sessions_by_peers: HashMap::new(),
            sessions_by_addr: HashMap::new(),
        }
    }

    /// Check if relay is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get current session count
    pub fn session_count(&self) -> usize {
        self.sessions_by_id.len()
    }

    /// Allocate a relay session for two peers
    pub fn allocate_session(
        &mut self,
        request: &RelayBindRequest,
        requester_addr: SocketAddr,
    ) -> Result<RelayBindAck> {
        if !self.config.enabled {
            return Ok(RelayBindAck {
                success: false,
                session_id: None,
                relay_endpoint: None,
                error: Some("Relay is disabled".to_string()),
            });
        }

        // Check session limit
        if self.sessions_by_id.len() >= self.config.max_sessions {
            return Ok(RelayBindAck {
                success: false,
                session_id: None,
                relay_endpoint: None,
                error: Some("Maximum sessions reached".to_string()),
            });
        }

        // Create sorted key pair for lookup
        let key_pair = Self::make_key_pair(&request.requester_key, &request.target_key);

        // Check if session already exists
        if let Some(session_id) = self.sessions_by_peers.get(&key_pair) {
            if let Some(session) = self.sessions_by_id.get_mut(session_id) {
                // Update the requester's address if it changed
                if session.pubkey_a == request.requester_key {
                    session.client_a = requester_addr;
                } else {
                    session.client_b = Some(requester_addr);
                }
                session.touch();

                // Update address index
                self.sessions_by_addr.insert(requester_addr, *session_id);

                info!(
                    "Reusing relay session {:02x?} for {} <-> {}",
                    &session_id[..4],
                    request.requester_vip,
                    request.target_vip
                );

                return Ok(RelayBindAck {
                    success: true,
                    session_id: Some(*session_id),
                    relay_endpoint: None, // Will be filled by caller with actual endpoint
                    error: None,
                });
            }
        }

        // Generate new session ID
        let session_id: SessionId = rand::random();

        // Create session
        let session = RelaySession::new(
            session_id,
            requester_addr,
            request.requester_key,
            request.target_key,
            request.requester_vip,
            request.target_vip,
        );

        info!(
            "Allocated relay session {:02x?} for {} <-> {}",
            &session_id[..4],
            request.requester_vip,
            request.target_vip
        );

        // Store session
        self.sessions_by_id.insert(session_id, session);
        self.sessions_by_peers.insert(key_pair, session_id);
        self.sessions_by_addr.insert(requester_addr, session_id);

        Ok(RelayBindAck {
            success: true,
            session_id: Some(session_id),
            relay_endpoint: None,
            error: None,
        })
    }

    /// Handle second peer joining a session
    pub fn join_session(
        &mut self,
        session_id: &SessionId,
        joiner_addr: SocketAddr,
        joiner_key: &[u8; 32],
    ) -> Result<bool> {
        if let Some(session) = self.sessions_by_id.get_mut(session_id) {
            // Verify this is the expected target
            if &session.pubkey_b == joiner_key {
                session.client_b = Some(joiner_addr);
                session.touch();
                self.sessions_by_addr.insert(joiner_addr, *session_id);

                info!(
                    "Peer joined relay session {:02x?} from {}",
                    &session_id[..4],
                    joiner_addr
                );
                return Ok(true);
            } else if &session.pubkey_a == joiner_key {
                // This is client A reconnecting with new address
                session.client_a = joiner_addr;
                session.touch();
                self.sessions_by_addr.insert(joiner_addr, *session_id);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Relay a packet from one peer to the other
    /// Returns the destination address if relay should proceed
    pub fn relay_packet(
        &mut self,
        session_id: &SessionId,
        from: SocketAddr,
        packet_size: usize,
    ) -> Option<SocketAddr> {
        let session = self.sessions_by_id.get_mut(session_id)?;

        // Check rate limit
        if !session.check_rate_limit(packet_size as u64, self.config.rate_limit_bytes_per_sec) {
            debug!("Rate limited packet in session {:02x?}", &session_id[..4]);
            return None;
        }

        // Determine destination
        let dest = if from == session.client_a {
            session.bytes_a_to_b += packet_size as u64;
            session.client_b
        } else if session.client_b == Some(from) {
            session.bytes_b_to_a += packet_size as u64;
            Some(session.client_a)
        } else {
            warn!(
                "Unknown sender {} for session {:02x?}",
                from,
                &session_id[..4]
            );
            return None;
        };

        session.touch();
        dest
    }

    /// Release a relay session
    pub fn release_session(&mut self, session_id: &SessionId) -> bool {
        if let Some(session) = self.sessions_by_id.remove(session_id) {
            // Clean up indexes
            let key_pair = Self::make_key_pair(&session.pubkey_a, &session.pubkey_b);
            self.sessions_by_peers.remove(&key_pair);
            self.sessions_by_addr.remove(&session.client_a);
            if let Some(client_b) = session.client_b {
                self.sessions_by_addr.remove(&client_b);
            }

            info!(
                "Released relay session {:02x?} ({} <-> {}), {} bytes relayed",
                &session_id[..4],
                session.vip_a,
                session.vip_b,
                session.bytes_a_to_b + session.bytes_b_to_a
            );
            true
        } else {
            false
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&mut self) -> Vec<SessionId> {
        let timeout = self.config.session_timeout;
        let expired: Vec<SessionId> = self
            .sessions_by_id
            .iter()
            .filter(|(_, s)| s.is_expired(timeout))
            .map(|(id, _)| *id)
            .collect();

        for session_id in &expired {
            self.release_session(session_id);
        }

        if !expired.is_empty() {
            info!("Cleaned up {} expired relay sessions", expired.len());
        }

        expired
    }

    /// Get session by client address
    pub fn get_session_by_addr(&self, addr: &SocketAddr) -> Option<&RelaySession> {
        self.sessions_by_addr
            .get(addr)
            .and_then(|id| self.sessions_by_id.get(id))
    }

    /// Get session statistics
    pub fn get_stats(&self) -> RelayStats {
        let mut total_bytes = 0u64;
        let mut active_sessions = 0usize;

        for session in self.sessions_by_id.values() {
            total_bytes += session.bytes_a_to_b + session.bytes_b_to_a;
            if session.client_b.is_some() {
                active_sessions += 1;
            }
        }

        RelayStats {
            total_sessions: self.sessions_by_id.len(),
            active_sessions,
            total_bytes_relayed: total_bytes,
        }
    }

    /// Create a sorted key pair for consistent lookup
    fn make_key_pair(key_a: &[u8; 32], key_b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        if key_a < key_b {
            (*key_a, *key_b)
        } else {
            (*key_b, *key_a)
        }
    }
}

/// Relay server statistics
#[derive(Debug, Clone)]
pub struct RelayStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub total_bytes_relayed: u64,
}

// ============================================================================
// Relay Client Implementation
// ============================================================================

/// Client-side relay state
#[derive(Debug, Clone, PartialEq)]
pub enum RelayClientState {
    /// Not using relay
    Disabled,
    /// Requesting relay allocation
    Binding,
    /// Relay session active
    Active {
        session_id: SessionId,
        relay_endpoint: SocketAddr,
    },
    /// Relay failed
    Failed,
}

/// Relay client for edge nodes
pub struct RelayClient {
    /// Our WireGuard public key
    our_key: [u8; 32],
    /// Our VIP
    our_vip: Ipv4Addr,
    /// Relay server endpoint (typically same as Nucleus)
    relay_endpoint: SocketAddr,
    /// Current state per target peer
    peer_states: HashMap<[u8; 32], RelayClientState>,
    /// Pending bind requests
    pending_binds: HashMap<[u8; 32], Instant>,
    /// Bind request timeout
    bind_timeout: Duration,
}

impl RelayClient {
    /// Create a new relay client
    pub fn new(our_key: [u8; 32], our_vip: Ipv4Addr, relay_endpoint: SocketAddr) -> Self {
        Self {
            our_key,
            our_vip,
            relay_endpoint,
            peer_states: HashMap::new(),
            pending_binds: HashMap::new(),
            bind_timeout: Duration::from_secs(10),
        }
    }

    /// Request relay allocation for a target peer
    pub fn create_bind_request(
        &mut self,
        target_key: [u8; 32],
        target_vip: Ipv4Addr,
    ) -> RelayBindRequest {
        self.pending_binds.insert(target_key, Instant::now());
        self.peer_states
            .insert(target_key, RelayClientState::Binding);

        RelayBindRequest {
            requester_key: self.our_key,
            target_key,
            requester_vip: self.our_vip,
            target_vip,
        }
    }

    /// Handle bind acknowledgement
    pub fn handle_bind_ack(
        &mut self,
        target_key: &[u8; 32],
        ack: RelayBindAck,
    ) -> Result<Option<SocketAddr>> {
        self.pending_binds.remove(target_key);

        if ack.success {
            if let (Some(session_id), Some(endpoint_str)) = (ack.session_id, ack.relay_endpoint) {
                let endpoint: SocketAddr =
                    endpoint_str.parse().context("Invalid relay endpoint")?;

                self.peer_states.insert(
                    *target_key,
                    RelayClientState::Active {
                        session_id,
                        relay_endpoint: endpoint,
                    },
                );

                info!("Relay session active for peer, using endpoint {}", endpoint);

                return Ok(Some(endpoint));
            }
        }

        if let Some(error) = ack.error {
            warn!("Relay bind failed: {}", error);
        }

        self.peer_states
            .insert(*target_key, RelayClientState::Failed);
        Ok(None)
    }

    /// Get the relay endpoint for a peer if active
    pub fn get_relay_endpoint(&self, target_key: &[u8; 32]) -> Option<SocketAddr> {
        match self.peer_states.get(target_key) {
            Some(RelayClientState::Active { relay_endpoint, .. }) => Some(*relay_endpoint),
            _ => None,
        }
    }

    /// Get session ID for a peer if active
    pub fn get_session_id(&self, target_key: &[u8; 32]) -> Option<SessionId> {
        match self.peer_states.get(target_key) {
            Some(RelayClientState::Active { session_id, .. }) => Some(*session_id),
            _ => None,
        }
    }

    /// Check if relay is active for a peer
    pub fn is_relay_active(&self, target_key: &[u8; 32]) -> bool {
        matches!(
            self.peer_states.get(target_key),
            Some(RelayClientState::Active { .. })
        )
    }

    /// Check for timed out bind requests
    pub fn cleanup_expired_binds(&mut self) -> Vec<[u8; 32]> {
        let timeout = self.bind_timeout;
        let expired: Vec<[u8; 32]> = self
            .pending_binds
            .iter()
            .filter(|(_, sent_at)| sent_at.elapsed() > timeout)
            .map(|(key, _)| *key)
            .collect();

        for key in &expired {
            self.pending_binds.remove(key);
            self.peer_states.insert(*key, RelayClientState::Failed);
        }

        expired
    }

    /// Clear relay state for a peer (e.g., when direct connection succeeds)
    pub fn clear_relay(&mut self, target_key: &[u8; 32]) {
        self.peer_states.remove(target_key);
        self.pending_binds.remove(target_key);
    }

    /// Get the relay server endpoint
    pub fn relay_endpoint(&self) -> SocketAddr {
        self.relay_endpoint
    }
}

// ============================================================================
// Message Encoding/Decoding
// ============================================================================

/// Encode a relay bind request
pub fn encode_relay_bind(request: &RelayBindRequest) -> Result<Vec<u8>> {
    let mut buf = vec![MSG_RELAY_BIND];
    let payload = serde_cbor::to_vec(request).context("Failed to encode RELAY_BIND")?;
    buf.extend(payload);
    Ok(buf)
}

/// Parse a relay bind request
pub fn parse_relay_bind(data: &[u8]) -> Result<RelayBindRequest> {
    if data.is_empty() || data[0] != MSG_RELAY_BIND {
        anyhow::bail!("Not a RELAY_BIND message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode RELAY_BIND")
}

/// Encode a relay bind acknowledgement
pub fn encode_relay_bind_ack(ack: &RelayBindAck) -> Result<Vec<u8>> {
    let mut buf = vec![MSG_RELAY_BIND_ACK];
    let payload = serde_cbor::to_vec(ack).context("Failed to encode RELAY_BIND_ACK")?;
    buf.extend(payload);
    Ok(buf)
}

/// Parse a relay bind acknowledgement
pub fn parse_relay_bind_ack(data: &[u8]) -> Result<RelayBindAck> {
    if data.is_empty() || data[0] != MSG_RELAY_BIND_ACK {
        anyhow::bail!("Not a RELAY_BIND_ACK message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode RELAY_BIND_ACK")
}

/// Encode relay data (prepend header to WireGuard packet)
pub fn encode_relay_data(session_id: &SessionId, wg_packet: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 16 + wg_packet.len());
    buf.push(MSG_RELAY_DATA);
    buf.extend_from_slice(session_id);
    buf.extend_from_slice(wg_packet);
    buf
}

/// Parse relay data header
pub fn parse_relay_data(data: &[u8]) -> Result<(SessionId, &[u8])> {
    if data.len() < 17 || data[0] != MSG_RELAY_DATA {
        anyhow::bail!("Invalid RELAY_DATA message");
    }
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&data[1..17]);
    Ok((session_id, &data[17..]))
}

/// Encode relay unbind
pub fn encode_relay_unbind(session_id: &SessionId) -> Vec<u8> {
    let mut buf = Vec::with_capacity(17);
    buf.push(MSG_RELAY_UNBIND);
    buf.extend_from_slice(session_id);
    buf
}

/// Parse relay unbind
pub fn parse_relay_unbind(data: &[u8]) -> Result<SessionId> {
    if data.len() < 17 || data[0] != MSG_RELAY_UNBIND {
        anyhow::bail!("Invalid RELAY_UNBIND message");
    }
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&data[1..17]);
    Ok(session_id)
}

/// Check if a message is a relay message
pub fn is_relay_message(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    matches!(
        data[0],
        MSG_RELAY_BIND
            | MSG_RELAY_BIND_ACK
            | MSG_RELAY_DATA
            | MSG_RELAY_UNBIND
            | MSG_RELAY_KEEPALIVE
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_keys() -> ([u8; 32], [u8; 32]) {
        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        key_a[0] = 1;
        key_b[0] = 2;
        (key_a, key_b)
    }

    #[test]
    fn test_relay_session_creation() {
        let config = RelayConfig::default();
        let mut server = RelayServer::new(config);

        let (key_a, key_b) = make_test_keys();
        let addr_a: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let vip_a: Ipv4Addr = "10.200.0.1".parse().unwrap();
        let vip_b: Ipv4Addr = "10.200.0.2".parse().unwrap();

        let request = RelayBindRequest {
            requester_key: key_a,
            target_key: key_b,
            requester_vip: vip_a,
            target_vip: vip_b,
        };

        let ack = server.allocate_session(&request, addr_a).unwrap();
        assert!(ack.success);
        assert!(ack.session_id.is_some());
        assert_eq!(server.session_count(), 1);
    }

    #[test]
    fn test_relay_session_reuse() {
        let config = RelayConfig::default();
        let mut server = RelayServer::new(config);

        let (key_a, key_b) = make_test_keys();
        let addr_a: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let addr_a2: SocketAddr = "1.2.3.4:51821".parse().unwrap();
        let vip_a: Ipv4Addr = "10.200.0.1".parse().unwrap();
        let vip_b: Ipv4Addr = "10.200.0.2".parse().unwrap();

        let request = RelayBindRequest {
            requester_key: key_a,
            target_key: key_b,
            requester_vip: vip_a,
            target_vip: vip_b,
        };

        let ack1 = server.allocate_session(&request, addr_a).unwrap();
        let ack2 = server.allocate_session(&request, addr_a2).unwrap();

        assert_eq!(ack1.session_id, ack2.session_id);
        assert_eq!(server.session_count(), 1);
    }

    #[test]
    fn test_relay_packet_forwarding() {
        let config = RelayConfig::default();
        let mut server = RelayServer::new(config);

        let (key_a, key_b) = make_test_keys();
        let addr_a: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let addr_b: SocketAddr = "5.6.7.8:51820".parse().unwrap();
        let vip_a: Ipv4Addr = "10.200.0.1".parse().unwrap();
        let vip_b: Ipv4Addr = "10.200.0.2".parse().unwrap();

        let request = RelayBindRequest {
            requester_key: key_a,
            target_key: key_b,
            requester_vip: vip_a,
            target_vip: vip_b,
        };

        let ack = server.allocate_session(&request, addr_a).unwrap();
        let session_id = ack.session_id.unwrap();

        // Client B joins
        server.join_session(&session_id, addr_b, &key_b).unwrap();

        // Test A -> B forwarding
        let dest = server.relay_packet(&session_id, addr_a, 100);
        assert_eq!(dest, Some(addr_b));

        // Test B -> A forwarding
        let dest = server.relay_packet(&session_id, addr_b, 100);
        assert_eq!(dest, Some(addr_a));
    }

    #[test]
    fn test_message_encoding() {
        let request = RelayBindRequest {
            requester_key: [1u8; 32],
            target_key: [2u8; 32],
            requester_vip: "10.200.0.1".parse().unwrap(),
            target_vip: "10.200.0.2".parse().unwrap(),
        };

        let encoded = encode_relay_bind(&request).unwrap();
        assert_eq!(encoded[0], MSG_RELAY_BIND);

        let decoded = parse_relay_bind(&encoded).unwrap();
        assert_eq!(decoded.requester_key, request.requester_key);
        assert_eq!(decoded.target_key, request.target_key);
    }

    #[test]
    fn test_relay_data_encoding() {
        let session_id: SessionId = [0x42u8; 16];
        let wg_packet = b"wireguard data here";

        let encoded = encode_relay_data(&session_id, wg_packet);
        assert_eq!(encoded[0], MSG_RELAY_DATA);

        let (parsed_id, parsed_data) = parse_relay_data(&encoded).unwrap();
        assert_eq!(parsed_id, session_id);
        assert_eq!(parsed_data, wg_packet);
    }
}
