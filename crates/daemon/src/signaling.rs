//! Nucleus Signaling Protocol - Scalable for 1000+ Edges
//!
//! ### Protocol Flow
//! ```mermaid
//! sequence_flow
//!   Edge->>Nucleus: REGISTER (Cluster, VIP, Port, PubKey, NatType)
//!   Nucleus-->>Edge: REGISTER_ACK (Success, RecentPeers)
//!   loop Every 30s
//!     Edge->>Nucleus: HEARTBEAT (Cluster, VIP, KnownCount)
//!     Nucleus-->>Edge: HEARTBEAT_ACK (NewPeers, RemovedVIPs)
//!   end
//!   Edge->>Nucleus: QUERY_PEER (TargetVIP)
//!   Nucleus-->>Edge: PEER_INFO (Endpoint, PubKey, NatType)
//! ```
//!
//! ### Key Concept
//! Nucleus acts as a VIP → endpoint registry (like DNS for VPN).
//! Edges use delta updates (heartbeats) to stay in sync without full table refreshes.
//!
//! ### Encryption (Phase 5)
//! Optional nacl box encryption for signaling messages:
//! - Uses X25519 key exchange with XSalsa20-Poly1305
//! - Each encrypted message includes sender's public key + nonce + ciphertext
//! - Backward compatible: MSG_ENCRYPTED (0x1D) wraps any message type
//! - Enable with `security.encrypt_signaling = true` in config

use anyhow::{Context, Result};
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use governor::{Quota, RateLimiter};
use hmac::{Hmac, Mac};
use log::{debug, info, warn};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroUsize};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use zeroize::ZeroizeOnDrop;

use crate::netcheck::NatType;

/// Message types for signaling protocol (0x11-0x1F to avoid WireGuard collision)
const MSG_REGISTER: u8 = 0x11;
const MSG_REGISTER_ACK: u8 = 0x12;
const MSG_HEARTBEAT: u8 = 0x13;
const MSG_HEARTBEAT_ACK: u8 = 0x14;
const MSG_QUERY_PEER: u8 = 0x15;
const MSG_PEER_INFO: u8 = 0x16;
#[allow(dead_code)]
const MSG_DEREGISTER: u8 = 0x17;
const MSG_STUN_QUERY: u8 = 0x18;
const MSG_STUN_RESPONSE: u8 = 0x19;
pub const MSG_NAT_PUNCH: u8 = 0x1A;
/// Disco ping - connectivity probe with transaction ID
pub const MSG_DISCO_PING: u8 = 0x1B;
/// Disco pong - response to ping with observed address
pub const MSG_DISCO_PONG: u8 = 0x1C;
/// Encrypted message envelope - wraps any message type with nacl box encryption
pub const MSG_ENCRYPTED: u8 = 0x1D;

/// How long peers stay in "recent" list for delta updates
const RECENT_PEER_WINDOW_SECS: u64 = 90; // 3x heartbeat interval

/// Maximum length for cluster names to prevent resource exhaustion
const MAX_CLUSTER_NAME_LEN: usize = 64;

/// Maximum number of removal records to keep per cluster
const MAX_REMOVAL_RECORDS: usize = 1000;

/// Maximum number of cached peer boxes for encryption
const MAX_PEER_BOX_CACHE_SIZE: usize = 1000;

fn is_valid_cluster(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CLUSTER_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

fn is_private_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    (octets[0] == 10) ||
    // 172.16.0.0/12
    (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
    // 192.168.0.0/16
    (octets[0] == 192 && octets[1] == 168)
}

/// Registration message from Edge to Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterMessage {
    pub cluster: String,
    pub vip: Ipv4Addr,
    pub listen_port: u16,
    pub public_key: [u8; 32],
    /// NAT type detected by the edge (for peer selection optimization)
    #[serde(default)]
    pub nat_type: Option<NatType>,
    pub hmac_tag: Option<[u8; 32]>,
}

/// Registration acknowledgment (includes recent peers for initial discovery)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterAckMessage {
    pub success: bool,
    pub recent_peers: Vec<PeerInfo>, // Peers that joined in last 90s
    pub hmac_tag: Option<[u8; 32]>,
}

/// Heartbeat from Edge to Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatMessage {
    pub cluster: String,
    pub vip: Ipv4Addr,
    pub last_seen_count: u32, // Number of peers edge knows about
    pub hmac_tag: Option<[u8; 32]>,
}

/// Heartbeat acknowledgment with delta updates
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatAckMessage {
    pub new_peers: Vec<PeerInfo>,    // Joined since last heartbeat
    pub removed_vips: Vec<Ipv4Addr>, // Left since last heartbeat
    pub hmac_tag: Option<[u8; 32]>,
}

/// Query for a specific peer by VIP
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QueryPeerMessage {
    pub cluster: String,
    pub target_vip: Ipv4Addr,
    pub requester_vip: Ipv4Addr,
    pub hmac_tag: Option<[u8; 32]>,
}

/// Peer info response (single peer)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerInfo {
    pub vip: Ipv4Addr,
    pub endpoint: String, // "ip:port"
    pub public_key: [u8; 32],
    /// NAT type of this peer (helps with connection strategy)
    #[serde(default)]
    pub nat_type: Option<NatType>,
}

/// Response to QUERY_PEER
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerInfoMessage {
    pub found: bool,
    pub peer: Option<PeerInfo>,
    pub hmac_tag: Option<[u8; 32]>,
}

/// STUN-like response with public endpoint
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StunResponse {
    pub public_addr: String, // "ip:port"
}

/// Disco Ping - connectivity probe for hole punching
/// Sent to peer's endpoint to establish bidirectional connectivity
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoPing {
    /// Random transaction ID (12 bytes, like STUN)
    pub tx_id: [u8; 12],
    /// Sender's WireGuard public key for identification
    pub sender_key: [u8; 32],
    /// Sender's VIP for routing
    pub sender_vip: Ipv4Addr,
}

/// Disco Pong - response to DiscoPing
/// Confirms connectivity and reports observed address
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoPong {
    /// Echo back the transaction ID from the ping
    pub tx_id: [u8; 12],
    /// Address we observed the ping coming from (NAT hairpin detection)
    pub observed_addr: String, // "ip:port"
    /// Responder's WireGuard public key
    pub responder_key: [u8; 32],
}

/// Encrypted envelope for signaling messages
/// Uses X25519 key exchange with XSalsa20-Poly1305 (nacl box)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedEnvelope {
    /// Sender's X25519 public key (32 bytes)
    pub sender_pubkey: [u8; 32],
    /// Random nonce (24 bytes for XSalsa20)
    pub nonce: [u8; 24],
    /// Encrypted message (original msg_type + payload)
    pub ciphertext: Vec<u8>,
}

/// Handles encryption/decryption of signaling messages
/// Uses crypto_box (X25519 + XSalsa20-Poly1305)
#[derive(ZeroizeOnDrop)]
pub struct SignalingEncryption {
    /// Our secret key (zeroized on drop)
    #[zeroize(skip)] // SecretKey from crypto_box handles its own zeroization
    secret_key: SecretKey,
    /// Our public key
    #[zeroize(skip)]
    public_key: PublicKey,
    /// Whether encryption is enabled
    #[zeroize(skip)]
    enabled: bool,
    /// Cached SalsaBox instances for known peers (LRU cache with bounded size)
    #[zeroize(skip)]
    peer_boxes: LruCache<[u8; 32], SalsaBox>,
}

impl SignalingEncryption {
    /// Create a new encryption context with a new random keypair
    pub fn new(enabled: bool) -> Self {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
            enabled,
            peer_boxes: LruCache::new(NonZeroUsize::new(MAX_PEER_BOX_CACHE_SIZE).unwrap()),
        }
    }

    /// Create from an existing secret key
    pub fn from_secret_key(secret_bytes: [u8; 32], enabled: bool) -> Self {
        let secret_key = SecretKey::from(secret_bytes);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
            enabled,
            peer_boxes: LruCache::new(NonZeroUsize::new(MAX_PEER_BOX_CACHE_SIZE).unwrap()),
        }
    }

    /// Get our public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Get our secret key bytes (for persistence)
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }

    /// Check if encryption is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable encryption
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get or create a SalsaBox for a peer
    fn get_or_create_box(&mut self, peer_pubkey: &[u8; 32]) -> &SalsaBox {
        if !self.peer_boxes.contains(peer_pubkey) {
            let peer_pk = PublicKey::from(*peer_pubkey);
            let salsa_box = SalsaBox::new(&peer_pk, &self.secret_key);
            self.peer_boxes.put(*peer_pubkey, salsa_box);
        }
        self.peer_boxes.get(peer_pubkey).unwrap()
    }

    /// Encrypt a message for a peer
    /// Returns MSG_ENCRYPTED + serialized EncryptedEnvelope
    pub fn encrypt(&mut self, plaintext: &[u8], peer_pubkey: &[u8; 32]) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(plaintext.to_vec());
        }

        let salsa_box = self.get_or_create_box(peer_pubkey);
        let nonce = SalsaBox::generate_nonce(&mut OsRng);

        let ciphertext = salsa_box
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let envelope = EncryptedEnvelope {
            sender_pubkey: self.public_key_bytes(),
            nonce: nonce.into(),
            ciphertext,
        };

        let mut data = vec![MSG_ENCRYPTED];
        let encoded =
            serde_cbor::to_vec(&envelope).context("Failed to encode EncryptedEnvelope")?;
        data.extend(encoded);
        Ok(data)
    }

    /// Decrypt an encrypted envelope
    /// Returns the decrypted message (msg_type + payload)
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            anyhow::bail!("Empty message");
        }

        // If not encrypted, return as-is
        if data[0] != MSG_ENCRYPTED {
            return Ok(data.to_vec());
        }

        let envelope: EncryptedEnvelope =
            serde_cbor::from_slice(&data[1..]).context("Failed to decode EncryptedEnvelope")?;

        let salsa_box = self.get_or_create_box(&envelope.sender_pubkey);
        let nonce = crypto_box::Nonce::from(envelope.nonce);

        let plaintext = salsa_box
            .decrypt(&nonce, envelope.ciphertext.as_slice())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Decrypt an encrypted envelope and return the sender's public key
    pub fn decrypt_with_sender(&mut self, data: &[u8]) -> Result<(Vec<u8>, Option<[u8; 32]>)> {
        if data.is_empty() {
            anyhow::bail!("Empty message");
        }

        // If not encrypted, return as-is with no sender
        if data[0] != MSG_ENCRYPTED {
            return Ok((data.to_vec(), None));
        }

        let envelope: EncryptedEnvelope =
            serde_cbor::from_slice(&data[1..]).context("Failed to decode EncryptedEnvelope")?;

        let salsa_box = self.get_or_create_box(&envelope.sender_pubkey);
        let nonce = crypto_box::Nonce::from(envelope.nonce);

        let plaintext = salsa_box
            .decrypt(&nonce, envelope.ciphertext.as_slice())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok((plaintext, Some(envelope.sender_pubkey)))
    }

    /// Clear cached boxes (e.g., when peer keys change)
    pub fn clear_cache(&mut self) {
        self.peer_boxes.clear();
    }

    /// Get the current cache size
    pub fn cache_size(&self) -> usize {
        self.peer_boxes.len()
    }
}

/// Registered peer on Nucleus with join time tracking
#[derive(Debug, Clone)]
pub struct RegisteredPeer {
    pub vip: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub listen_port: u16,
    pub public_key: [u8; 32],
    /// NAT type reported by this peer
    pub nat_type: Option<NatType>,
    pub joined_at: Instant, // For "recent peers" calculation
    pub last_seen: Instant,
}

/// Recently removed peer (for delta updates)
#[derive(Debug, Clone)]
struct RemovedPeer {
    pub vip: Ipv4Addr,
    pub removed_at: Instant,
}

/// Per-cluster state
#[derive(Default)]
struct ClusterState {
    /// VIP → peer info (O(1) lookup for QUERY_PEER)
    peers: HashMap<Ipv4Addr, RegisteredPeer>,
    /// Recently removed peers for delta updates
    removed: Vec<RemovedPeer>,
}

/// Nucleus state - manages registered peers by cluster
/// Optimized for 1000+ edges per cluster
pub struct NucleusState {
    clusters: HashMap<String, ClusterState>,
    rate_limiter: RateLimiter<
        std::net::IpAddr,
        governor::state::keyed::DefaultKeyedStateStore<std::net::IpAddr>,
        governor::clock::DefaultClock,
    >,
}

impl Default for NucleusState {
    fn default() -> Self {
        Self::new()
    }
}

impl NucleusState {
    pub fn new() -> Self {
        // Rate limit: 10 requests per second per IP
        let quota = Quota::per_second(NonZeroU32::new(10).unwrap());
        let rate_limiter = RateLimiter::keyed(quota);
        Self {
            clusters: HashMap::new(),
            rate_limiter,
        }
    }

    /// Register or update a peer
    pub fn register(&mut self, cluster: &str, peer: RegisteredPeer) -> Vec<PeerInfo> {
        let state = self.clusters.entry(cluster.to_string()).or_default();
        let is_new = !state.peers.contains_key(&peer.vip);

        if is_new {
            info!(
                "New peer {} at {} in cluster '{}'",
                peer.vip, peer.endpoint, cluster
            );
        } else {
            debug!("Updated peer {} in cluster '{}'", peer.vip, cluster);
        }

        state.peers.insert(peer.vip, peer.clone());

        // Return recent peers (joined in last RECENT_PEER_WINDOW_SECS)
        self.get_recent_peers(cluster, peer.vip)
    }

    /// Get peers that joined recently (for REGISTER_ACK)
    fn get_recent_peers(&self, cluster: &str, exclude_vip: Ipv4Addr) -> Vec<PeerInfo> {
        let window = Duration::from_secs(RECENT_PEER_WINDOW_SECS);

        self.clusters
            .get(cluster)
            .map(|state| {
                state
                    .peers
                    .values()
                    .filter(|p| p.vip != exclude_vip && p.joined_at.elapsed() < window)
                    .map(|p| PeerInfo {
                        vip: p.vip,
                        endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                        public_key: p.public_key,
                        nat_type: p.nat_type,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update heartbeat and return delta (new peers + removed peers)
    pub fn heartbeat(
        &mut self,
        cluster: &str,
        vip: Ipv4Addr,
        last_heartbeat_time: Option<Instant>,
    ) -> (Vec<PeerInfo>, Vec<Ipv4Addr>) {
        let state = match self.clusters.get_mut(cluster) {
            Some(s) => s,
            None => return (vec![], vec![]),
        };

        // Update last_seen
        if let Some(peer) = state.peers.get_mut(&vip) {
            peer.last_seen = Instant::now();
        }

        // Calculate delta since last heartbeat (or last 30s if unknown)
        let since = last_heartbeat_time.unwrap_or_else(|| Instant::now() - Duration::from_secs(30));

        // New peers since last heartbeat
        let new_peers: Vec<PeerInfo> = state
            .peers
            .values()
            .filter(|p| p.vip != vip && p.joined_at > since)
            .map(|p| PeerInfo {
                vip: p.vip,
                endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                public_key: p.public_key,
                nat_type: p.nat_type,
            })
            .collect();

        // Removed peers since last heartbeat
        let removed_vips: Vec<Ipv4Addr> = state
            .removed
            .iter()
            .filter(|r| r.removed_at > since)
            .map(|r| r.vip)
            .collect();

        (new_peers, removed_vips)
    }

    /// Lookup a specific peer by VIP (O(1))
    pub fn query_peer(&self, cluster: &str, vip: Ipv4Addr) -> Option<PeerInfo> {
        self.clusters
            .get(cluster)
            .and_then(|state| state.peers.get(&vip))
            .map(|p| PeerInfo {
                vip: p.vip,
                endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                public_key: p.public_key,
                nat_type: p.nat_type,
            })
    }

    /// Remove stale peers (no heartbeat for > 60 seconds)
    pub fn cleanup(&mut self) {
        let timeout = Duration::from_secs(60);
        let removal_retention = Duration::from_secs(RECENT_PEER_WINDOW_SECS);

        for (cluster, state) in self.clusters.iter_mut() {
            // Find and remove stale peers
            let stale: Vec<Ipv4Addr> = state
                .peers
                .iter()
                .filter(|(_, p)| p.last_seen.elapsed() > timeout)
                .map(|(vip, _)| *vip)
                .collect();

            for vip in stale {
                state.peers.remove(&vip);
                state.removed.push(RemovedPeer {
                    vip,
                    removed_at: Instant::now(),
                });
                info!("Removed stale peer {} from cluster '{}'", vip, cluster);
            }

            // Cleanup old removal records
            state
                .removed
                .retain(|r| r.removed_at.elapsed() < removal_retention);

            // Enforce capacity limit
            if state.removed.len() > MAX_REMOVAL_RECORDS {
                state.removed.truncate(MAX_REMOVAL_RECORDS);
            }
        }
    }

    /// Total registered peers
    pub fn peer_count(&self) -> usize {
        self.clusters.values().map(|s| s.peers.len()).sum()
    }
}

/// Encode a signaling message
pub fn encode_message(msg_type: u8, payload: &impl Serialize) -> Result<Vec<u8>> {
    let mut data = vec![msg_type];
    let encoded = serde_cbor::to_vec(payload).context("Failed to encode CBOR")?;
    data.extend(encoded);
    Ok(data)
}

/// Helper to sign a slice of bytes with a secret
fn calculate_hmac(secret: &str, data: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    result.into_bytes().into()
}

/// Constant-time comparison of HMAC tags to prevent timing attacks
fn verify_hmac_tag(received: Option<[u8; 32]>, expected: [u8; 32]) -> bool {
    match received {
        Some(tag) => tag.ct_eq(&expected).into(),
        None => false,
    }
}

/// Handle incoming signaling message (Nucleus side)
pub fn handle_nucleus_message(
    state: &mut NucleusState,
    data: &[u8],
    src: SocketAddr,
    secret: Option<&str>,
) -> Option<Vec<u8>> {
    // Rate limiting: Check if IP is allowed
    let ip = src.ip();
    if state.rate_limiter.check_key(&ip).is_err() {
        warn!("Rate limit exceeded for IP: {}", ip);
        return None;
    }

    if data.is_empty() {
        return None;
    }

    let msg_type = data[0];
    let payload = &data[1..];

    match msg_type {
        MSG_REGISTER => match serde_cbor::from_slice::<RegisterMessage>(payload) {
            Ok(reg) => {
                if !is_valid_cluster(&reg.cluster) {
                    warn!(
                        "Invalid cluster name in REGISTER from {}: {}",
                        src, reg.cluster
                    );
                    return None;
                }
                if !is_private_ip(reg.vip) {
                    warn!("VIP {} is not in private IP range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)", reg.vip);
                    return None;
                }
                if let Some(s) = secret {
                    let mut check_reg = reg.clone();
                    check_reg.hmac_tag = None;
                    let check_bytes = serde_cbor::to_vec(&check_reg).ok()?;
                    let expected = calculate_hmac(s, &check_bytes);
                    if !verify_hmac_tag(reg.hmac_tag, expected) {
                        warn!("HMAC verification failed for REGISTER from {}", src);
                        return None;
                    }
                }

                let peer = RegisteredPeer {
                    vip: reg.vip,
                    endpoint: src,
                    listen_port: reg.listen_port,
                    public_key: reg.public_key,
                    nat_type: reg.nat_type,
                    joined_at: Instant::now(),
                    last_seen: Instant::now(),
                };
                let recent_peers = state.register(&reg.cluster, peer);

                let mut ack = RegisterAckMessage {
                    success: true,
                    recent_peers,
                    hmac_tag: None,
                };

                if let Some(s) = secret {
                    let bytes = serde_cbor::to_vec(&ack).ok()?;
                    ack.hmac_tag = Some(calculate_hmac(s, &bytes));
                }

                encode_message(MSG_REGISTER_ACK, &ack).ok()
            }
            Err(e) => {
                warn!("Invalid REGISTER from {}: {}", src, e);
                None
            }
        },
        MSG_HEARTBEAT => match serde_cbor::from_slice::<HeartbeatMessage>(payload) {
            Ok(hb) => {
                if !is_valid_cluster(&hb.cluster) {
                    warn!(
                        "Invalid cluster name in HEARTBEAT from {}: {}",
                        src, hb.cluster
                    );
                    return None;
                }
                if !is_private_ip(hb.vip) {
                    warn!("VIP {} is not in private IP range", hb.vip);
                    return None;
                }

                if let Some(s) = secret {
                    let mut check_hb = hb.clone();
                    check_hb.hmac_tag = None;
                    let check_bytes = serde_cbor::to_vec(&check_hb).ok()?;
                    let expected = calculate_hmac(s, &check_bytes);
                    if !verify_hmac_tag(hb.hmac_tag, expected) {
                        warn!("HMAC verification failed for HEARTBEAT from {}", src);
                        return None;
                    }
                }

                let (new_peers, removed_vips) = state.heartbeat(&hb.cluster, hb.vip, None);

                let mut ack = HeartbeatAckMessage {
                    new_peers,
                    removed_vips,
                    hmac_tag: None,
                };

                if let Some(s) = secret {
                    let bytes = serde_cbor::to_vec(&ack).ok()?;
                    ack.hmac_tag = Some(calculate_hmac(s, &bytes));
                }

                encode_message(MSG_HEARTBEAT_ACK, &ack).ok()
            }
            Err(e) => {
                warn!("Invalid HEARTBEAT from {}: {}", src, e);
                None
            }
        },
        MSG_QUERY_PEER => match serde_cbor::from_slice::<QueryPeerMessage>(payload) {
            Ok(query) => {
                if !is_valid_cluster(&query.cluster) {
                    warn!(
                        "Invalid cluster name in QUERY_PEER from {}: {}",
                        src, query.cluster
                    );
                    return None;
                }
                if !is_private_ip(query.target_vip) || !is_private_ip(query.requester_vip) {
                    warn!(
                        "Invalid VIP in QUERY_PEER: target={}, requester={}",
                        query.target_vip, query.requester_vip
                    );
                    return None;
                }

                if let Some(s) = secret {
                    let mut check_query = query.clone();
                    check_query.hmac_tag = None;
                    let check_bytes = serde_cbor::to_vec(&check_query).ok()?;
                    let expected = calculate_hmac(s, &check_bytes);
                    if !verify_hmac_tag(query.hmac_tag, expected) {
                        warn!("HMAC verification failed for QUERY_PEER from {}", src);
                        return None;
                    }
                }

                let peer = state.query_peer(&query.cluster, query.target_vip);
                let mut response = PeerInfoMessage {
                    found: peer.is_some(),
                    peer,
                    hmac_tag: None,
                };

                if let Some(s) = secret {
                    let bytes = serde_cbor::to_vec(&response).ok()?;
                    response.hmac_tag = Some(calculate_hmac(s, &bytes));
                }

                encode_message(MSG_PEER_INFO, &response).ok()
            }
            Err(e) => {
                warn!("Invalid QUERY_PEER from {}: {}", src, e);
                None
            }
        },
        MSG_STUN_QUERY => {
            // Echo back the source address
            let response = StunResponse {
                public_addr: src.to_string(),
            };
            encode_message(MSG_STUN_RESPONSE, &response).ok()
        }
        _ => {
            debug!("Unknown message type {} from {}", msg_type, src);
            None
        }
    }
}

/// Edge client for connecting to Nucleus
#[derive(Clone)]
pub struct NucleusClient {
    nucleus_addr: SocketAddr,
    cluster: String,
    vip: Ipv4Addr,
    listen_port: u16,
    public_key: [u8; 32],
    secret: Option<String>,
    /// NAT type detected for this client
    nat_type: Option<NatType>,
}

impl NucleusClient {
    pub async fn new(
        nucleus: &str,
        cluster: String,
        public_key: [u8; 32],
        vip: Ipv4Addr,
        listen_port: u16,
        secret: Option<String>,
    ) -> Result<Self> {
        use tokio::net::lookup_host;
        let nucleus_addr = lookup_host(nucleus)
            .await
            .context("Failed to resolve nucleus address")?
            .next()
            .context("No addresses found for nucleus")?;

        Ok(Self {
            nucleus_addr,
            cluster,
            vip,
            listen_port,
            public_key,
            secret,
            nat_type: None,
        })
    }

    /// Set the detected NAT type
    pub fn set_nat_type(&mut self, nat_type: NatType) {
        self.nat_type = Some(nat_type);
    }

    /// Get the detected NAT type
    pub fn nat_type(&self) -> Option<NatType> {
        self.nat_type
    }

    /// Send registration to nucleus
    pub async fn register(&self, socket: &UdpSocket) -> Result<()> {
        let mut msg = RegisterMessage {
            cluster: self.cluster.clone(),
            vip: self.vip,
            listen_port: self.listen_port,
            public_key: self.public_key,
            nat_type: self.nat_type,
            hmac_tag: None,
        };

        if let Some(s) = &self.secret {
            let bytes = serde_cbor::to_vec(&msg)?;
            msg.hmac_tag = Some(calculate_hmac(s, &bytes));
        }

        let data = encode_message(MSG_REGISTER, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        info!(
            "Registered with nucleus {} (cluster: {}, vip: {})",
            self.nucleus_addr, self.cluster, self.vip
        );
        Ok(())
    }

    /// Send heartbeat to nucleus
    pub async fn heartbeat(&self, socket: &UdpSocket, known_peer_count: u32) -> Result<()> {
        let mut msg = HeartbeatMessage {
            cluster: self.cluster.clone(),
            vip: self.vip,
            last_seen_count: known_peer_count,
            hmac_tag: None,
        };

        if let Some(s) = &self.secret {
            let bytes = serde_cbor::to_vec(&msg)?;
            msg.hmac_tag = Some(calculate_hmac(s, &bytes));
        }

        let data = encode_message(MSG_HEARTBEAT, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        debug!("Sent heartbeat to nucleus");
        Ok(())
    }

    /// Query public endpoint from built-in STUN on Nucleus
    pub async fn query_stun(&self, socket: &UdpSocket) -> Result<()> {
        let data = vec![MSG_STUN_QUERY];
        socket.send_to(&data, self.nucleus_addr).await?;
        debug!("Sent STUN query to nucleus");
        Ok(())
    }

    /// Query specific peer by VIP
    pub async fn query_peer(&self, socket: &UdpSocket, target_vip: Ipv4Addr) -> Result<()> {
        let mut msg = QueryPeerMessage {
            cluster: self.cluster.clone(),
            target_vip,
            requester_vip: self.vip,
            hmac_tag: None,
        };

        if let Some(s) = &self.secret {
            let bytes = serde_cbor::to_vec(&msg)?;
            msg.hmac_tag = Some(calculate_hmac(s, &bytes));
        }

        let data = encode_message(MSG_QUERY_PEER, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        debug!("Queried peer {}", target_vip);
        Ok(())
    }

    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    pub fn vip(&self) -> Ipv4Addr {
        self.vip
    }

    #[allow(dead_code)]
    pub fn nucleus_addr(&self) -> SocketAddr {
        self.nucleus_addr
    }
}

/// Parse REGISTER_ACK response
pub fn parse_register_ack(data: &[u8], secret: Option<&str>) -> Result<RegisterAckMessage> {
    if data.is_empty() || data[0] != MSG_REGISTER_ACK {
        anyhow::bail!("Not a REGISTER_ACK message");
    }
    let ack: RegisterAckMessage =
        serde_cbor::from_slice(&data[1..]).context("Failed to decode REGISTER_ACK")?;

    if let Some(s) = secret {
        let mut check_ack = ack.clone();
        check_ack.hmac_tag = None;
        let bytes = serde_cbor::to_vec(&check_ack)?;
        let expected = calculate_hmac(s, &bytes);
        if !verify_hmac_tag(ack.hmac_tag, expected) {
            anyhow::bail!("HMAC verification failed for REGISTER_ACK");
        }
    }
    Ok(ack)
}

/// Parse HEARTBEAT_ACK response
pub fn parse_heartbeat_ack(data: &[u8], secret: Option<&str>) -> Result<HeartbeatAckMessage> {
    if data.is_empty() || data[0] != MSG_HEARTBEAT_ACK {
        anyhow::bail!("Not a HEARTBEAT_ACK message");
    }
    let ack: HeartbeatAckMessage =
        serde_cbor::from_slice(&data[1..]).context("Failed to decode HEARTBEAT_ACK")?;

    if let Some(s) = secret {
        let mut check_ack = ack.clone();
        check_ack.hmac_tag = None;
        let bytes = serde_cbor::to_vec(&check_ack)?;
        let expected = calculate_hmac(s, &bytes);
        if !verify_hmac_tag(ack.hmac_tag, expected) {
            anyhow::bail!("HMAC verification failed for HEARTBEAT_ACK");
        }
    }
    Ok(ack)
}

/// Parse PEER_INFO response
pub fn parse_peer_info(data: &[u8], secret: Option<&str>) -> Result<PeerInfoMessage> {
    if data.is_empty() || data[0] != MSG_PEER_INFO {
        anyhow::bail!("Not a PEER_INFO message");
    }
    let info: PeerInfoMessage =
        serde_cbor::from_slice(&data[1..]).context("Failed to decode PEER_INFO")?;

    if let Some(s) = secret {
        let mut check_info = info.clone();
        check_info.hmac_tag = None;
        let bytes = serde_cbor::to_vec(&check_info)?;
        let expected = calculate_hmac(s, &bytes);
        if !verify_hmac_tag(info.hmac_tag, expected) {
            anyhow::bail!("HMAC verification failed for PEER_INFO");
        }
    }
    Ok(info)
}

/// Check if message is a signaling message (from nucleus or peer)
pub fn is_signaling_message(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    matches!(
        data[0],
        MSG_REGISTER_ACK
            | MSG_HEARTBEAT_ACK
            | MSG_PEER_INFO
            | MSG_STUN_RESPONSE
            | MSG_NAT_PUNCH
            | MSG_DISCO_PING
            | MSG_DISCO_PONG
            | MSG_ENCRYPTED
    )
}

/// Get signaling message type
pub fn get_signaling_type(data: &[u8]) -> Option<u8> {
    data.first().copied()
}

/// Parse STUN_RESPONSE
pub fn parse_stun_response(data: &[u8]) -> Result<StunResponse> {
    if data.is_empty() || data[0] != MSG_STUN_RESPONSE {
        anyhow::bail!("Not a STUN_RESPONSE message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode STUN_RESPONSE")
}

/// Parse DISCO_PING
pub fn parse_disco_ping(data: &[u8]) -> Result<DiscoPing> {
    if data.is_empty() || data[0] != MSG_DISCO_PING {
        anyhow::bail!("Not a DISCO_PING message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode DISCO_PING")
}

/// Parse DISCO_PONG
pub fn parse_disco_pong(data: &[u8]) -> Result<DiscoPong> {
    if data.is_empty() || data[0] != MSG_DISCO_PONG {
        anyhow::bail!("Not a DISCO_PONG message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode DISCO_PONG")
}

/// Encode a DISCO_PING message
pub fn encode_disco_ping(ping: &DiscoPing) -> Result<Vec<u8>> {
    encode_message(MSG_DISCO_PING, ping)
}

/// Encode a DISCO_PONG message
pub fn encode_disco_pong(pong: &DiscoPong) -> Result<Vec<u8>> {
    encode_message(MSG_DISCO_PONG, pong)
}

// Re-export constants for matching
pub const SIGNALING_REGISTER_ACK: u8 = MSG_REGISTER_ACK;
pub const SIGNALING_HEARTBEAT_ACK: u8 = MSG_HEARTBEAT_ACK;
pub const SIGNALING_PEER_INFO: u8 = MSG_PEER_INFO;
pub const SIGNALING_STUN_RESPONSE: u8 = MSG_STUN_RESPONSE;
pub const SIGNALING_NAT_PUNCH: u8 = MSG_NAT_PUNCH;
pub const SIGNALING_DISCO_PING: u8 = MSG_DISCO_PING;
pub const SIGNALING_DISCO_PONG: u8 = MSG_DISCO_PONG;
pub const SIGNALING_ENCRYPTED: u8 = MSG_ENCRYPTED;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let mut alice = SignalingEncryption::new(true);
        let mut bob = SignalingEncryption::new(true);

        // Original message
        let original = b"Hello, encrypted world!";

        // Alice encrypts for Bob
        let encrypted = alice.encrypt(original, &bob.public_key_bytes()).unwrap();
        assert!(encrypted[0] == MSG_ENCRYPTED, "Should be encrypted message");

        // Bob decrypts
        let decrypted = bob.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encryption_disabled_passthrough() {
        let mut enc = SignalingEncryption::new(false);
        let peer_key = [0u8; 32];

        let original = vec![MSG_REGISTER, 1, 2, 3];
        let result = enc.encrypt(&original, &peer_key).unwrap();
        assert_eq!(result, original, "Disabled encryption should pass through");
    }

    #[test]
    fn test_decrypt_unencrypted_passthrough() {
        let mut enc = SignalingEncryption::new(true);

        let original = vec![MSG_REGISTER, 1, 2, 3];
        let result = enc.decrypt(&original).unwrap();
        assert_eq!(result, original, "Unencrypted messages should pass through");
    }

    #[test]
    fn test_encryption_with_sender() {
        let mut alice = SignalingEncryption::new(true);
        let mut bob = SignalingEncryption::new(true);

        let original = b"Message with sender tracking";
        let encrypted = alice.encrypt(original, &bob.public_key_bytes()).unwrap();

        let (decrypted, sender) = bob.decrypt_with_sender(&encrypted).unwrap();
        assert_eq!(decrypted, original);
        assert_eq!(sender, Some(alice.public_key_bytes()));
    }

    #[test]
    fn test_from_secret_key() {
        let secret_bytes = [42u8; 32];
        let enc1 = SignalingEncryption::from_secret_key(secret_bytes, true);
        let enc2 = SignalingEncryption::from_secret_key(secret_bytes, true);

        // Same secret key should produce same public key
        assert_eq!(enc1.public_key_bytes(), enc2.public_key_bytes());
        assert_eq!(enc1.secret_key_bytes(), enc2.secret_key_bytes());
    }
}
