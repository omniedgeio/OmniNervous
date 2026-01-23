//! Nucleus Signaling Protocol - Scalable for 1000+ Edges
//!
//! ### Protocol Flow
//! ```mermaid
//! sequence_flow
//!   Edge->>Nucleus: REGISTER (Cluster, VIP, Port, PubKey)
//!   Nucleus-->>Edge: REGISTER_ACK (Success, RecentPeers)
//!   loop Every 30s
//!     Edge->>Nucleus: HEARTBEAT (Cluster, VIP, KnownCount)
//!     Nucleus-->>Edge: HEARTBEAT_ACK (NewPeers, RemovedVIPs)
//!   end
//!   Edge->>Nucleus: QUERY_PEER (TargetVIP)
//!   Nucleus-->>Edge: PEER_INFO (Endpoint, PubKey)
//! ```
//!
//! ### Key Concept
//! Nucleus acts as a VIP → endpoint registry (like DNS for VPN).
//! Edges use delta updates (heartbeats) to stay in sync without full table refreshes.

use anyhow::{Context, Result};
use log::{info, warn, debug};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr};
use std::time::{Instant, Duration};
use tokio::net::UdpSocket;

/// Message types for signaling protocol
const MSG_REGISTER: u8 = 0x01;
const MSG_REGISTER_ACK: u8 = 0x02;
const MSG_HEARTBEAT: u8 = 0x03;
const MSG_HEARTBEAT_ACK: u8 = 0x04;
const MSG_QUERY_PEER: u8 = 0x05;
const MSG_PEER_INFO: u8 = 0x06;
#[allow(dead_code)]
const MSG_DEREGISTER: u8 = 0x07;

/// How long peers stay in "recent" list for delta updates
const RECENT_PEER_WINDOW_SECS: u64 = 90; // 3x heartbeat interval

/// Registration message from Edge to Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterMessage {
    pub cluster: String,
    pub vip: Ipv4Addr,
    pub listen_port: u16,
    pub public_key: [u8; 32],
}

/// Registration acknowledgment (includes recent peers for initial discovery)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterAckMessage {
    pub success: bool,
    pub recent_peers: Vec<PeerInfo>,  // Peers that joined in last 90s
}

/// Heartbeat from Edge to Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatMessage {
    pub cluster: String,
    pub vip: Ipv4Addr,
    pub last_seen_count: u32,  // Number of peers edge knows about
}

/// Heartbeat acknowledgment with delta updates
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatAckMessage {
    pub new_peers: Vec<PeerInfo>,      // Joined since last heartbeat
    pub removed_vips: Vec<Ipv4Addr>,   // Left since last heartbeat
}

/// Query for a specific peer by VIP
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QueryPeerMessage {
    pub cluster: String,
    pub target_vip: Ipv4Addr,
    pub requester_vip: Ipv4Addr,
}

/// Peer info response (single peer)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerInfo {
    pub vip: Ipv4Addr,
    pub endpoint: String,        // "ip:port"
    pub public_key: [u8; 32],
}

/// Response to QUERY_PEER
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerInfoMessage {
    pub found: bool,
    pub peer: Option<PeerInfo>,
}

/// Registered peer on Nucleus with join time tracking
#[derive(Debug, Clone)]
pub struct RegisteredPeer {
    pub vip: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub listen_port: u16,
    pub public_key: [u8; 32],
    pub joined_at: Instant,      // For "recent peers" calculation
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
#[derive(Default)]
pub struct NucleusState {
    clusters: HashMap<String, ClusterState>,
}

impl NucleusState {
    pub fn new() -> Self {
        Self { clusters: HashMap::new() }
    }

    /// Register or update a peer
    pub fn register(&mut self, cluster: &str, peer: RegisteredPeer) -> Vec<PeerInfo> {
        let state = self.clusters.entry(cluster.to_string()).or_default();
        let is_new = !state.peers.contains_key(&peer.vip);
        
        if is_new {
            info!("New peer {} at {} in cluster '{}'", peer.vip, peer.endpoint, cluster);
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
        
        self.clusters.get(cluster)
            .map(|state| {
                state.peers.values()
                    .filter(|p| p.vip != exclude_vip && p.joined_at.elapsed() < window)
                    .map(|p| PeerInfo {
                        vip: p.vip,
                        endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                        public_key: p.public_key,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update heartbeat and return delta (new peers + removed peers)
    pub fn heartbeat(&mut self, cluster: &str, vip: Ipv4Addr, last_heartbeat_time: Option<Instant>) 
        -> (Vec<PeerInfo>, Vec<Ipv4Addr>) 
    {
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
        let new_peers: Vec<PeerInfo> = state.peers.values()
            .filter(|p| p.vip != vip && p.joined_at > since)
            .map(|p| PeerInfo {
                vip: p.vip,
                endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                public_key: p.public_key,
            })
            .collect();
        
        // Removed peers since last heartbeat
        let removed_vips: Vec<Ipv4Addr> = state.removed.iter()
            .filter(|r| r.removed_at > since)
            .map(|r| r.vip)
            .collect();
        
        (new_peers, removed_vips)
    }

    /// Lookup a specific peer by VIP (O(1))
    pub fn query_peer(&self, cluster: &str, vip: Ipv4Addr) -> Option<PeerInfo> {
        self.clusters.get(cluster)
            .and_then(|state| state.peers.get(&vip))
            .map(|p| PeerInfo {
                vip: p.vip,
                endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                public_key: p.public_key,
            })
    }

    /// Remove stale peers (no heartbeat for > 60 seconds)
    pub fn cleanup(&mut self) {
        let timeout = Duration::from_secs(60);
        let removal_retention = Duration::from_secs(RECENT_PEER_WINDOW_SECS);
        
        for (cluster, state) in self.clusters.iter_mut() {
            // Find and remove stale peers
            let stale: Vec<Ipv4Addr> = state.peers.iter()
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
            state.removed.retain(|r| r.removed_at.elapsed() < removal_retention);
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
    let encoded = serde_cbor::to_vec(payload)
        .context("Failed to encode CBOR")?;
    data.extend(encoded);
    Ok(data)
}

/// Handle incoming signaling message (Nucleus side)
pub fn handle_nucleus_message(
    state: &mut NucleusState,
    data: &[u8],
    src: SocketAddr,
) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }

    let msg_type = data[0];
    let payload = &data[1..];

    match msg_type {
        MSG_REGISTER => {
            match serde_cbor::from_slice::<RegisterMessage>(payload) {
                Ok(reg) => {
                    let peer = RegisteredPeer {
                        vip: reg.vip,
                        endpoint: src,
                        listen_port: reg.listen_port,
                        public_key: reg.public_key,
                        joined_at: Instant::now(),
                        last_seen: Instant::now(),
                    };
                    let recent_peers = state.register(&reg.cluster, peer);
                    
                    let ack = RegisterAckMessage {
                        success: true,
                        recent_peers,
                    };
                    encode_message(MSG_REGISTER_ACK, &ack).ok()
                }
                Err(e) => {
                    warn!("Invalid REGISTER from {}: {}", src, e);
                    None
                }
            }
        }
        MSG_HEARTBEAT => {
            match serde_cbor::from_slice::<HeartbeatMessage>(payload) {
                Ok(hb) => {
                    let (new_peers, removed_vips) = state.heartbeat(&hb.cluster, hb.vip, None);
                    let ack = HeartbeatAckMessage { new_peers, removed_vips };
                    encode_message(MSG_HEARTBEAT_ACK, &ack).ok()
                }
                Err(e) => {
                    warn!("Invalid HEARTBEAT from {}: {}", src, e);
                    None
                }
            }
        }
        MSG_QUERY_PEER => {
            match serde_cbor::from_slice::<QueryPeerMessage>(payload) {
                Ok(query) => {
                    let peer = state.query_peer(&query.cluster, query.target_vip);
                    let response = PeerInfoMessage {
                        found: peer.is_some(),
                        peer,
                    };
                    encode_message(MSG_PEER_INFO, &response).ok()
                }
                Err(e) => {
                    warn!("Invalid QUERY_PEER from {}: {}", src, e);
                    None
                }
            }
        }
        _ => {
            debug!("Unknown message type {} from {}", msg_type, src);
            None
        }
    }
}

/// Edge client for connecting to Nucleus
pub struct NucleusClient {
    nucleus_addr: SocketAddr,
    cluster: String,
    vip: Ipv4Addr,
    listen_port: u16,
    public_key: [u8; 32],
}

impl NucleusClient {
    pub async fn new(
        nucleus: &str,
        cluster: String,
        public_key: [u8; 32],
        vip: Ipv4Addr,
        listen_port: u16,
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
        })
    }

    /// Send registration to nucleus
    pub async fn register(&self, socket: &UdpSocket) -> Result<()> {
        let msg = RegisterMessage {
            cluster: self.cluster.clone(),
            vip: self.vip,
            listen_port: self.listen_port,
            public_key: self.public_key,
        };
        let data = encode_message(MSG_REGISTER, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        info!("Registered with nucleus {} (cluster: {}, vip: {})", 
              self.nucleus_addr, self.cluster, self.vip);
        Ok(())
    }

    /// Send heartbeat to nucleus
    pub async fn heartbeat(&self, socket: &UdpSocket, known_peer_count: u32) -> Result<()> {
        let msg = HeartbeatMessage {
            cluster: self.cluster.clone(),
            vip: self.vip,
            last_seen_count: known_peer_count,
        };
        let data = encode_message(MSG_HEARTBEAT, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        debug!("Sent heartbeat to nucleus");
        Ok(())
    }

    /// Query specific peer by VIP
    pub async fn query_peer(&self, socket: &UdpSocket, target_vip: Ipv4Addr) -> Result<()> {
        let msg = QueryPeerMessage {
            cluster: self.cluster.clone(),
            target_vip,
            requester_vip: self.vip,
        };
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
pub fn parse_register_ack(data: &[u8]) -> Result<RegisterAckMessage> {
    if data.is_empty() || data[0] != MSG_REGISTER_ACK {
        anyhow::bail!("Not a REGISTER_ACK message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode REGISTER_ACK")
}

/// Parse HEARTBEAT_ACK response
pub fn parse_heartbeat_ack(data: &[u8]) -> Result<HeartbeatAckMessage> {
    if data.is_empty() || data[0] != MSG_HEARTBEAT_ACK {
        anyhow::bail!("Not a HEARTBEAT_ACK message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode HEARTBEAT_ACK")
}

/// Parse PEER_INFO response
pub fn parse_peer_info(data: &[u8]) -> Result<PeerInfoMessage> {
    if data.is_empty() || data[0] != MSG_PEER_INFO {
        anyhow::bail!("Not a PEER_INFO message");
    }
    serde_cbor::from_slice(&data[1..]).context("Failed to decode PEER_INFO")
}

/// Check if message is a signaling message (from nucleus)
pub fn is_signaling_message(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    matches!(data[0], MSG_REGISTER_ACK | MSG_HEARTBEAT_ACK | MSG_PEER_INFO)
}

/// Get signaling message type
pub fn get_signaling_type(data: &[u8]) -> Option<u8> {
    data.first().copied()
}

// Re-export constants for matching
pub const SIGNALING_REGISTER_ACK: u8 = MSG_REGISTER_ACK;
pub const SIGNALING_HEARTBEAT_ACK: u8 = MSG_HEARTBEAT_ACK;
pub const SIGNALING_PEER_INFO: u8 = MSG_PEER_INFO;
