//! Nucleus Signaling Protocol
//!
//! Simple UDP-based signaling for P2P VPN peer discovery.
//! Nucleus acts as a rendezvous server (like n2n supernode) - does NOT
//! store or validate public keys. Authentication happens edge-to-edge.
//!
//! Message Format (all messages are CBOR-encoded):
//! - REGISTER: Edge → Nucleus (join cluster with VIP + endpoint)
//! - PEER_LIST: Nucleus → Edge (list of peers in cluster)
//! - HEARTBEAT: Edge → Nucleus (keep alive)

use anyhow::{Context, Result};
use log::{info, warn, debug};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr};
use std::time::{Instant, Duration};
use tokio::net::UdpSocket;

/// Message types for signaling protocol
const MSG_REGISTER: u8 = 0x01;
const MSG_PEER_LIST: u8 = 0x02;
const MSG_HEARTBEAT: u8 = 0x03;
#[allow(dead_code)]
const MSG_DEREGISTER: u8 = 0x04;

/// Registration message from Edge to Nucleus
/// NOTE: Nucleus uses VIP as peer identifier (like n2n uses MAC)
/// Public key is passed through to other edges but NOT validated by Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterMessage {
    pub cluster: String,
    pub vip: Ipv4Addr,           // Primary identifier (like MAC in n2n)
    pub listen_port: u16,
    pub public_key: [u8; 32],    // Passed through for edge-to-edge auth
}

/// Peer info broadcast from Nucleus to Edges
/// Contains everything an edge needs to connect to another edge
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerInfo {
    pub vip: Ipv4Addr,
    pub endpoint: String,        // "ip:port"
    pub public_key: [u8; 32],    // For edge-to-edge Noise handshake
}

/// Peer list message from Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerListMessage {
    pub peers: Vec<PeerInfo>,
}

/// Heartbeat/keepalive - uses VIP as identifier (not pubkey)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatMessage {
    pub cluster: String,
    pub vip: Ipv4Addr,           // Identifies which peer is alive
}

/// Registered peer on Nucleus
/// Nucleus stores minimal info - just enough for routing/relay
/// No cryptographic validation - that's edge-to-edge
#[derive(Debug, Clone)]
pub struct RegisteredPeer {
    pub vip: Ipv4Addr,           // Primary identifier
    pub endpoint: SocketAddr,     // Where to reach this peer
    pub listen_port: u16,
    pub public_key: [u8; 32],    // Passed through, not validated
    pub last_seen: Instant,
}

/// Nucleus state - manages registered peers by cluster
/// Acts as simple rendezvous server (like n2n supernode)
#[derive(Default)]
pub struct NucleusState {
    /// cluster_name -> list of registered peers
    peers: HashMap<String, Vec<RegisteredPeer>>,
}

impl NucleusState {
    pub fn new() -> Self {
        Self { peers: HashMap::new() }
    }

    /// Register or update a peer (identified by VIP, not pubkey)
    pub fn register(&mut self, cluster: &str, peer: RegisteredPeer) {
        let peers = self.peers.entry(cluster.to_string()).or_default();
        
        // Find by VIP (like n2n uses MAC as identifier)
        if let Some(existing) = peers.iter_mut().find(|p| p.vip == peer.vip) {
            existing.endpoint = peer.endpoint;
            existing.listen_port = peer.listen_port;
            existing.public_key = peer.public_key; // Pass through updated key
            existing.last_seen = Instant::now();
            info!("Updated peer {} at {} in cluster '{}'", peer.vip, peer.endpoint, cluster);
        } else {
            info!("Registered new peer {} at {} in cluster '{}'", peer.vip, peer.endpoint, cluster);
            peers.push(peer);
        }
    }

    /// Get all peers in a cluster (except the requester, identified by VIP)
    pub fn get_peers(&self, cluster: &str, exclude_vip: Ipv4Addr) -> Vec<PeerInfo> {
        self.peers.get(cluster)
            .map(|peers| {
                peers.iter()
                    .filter(|p| p.vip != exclude_vip)
                    .map(|p| PeerInfo {
                        vip: p.vip,
                        endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                        public_key: p.public_key,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update heartbeat (identified by VIP)
    pub fn heartbeat(&mut self, cluster: &str, vip: Ipv4Addr) {
        if let Some(peers) = self.peers.get_mut(cluster) {
            if let Some(peer) = peers.iter_mut().find(|p| p.vip == vip) {
                peer.last_seen = Instant::now();
                debug!("Heartbeat from {}", vip);
            }
        }
    }

    /// Remove stale peers (no heartbeat for > 60 seconds)
    pub fn cleanup(&mut self) {
        let timeout = Duration::from_secs(60);
        for (cluster, peers) in self.peers.iter_mut() {
            let before = peers.len();
            peers.retain(|p| p.last_seen.elapsed() < timeout);
            let removed = before - peers.len();
            if removed > 0 {
                info!("Removed {} stale peers from cluster '{}'", removed, cluster);
            }
        }
    }

    /// Total registered peers
    pub fn peer_count(&self) -> usize {
        self.peers.values().map(|v| v.len()).sum()
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
/// Nucleus just relays peer info - no crypto validation
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
                        public_key: reg.public_key, // Pass through, don't validate
                        last_seen: Instant::now(),
                    };
                    state.register(&reg.cluster, peer);

                    // Send back peer list (exclude self by VIP)
                    let peers = state.get_peers(&reg.cluster, reg.vip);
                    let response = PeerListMessage { peers };
                    encode_message(MSG_PEER_LIST, &response).ok()
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
                    state.heartbeat(&hb.cluster, hb.vip);
                    None
                }
                Err(e) => {
                    warn!("Invalid HEARTBEAT from {}: {}", src, e);
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

    /// Send heartbeat to nucleus (uses VIP as identifier)
    pub async fn heartbeat(&self, socket: &UdpSocket) -> Result<()> {
        let msg = HeartbeatMessage {
            cluster: self.cluster.clone(),
            vip: self.vip,
        };
        let data = encode_message(MSG_HEARTBEAT, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        debug!("Sent heartbeat to nucleus");
        Ok(())
    }

    #[allow(dead_code)]
    pub fn nucleus_addr(&self) -> SocketAddr {
        self.nucleus_addr
    }
}

/// Parse peer list response
pub fn parse_peer_list(data: &[u8]) -> Result<Vec<PeerInfo>> {
    if data.is_empty() || data[0] != MSG_PEER_LIST {
        anyhow::bail!("Not a peer list message");
    }
    let list: PeerListMessage = serde_cbor::from_slice(&data[1..])
        .context("Failed to decode peer list")?;
    Ok(list.peers)
}

/// Check if message is from nucleus (peer list)
pub fn is_signaling_message(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == MSG_PEER_LIST
}
