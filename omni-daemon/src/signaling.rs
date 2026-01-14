//! Nucleus Signaling Protocol
//!
//! Simple UDP-based signaling for P2P VPN peer discovery.
//! 
//! Message Format (all messages are CBOR-encoded):
//! - REGISTER: Edge → Nucleus (join cluster)
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
const MSG_DEREGISTER: u8 = 0x04;

/// Registration message from Edge to Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterMessage {
    pub cluster: String,
    pub public_key: [u8; 32],
    pub vip: Ipv4Addr,
    pub listen_port: u16,
}

/// Peer info broadcast from Nucleus to Edges
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerInfo {
    pub public_key: [u8; 32],
    pub vip: Ipv4Addr,
    pub endpoint: String, // "ip:port"
}

/// Peer list message from Nucleus
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PeerListMessage {
    pub peers: Vec<PeerInfo>,
}

/// Heartbeat/keepalive
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeartbeatMessage {
    pub cluster: String,
    pub public_key: [u8; 32],
}

/// Registered peer on Nucleus
#[derive(Debug, Clone)]
pub struct RegisteredPeer {
    pub public_key: [u8; 32],
    pub vip: Ipv4Addr,
    pub endpoint: SocketAddr,
    pub listen_port: u16,
    pub last_seen: Instant,
}

/// Nucleus state - manages registered peers by cluster
#[derive(Default)]
pub struct NucleusState {
    /// cluster_name -> list of registered peers
    peers: HashMap<String, Vec<RegisteredPeer>>,
}

impl NucleusState {
    pub fn new() -> Self {
        Self { peers: HashMap::new() }
    }

    /// Register or update a peer
    pub fn register(&mut self, cluster: &str, peer: RegisteredPeer) {
        let peers = self.peers.entry(cluster.to_string()).or_default();
        
        // Update existing or add new
        if let Some(existing) = peers.iter_mut().find(|p| p.public_key == peer.public_key) {
            existing.endpoint = peer.endpoint;
            existing.vip = peer.vip;
            existing.listen_port = peer.listen_port;
            existing.last_seen = Instant::now();
            info!("Updated peer {} in cluster '{}'", peer.vip, cluster);
        } else {
            info!("Registered new peer {} in cluster '{}' from {}", peer.vip, cluster, peer.endpoint);
            peers.push(peer);
        }
    }

    /// Get all peers in a cluster (except the requester)
    pub fn get_peers(&self, cluster: &str, exclude_key: &[u8; 32]) -> Vec<PeerInfo> {
        self.peers.get(cluster)
            .map(|peers| {
                peers.iter()
                    .filter(|p| &p.public_key != exclude_key)
                    .map(|p| PeerInfo {
                        public_key: p.public_key,
                        vip: p.vip,
                        endpoint: format!("{}:{}", p.endpoint.ip(), p.listen_port),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update heartbeat
    pub fn heartbeat(&mut self, cluster: &str, public_key: &[u8; 32]) {
        if let Some(peers) = self.peers.get_mut(cluster) {
            if let Some(peer) = peers.iter_mut().find(|p| &p.public_key == public_key) {
                peer.last_seen = Instant::now();
                debug!("Heartbeat from {}", peer.vip);
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

/// Decode a signaling message
pub fn decode_message_type(data: &[u8]) -> Option<u8> {
    data.first().copied()
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
                        public_key: reg.public_key,
                        vip: reg.vip,
                        endpoint: src,
                        listen_port: reg.listen_port,
                        last_seen: Instant::now(),
                    };
                    state.register(&reg.cluster, peer);

                    // Send back peer list
                    let peers = state.get_peers(&reg.cluster, &reg.public_key);
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
                    state.heartbeat(&hb.cluster, &hb.public_key);
                    // Could send updated peer list, but skip for simplicity
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
    public_key: [u8; 32],
    vip: Ipv4Addr,
    listen_port: u16,
}

impl NucleusClient {
    pub async fn new(
        nucleus: &str,
        cluster: String,
        public_key: [u8; 32],
        vip: Ipv4Addr,
        listen_port: u16,
    ) -> Result<Self> {
        // Resolve nucleus address
        use tokio::net::lookup_host;
        let nucleus_addr = lookup_host(nucleus)
            .await
            .context("Failed to resolve nucleus address")?
            .next()
            .context("No addresses found for nucleus")?;

        Ok(Self {
            nucleus_addr,
            cluster,
            public_key,
            vip,
            listen_port,
        })
    }

    /// Send registration to nucleus
    pub async fn register(&self, socket: &UdpSocket) -> Result<()> {
        let msg = RegisterMessage {
            cluster: self.cluster.clone(),
            public_key: self.public_key,
            vip: self.vip,
            listen_port: self.listen_port,
        };
        let data = encode_message(MSG_REGISTER, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        info!("Registered with nucleus {} (cluster: {}, vip: {})", 
              self.nucleus_addr, self.cluster, self.vip);
        Ok(())
    }

    /// Send heartbeat to nucleus
    pub async fn heartbeat(&self, socket: &UdpSocket) -> Result<()> {
        let msg = HeartbeatMessage {
            cluster: self.cluster.clone(),
            public_key: self.public_key,
        };
        let data = encode_message(MSG_HEARTBEAT, &msg)?;
        socket.send_to(&data, self.nucleus_addr).await?;
        debug!("Sent heartbeat to nucleus");
        Ok(())
    }

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
