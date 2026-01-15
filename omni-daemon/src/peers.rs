//! Peer routing table for VIP-to-peer address mapping
//!
//! Maps virtual IPs to peer UDP endpoints for packet routing.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use log::info;

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Session ID for this peer
    pub session_id: u64,
    /// Peer's UDP endpoint (public IP:port)
    pub endpoint: SocketAddr,
    /// Peer's virtual IP
    pub virtual_ip: Ipv4Addr,
    /// Peer's X25519 public key (for Noise handshake)
    pub public_key: Option<[u8; 32]>,
    /// Last activity time
    pub last_seen: Instant,
    /// Whether handshake has been initiated to this peer
    pub handshake_initiated: bool,
}

/// Peer routing table
pub struct PeerTable {
    /// VIP → PeerInfo mapping
    by_vip: HashMap<Ipv4Addr, PeerInfo>,
    /// Session ID → VIP mapping (for reverse lookup)
    by_session: HashMap<u64, Ipv4Addr>,
    /// Peer timeout duration
    timeout: Duration,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            by_vip: HashMap::new(),
            by_session: HashMap::new(),
            timeout: Duration::from_secs(120), // 2 minute timeout
        }
    }
    
    /// Add or update a peer (without public key - for handshake completion)
    /// This is called when handshake completes, so set handshake_initiated=true
    pub fn upsert(&mut self, virtual_ip: Ipv4Addr, session_id: u64, endpoint: SocketAddr) {
        // Preserve existing public_key if peer already exists
        let existing_pubkey = self.by_vip.get(&virtual_ip).and_then(|p| p.public_key);
        
        let peer = PeerInfo {
            session_id,
            endpoint,
            virtual_ip,
            public_key: existing_pubkey,
            last_seen: Instant::now(),
            handshake_initiated: true, // Handshake completed!
        };
        
        // Remove old session mapping if VIP was mapped to different session
        if let Some(old) = self.by_vip.get(&virtual_ip) {
            if old.session_id != session_id {
                self.by_session.remove(&old.session_id);
            }
        }
        
        self.by_vip.insert(virtual_ip, peer);
        self.by_session.insert(session_id, virtual_ip);
        
        info!("Peer registered: {} → {} (session {})", virtual_ip, endpoint, session_id);
    }
    
    /// Register a peer from signaling (includes public key for handshake)
    /// Preserves handshake_initiated state if peer already exists
    pub fn register(&mut self, public_key: [u8; 32], endpoint: SocketAddr, vip: Ipv4Addr, session_id: u64) {
        // Preserve handshake_initiated state if peer already exists
        let handshake_initiated = self.by_vip.get(&vip)
            .map(|p| p.handshake_initiated)
            .unwrap_or(false);
        
        let peer = PeerInfo {
            session_id,
            endpoint,
            virtual_ip: vip,
            public_key: Some(public_key),
            last_seen: Instant::now(),
            handshake_initiated, // Preserve existing state!
        };
        
        // Remove old session mapping if VIP was mapped to different session
        if let Some(old) = self.by_vip.get(&vip) {
            if old.session_id != session_id {
                self.by_session.remove(&old.session_id);
            }
        }
        
        self.by_vip.insert(vip, peer);
        self.by_session.insert(session_id, vip);
        
        info!("Peer registered from signaling: {} → {} (session {})", vip, endpoint, session_id);
    }
    
    /// Mark peer as handshake initiated
    pub fn mark_handshake_initiated(&mut self, vip: &Ipv4Addr) {
        if let Some(peer) = self.by_vip.get_mut(vip) {
            peer.handshake_initiated = true;
        }
    }
    
    /// Get peers that need handshake initiation
    pub fn peers_needing_handshake(&self) -> Vec<PeerInfo> {
        self.by_vip.values()
            .filter(|p| p.public_key.is_some() && !p.handshake_initiated)
            .cloned()
            .collect()
    }
    
    /// Lookup peer by virtual IP
    pub fn lookup_by_vip(&self, vip: &Ipv4Addr) -> Option<&PeerInfo> {
        self.by_vip.get(vip)
    }
    
    /// Lookup peer by session ID
    pub fn lookup_by_session(&self, session_id: u64) -> Option<&PeerInfo> {
        self.by_session.get(&session_id)
            .and_then(|vip| self.by_vip.get(vip))
    }
    
    /// Update last_seen for a peer
    pub fn touch(&mut self, vip: &Ipv4Addr) {
        if let Some(peer) = self.by_vip.get_mut(vip) {
            peer.last_seen = Instant::now();
        }
    }
    
    /// Remove a peer by VIP (for delta updates from nucleus)
    pub fn remove_by_vip(&mut self, vip: &Ipv4Addr) {
        if let Some(peer) = self.by_vip.remove(vip) {
            self.by_session.remove(&peer.session_id);
            info!("Removed peer {} from routing table", vip);
        }
    }
    
    /// Remove expired peers
    pub fn cleanup(&mut self) -> Vec<Ipv4Addr> {
        let now = Instant::now();
        let expired: Vec<_> = self.by_vip.iter()
            .filter(|(_, p)| now.duration_since(p.last_seen) > self.timeout)
            .map(|(vip, _)| *vip)
            .collect();
        
        for vip in &expired {
            if let Some(peer) = self.by_vip.remove(vip) {
                self.by_session.remove(&peer.session_id);
                info!("Peer expired: {} (session {})", vip, peer.session_id);
            }
        }
        
        expired
    }
    
    /// Get peer count
    pub fn len(&self) -> usize {
        self.by_vip.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.by_vip.is_empty()
    }
    
    /// Iterate over all peers
    pub fn iter(&self) -> impl Iterator<Item = &PeerInfo> {
        self.by_vip.values()
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_peer_upsert_and_lookup() {
        let mut table = PeerTable::new();
        
        let vip = Ipv4Addr::new(10, 200, 0, 10);
        let endpoint: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        
        table.upsert(vip, 12345, endpoint);
        
        let peer = table.lookup_by_vip(&vip).unwrap();
        assert_eq!(peer.session_id, 12345);
        assert_eq!(peer.endpoint, endpoint);
        
        let peer2 = table.lookup_by_session(12345).unwrap();
        assert_eq!(peer2.virtual_ip, vip);
        
        assert_eq!(table.len(), 1);
    }
}
