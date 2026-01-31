//! Peer routing table for VIP-to-peer address mapping
//!
//! Maps virtual IPs to peer UDP endpoints for packet routing.

use log::info;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's UDP endpoint (public IP:port)
    pub endpoint: SocketAddr,
    /// Peer's virtual IP
    pub virtual_ip: Ipv4Addr,
    /// Peer's X25519 public key
    pub public_key: Option<[u8; 32]>,
    /// Last activity time
    pub last_seen: Instant,
}

/// Peer routing table
pub struct PeerTable {
    /// VIP → PeerInfo mapping
    by_vip: HashMap<Ipv4Addr, PeerInfo>,
    /// Peer timeout duration
    timeout: Duration,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            by_vip: HashMap::new(),
            timeout: Duration::from_secs(120), // 2 minute timeout
        }
    }

    /// Add or update a peer
    pub fn upsert(&mut self, virtual_ip: Ipv4Addr, endpoint: SocketAddr) {
        // Preserve existing public_key if peer already exists
        let existing_pubkey = self.by_vip.get(&virtual_ip).and_then(|p| p.public_key);

        let peer = PeerInfo {
            endpoint,
            virtual_ip,
            public_key: existing_pubkey,
            last_seen: Instant::now(),
        };

        self.by_vip.insert(virtual_ip, peer);

        info!("Peer registered: {} → {}", virtual_ip, endpoint);
    }

    /// Register a peer from signaling (includes public key and pinning check)
    pub fn register(
        &mut self,
        public_key: [u8; 32],
        endpoint: SocketAddr,
        vip: Ipv4Addr,
    ) -> Result<(), String> {
        if let Some(existing) = self.by_vip.get(&vip) {
            if let Some(pinned_key) = existing.public_key {
                if pinned_key != public_key {
                    let err = format!(
                        "ALERT: Public key mismatch for peer {}! Potential MITM attempt detected.",
                        vip
                    );
                    log::warn!("{}", err);
                    return Err(err);
                }
            }
        }

        let peer = PeerInfo {
            endpoint,
            virtual_ip: vip,
            public_key: Some(public_key),
            last_seen: Instant::now(),
        };

        self.by_vip.insert(vip, peer);
        info!("Peer registered and pinned: {} → {}", vip, endpoint);
        Ok(())
    }

    /// Lookup peer by virtual IP
    pub fn lookup_by_vip(&self, vip: &Ipv4Addr) -> Option<&PeerInfo> {
        self.by_vip.get(vip)
    }

    /// Update last_seen for a peer
    pub fn touch(&mut self, vip: &Ipv4Addr) {
        if let Some(peer) = self.by_vip.get_mut(vip) {
            peer.last_seen = Instant::now();
        }
    }

    /// Remove a peer by VIP (for delta updates from nucleus)
    pub fn remove_by_vip(&mut self, vip: &Ipv4Addr) -> Option<[u8; 32]> {
        if let Some(peer) = self.by_vip.remove(vip) {
            info!("Removed peer {} from routing table", vip);
            peer.public_key
        } else {
            None
        }
    }

    /// Remove expired peers
    pub fn cleanup(&mut self) -> Vec<Ipv4Addr> {
        let now = Instant::now();
        let expired: Vec<_> = self
            .by_vip
            .iter()
            .filter(|(_, p)| now.duration_since(p.last_seen) > self.timeout)
            .map(|(vip, _)| *vip)
            .collect();

        for vip in &expired {
            if let Some(_peer) = self.by_vip.remove(vip) {
                info!("Peer expired: {}", vip);
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

    /// Find a peer by their public key
    pub fn find_by_public_key(&self, public_key: &[u8; 32]) -> Option<&PeerInfo> {
        self.by_vip
            .values()
            .find(|p| p.public_key.as_ref() == Some(public_key))
    }

    /// Update a peer's endpoint by their public key
    /// Used when disco ping/pong reveals a new endpoint (NAT rebinding, mobile roaming)
    pub fn update_endpoint(
        &mut self,
        public_key: &[u8; 32],
        new_endpoint: SocketAddr,
    ) -> Result<(), String> {
        // Find the peer by public key
        let vip = self
            .by_vip
            .iter()
            .find(|(_, p)| p.public_key.as_ref() == Some(public_key))
            .map(|(vip, _)| *vip);

        if let Some(vip) = vip {
            if let Some(peer) = self.by_vip.get_mut(&vip) {
                let old_endpoint = peer.endpoint;
                peer.endpoint = new_endpoint;
                peer.last_seen = Instant::now();
                info!(
                    "Updated peer {} endpoint: {} -> {}",
                    vip, old_endpoint, new_endpoint
                );
                Ok(())
            } else {
                Err(format!("Peer {} not found", vip))
            }
        } else {
            Err("No peer found with matching public key".to_string())
        }
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

        table.upsert(vip, endpoint);

        let peer = table.lookup_by_vip(&vip).unwrap();
        assert_eq!(peer.endpoint, endpoint);

        assert_eq!(table.len(), 1);
    }
}
