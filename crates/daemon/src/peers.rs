//! Peer routing table for VIP-to-peer address mapping
//!
//! Maps virtual IPs to peer UDP endpoints for packet routing.

use log::info;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Information about a connected peer in the routing table
/// Note: This is distinct from signaling::PeerInfo which represents peer info from the nucleus
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Peer's UDP endpoint (public IP:port)
    pub endpoint: SocketAddr,
    /// Peer's virtual IP
    pub virtual_ip: Ipv4Addr,
    /// Peer's IPv6 virtual IP (dual-stack support)
    pub virtual_ip_v6: Option<Ipv6Addr>,
    /// Peer's X25519 public key
    pub public_key: Option<[u8; 32]>,
    /// Last activity time
    pub last_seen: Instant,
}

/// Peer routing table
pub struct PeerTable {
    /// VIP → PeerEntry mapping
    by_vip: HashMap<Ipv4Addr, PeerEntry>,
    /// IPv6 VIP → IPv4 VIP mapping for dual-stack routing
    by_vip_v6: HashMap<Ipv6Addr, Ipv4Addr>,
    /// Peer timeout duration
    timeout: Duration,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            by_vip: HashMap::new(),
            by_vip_v6: HashMap::new(),
            timeout: Duration::from_secs(120), // 2 minute timeout
        }
    }

    /// Add or update a peer
    pub fn upsert(&mut self, virtual_ip: Ipv4Addr, endpoint: SocketAddr) {
        self.upsert_with_v6(virtual_ip, None, endpoint);
    }

    /// Add or update a peer with optional IPv6 address
    pub fn upsert_with_v6(
        &mut self,
        virtual_ip: Ipv4Addr,
        virtual_ip_v6: Option<Ipv6Addr>,
        endpoint: SocketAddr,
    ) {
        // Preserve existing public_key and IPv6 if peer already exists
        let existing = self.by_vip.get(&virtual_ip);
        let existing_pubkey = existing.and_then(|p| p.public_key);
        let existing_v6 = existing.and_then(|p| p.virtual_ip_v6);

        // Use provided IPv6 or fall back to existing
        let final_v6 = virtual_ip_v6.or(existing_v6);

        let peer = PeerEntry {
            endpoint,
            virtual_ip,
            virtual_ip_v6: final_v6,
            public_key: existing_pubkey,
            last_seen: Instant::now(),
        };

        // Update IPv6 → IPv4 mapping
        if let Some(v6) = final_v6 {
            self.by_vip_v6.insert(v6, virtual_ip);
        }

        self.by_vip.insert(virtual_ip, peer);

        if let Some(v6) = final_v6 {
            info!("Peer registered: {} (v6: {}) → {}", virtual_ip, v6, endpoint);
        } else {
            info!("Peer registered: {} → {}", virtual_ip, endpoint);
        }
    }

    /// Register a peer from signaling (includes public key and pinning check)
    pub fn register(
        &mut self,
        public_key: [u8; 32],
        endpoint: SocketAddr,
        vip: Ipv4Addr,
    ) -> Result<(), String> {
        self.register_with_v6(public_key, endpoint, vip, None)
    }

    /// Register a peer from signaling with optional IPv6 (includes public key and pinning check)
    pub fn register_with_v6(
        &mut self,
        public_key: [u8; 32],
        endpoint: SocketAddr,
        vip: Ipv4Addr,
        vip_v6: Option<Ipv6Addr>,
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

        // Use provided IPv6 or preserve existing
        let existing_v6 = self.by_vip.get(&vip).and_then(|p| p.virtual_ip_v6);
        let final_v6 = vip_v6.or(existing_v6);

        let peer = PeerEntry {
            endpoint,
            virtual_ip: vip,
            virtual_ip_v6: final_v6,
            public_key: Some(public_key),
            last_seen: Instant::now(),
        };

        // Update IPv6 → IPv4 mapping
        if let Some(v6) = final_v6 {
            self.by_vip_v6.insert(v6, vip);
        }

        self.by_vip.insert(vip, peer);
        
        if let Some(v6) = final_v6 {
            info!("Peer registered and pinned: {} (v6: {}) → {}", vip, v6, endpoint);
        } else {
            info!("Peer registered and pinned: {} → {}", vip, endpoint);
        }
        Ok(())
    }

    /// Lookup peer by virtual IP
    pub fn lookup_by_vip(&self, vip: &Ipv4Addr) -> Option<&PeerEntry> {
        self.by_vip.get(vip)
    }

    /// Lookup peer by IPv6 virtual IP
    pub fn lookup_by_vip_v6(&self, vip_v6: &Ipv6Addr) -> Option<&PeerEntry> {
        self.by_vip_v6
            .get(vip_v6)
            .and_then(|vip| self.by_vip.get(vip))
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
            // Also remove from IPv6 mapping
            if let Some(v6) = peer.virtual_ip_v6 {
                self.by_vip_v6.remove(&v6);
            }
            info!("Removed peer {} (v6: {:?}) from routing table", vip, peer.virtual_ip_v6);
            peer.public_key
        } else {
            None
        }
    }

    /// Remove a peer by IPv6 VIP (for delta updates from nucleus)
    pub fn remove_by_vip_v6(&mut self, vip_v6: &Ipv6Addr) -> Option<[u8; 32]> {
        if let Some(vip) = self.by_vip_v6.remove(vip_v6) {
            if let Some(peer) = self.by_vip.remove(&vip) {
                info!("Removed peer {} (v6: {}) from routing table via IPv6", vip, vip_v6);
                return peer.public_key;
            }
        }
        None
    }

    /// Remove expired peers
    pub fn cleanup(&mut self) -> Vec<Ipv4Addr> {
        let now = Instant::now();
        let expired: Vec<_> = self
            .by_vip
            .iter()
            .filter(|(_, p)| now.duration_since(p.last_seen) > self.timeout)
            .map(|(vip, p)| (*vip, p.virtual_ip_v6))
            .collect();

        let mut expired_vips = Vec::new();
        for (vip, vip_v6) in expired {
            if let Some(_peer) = self.by_vip.remove(&vip) {
                // Also remove from IPv6 mapping
                if let Some(v6) = vip_v6 {
                    self.by_vip_v6.remove(&v6);
                }
                info!("Peer expired: {} (v6: {:?})", vip, vip_v6);
                expired_vips.push(vip);
            }
        }

        expired_vips
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
    pub fn iter(&self) -> impl Iterator<Item = &PeerEntry> {
        self.by_vip.values()
    }

    /// Find a peer by their public key
    pub fn find_by_public_key(&self, public_key: &[u8; 32]) -> Option<&PeerEntry> {
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
        assert_eq!(peer.virtual_ip_v6, None);

        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_peer_upsert_with_v6() {
        let mut table = PeerTable::new();

        let vip = Ipv4Addr::new(10, 200, 0, 10);
        let vip_v6: Ipv6Addr = "fd00:1234::10".parse().unwrap();
        let endpoint: SocketAddr = "1.2.3.4:51820".parse().unwrap();

        table.upsert_with_v6(vip, Some(vip_v6), endpoint);

        // Lookup by IPv4
        let peer = table.lookup_by_vip(&vip).unwrap();
        assert_eq!(peer.endpoint, endpoint);
        assert_eq!(peer.virtual_ip_v6, Some(vip_v6));

        // Lookup by IPv6
        let peer_v6 = table.lookup_by_vip_v6(&vip_v6).unwrap();
        assert_eq!(peer_v6.virtual_ip, vip);
        assert_eq!(peer_v6.endpoint, endpoint);

        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_remove_by_vip_cleans_v6() {
        let mut table = PeerTable::new();

        let vip = Ipv4Addr::new(10, 200, 0, 10);
        let vip_v6: Ipv6Addr = "fd00:1234::10".parse().unwrap();
        let endpoint: SocketAddr = "1.2.3.4:51820".parse().unwrap();

        table.upsert_with_v6(vip, Some(vip_v6), endpoint);
        assert!(table.lookup_by_vip_v6(&vip_v6).is_some());

        table.remove_by_vip(&vip);

        assert!(table.lookup_by_vip(&vip).is_none());
        assert!(table.lookup_by_vip_v6(&vip_v6).is_none());
    }
}
