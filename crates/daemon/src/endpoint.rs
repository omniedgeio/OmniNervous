//! Endpoint Management for Multi-Path NAT Traversal
//!
//! Tracks multiple endpoints per peer with latency measurements and
//! connection state, enabling optimal path selection and automatic
//! failover between direct and relay connections.

use log::{debug, info};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// ============================================================================
// Data Structures
// ============================================================================

/// Source of an endpoint discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSource {
    /// Discovered via STUN query
    Stun,
    /// Reported by Nucleus signaling server
    Nucleus,
    /// Discovered via disco ping/pong
    DirectProbe,
    /// Relay server endpoint
    Relay,
    /// Port mapping (NAT-PMP/UPnP)
    PortMap,
}

/// Type of network path
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathType {
    /// Direct IPv4 connection
    DirectIPv4,
    /// Direct IPv6 connection (preferred)
    DirectIPv6,
    /// Relayed connection
    Relay,
}

/// Connection state for an endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    /// Initial state, not yet probed
    Init,
    /// Actively probing with disco pings
    Probing,
    /// Direct connection confirmed via disco pong
    DirectOk,
    /// Direct connection failed, using relay
    RelayOk,
    /// Connection failed
    Failed,
}

/// Information about a single endpoint
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    /// Socket address
    pub addr: SocketAddr,
    /// How this endpoint was discovered
    pub source: EndpointSource,
    /// Measured latency (RTT/2)
    pub latency: Option<Duration>,
    /// When we last received a pong from this endpoint
    pub last_pong: Option<Instant>,
    /// Type of path
    pub path_type: PathType,
    /// Current connection state
    pub state: EndpointState,
    /// Number of probe attempts
    pub probe_count: u32,
    /// Last probe time
    pub last_probe: Option<Instant>,
}

impl EndpointInfo {
    /// Create a new endpoint from discovery
    pub fn new(addr: SocketAddr, source: EndpointSource) -> Self {
        let path_type = if source == EndpointSource::Relay {
            PathType::Relay
        } else if addr.is_ipv6() {
            PathType::DirectIPv6
        } else {
            PathType::DirectIPv4
        };

        Self {
            addr,
            source,
            latency: None,
            last_pong: None,
            path_type,
            state: EndpointState::Init,
            probe_count: 0,
            last_probe: None,
        }
    }

    /// Update endpoint with pong response
    pub fn record_pong(&mut self, rtt: Duration) {
        self.latency = Some(rtt / 2); // One-way latency estimate
        self.last_pong = Some(Instant::now());
        self.state = if self.source == EndpointSource::Relay {
            EndpointState::RelayOk
        } else {
            EndpointState::DirectOk
        };
    }

    /// Mark endpoint as probing
    pub fn mark_probing(&mut self) {
        self.state = EndpointState::Probing;
        self.probe_count += 1;
        self.last_probe = Some(Instant::now());
    }

    /// Mark endpoint as failed
    pub fn mark_failed(&mut self) {
        self.state = EndpointState::Failed;
    }

    /// Check if endpoint is responsive (recently got pong)
    pub fn is_responsive(&self, timeout: Duration) -> bool {
        self.last_pong
            .map(|t| t.elapsed() < timeout)
            .unwrap_or(false)
    }

    /// Check if endpoint needs re-probing
    pub fn needs_probe(&self, interval: Duration) -> bool {
        match self.last_probe {
            Some(t) => t.elapsed() > interval,
            None => true,
        }
    }
}

/// Collection of endpoints for a peer with path selection logic
#[derive(Debug, Clone)]
pub struct EndpointSet {
    /// All known endpoints for this peer
    pub endpoints: Vec<EndpointInfo>,
    /// Index of the currently selected best endpoint
    pub best_endpoint: Option<usize>,
    /// When the best endpoint was last changed
    pub best_changed_at: Option<Instant>,
}

impl EndpointSet {
    /// Create an empty endpoint set
    pub fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            best_endpoint: None,
            best_changed_at: None,
        }
    }

    /// Add or update an endpoint
    pub fn upsert(&mut self, addr: SocketAddr, source: EndpointSource) -> usize {
        // Check if endpoint already exists
        for (i, ep) in self.endpoints.iter_mut().enumerate() {
            if ep.addr == addr {
                // Update source if it's a "better" source
                if source_priority(source) > source_priority(ep.source) {
                    ep.source = source;
                }
                return i;
            }
        }

        // Add new endpoint
        let ep = EndpointInfo::new(addr, source);
        self.endpoints.push(ep);
        self.endpoints.len() - 1
    }

    /// Get the best endpoint address
    pub fn best_addr(&self) -> Option<SocketAddr> {
        self.best_endpoint
            .and_then(|i| self.endpoints.get(i))
            .map(|e| e.addr)
    }

    /// Get the best endpoint info
    pub fn best(&self) -> Option<&EndpointInfo> {
        self.best_endpoint.and_then(|i| self.endpoints.get(i))
    }

    /// Record a pong response from an endpoint
    pub fn record_pong(&mut self, addr: SocketAddr, rtt: Duration) {
        if let Some(ep) = self.endpoints.iter_mut().find(|e| e.addr == addr) {
            ep.record_pong(rtt);
        }

        // Re-evaluate best endpoint
        self.select_best_endpoint();
    }

    /// Select the best endpoint based on latency and path type
    pub fn select_best_endpoint(&mut self) -> bool {
        // Collect responsive endpoints with latency
        let mut candidates: Vec<(usize, &EndpointInfo)> = self
            .endpoints
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                matches!(e.state, EndpointState::DirectOk | EndpointState::RelayOk)
                    && e.latency.is_some()
            })
            .collect();

        if candidates.is_empty() {
            return false;
        }

        // Sort by latency (ascending)
        candidates.sort_by_key(|(_, e)| e.latency.unwrap());

        // Get the best by latency
        let (best_idx, best) = candidates[0];

        // Prefer IPv6 if within 5ms of the best
        let ipv6_threshold = Duration::from_millis(5);
        for (idx, ep) in &candidates {
            if ep.path_type == PathType::DirectIPv6 {
                if let (Some(ep_lat), Some(best_lat)) = (ep.latency, best.latency) {
                    if ep_lat <= best_lat + ipv6_threshold {
                        return self.set_best(*idx);
                    }
                }
            }
        }

        // Prefer direct over relay at similar latency
        let relay_threshold = Duration::from_millis(10);
        if best.path_type == PathType::Relay {
            for (idx, ep) in &candidates {
                if ep.path_type != PathType::Relay {
                    if let (Some(ep_lat), Some(best_lat)) = (ep.latency, best.latency) {
                        if ep_lat <= best_lat + relay_threshold {
                            return self.set_best(*idx);
                        }
                    }
                }
            }
        }

        self.set_best(best_idx)
    }

    /// Set the best endpoint, returning true if it changed
    fn set_best(&mut self, idx: usize) -> bool {
        if self.best_endpoint != Some(idx) {
            let old_addr = self.best_addr();
            self.best_endpoint = Some(idx);
            self.best_changed_at = Some(Instant::now());

            if let Some(ep) = self.endpoints.get(idx) {
                info!(
                    "Best endpoint changed: {:?} -> {} ({:?}, latency {:?})",
                    old_addr, ep.addr, ep.path_type, ep.latency
                );
            }
            true
        } else {
            false
        }
    }

    /// Get endpoints that need probing
    pub fn endpoints_needing_probe(&self, interval: Duration) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .filter(|e| e.needs_probe(interval) && e.state != EndpointState::Failed)
            .map(|e| e.addr)
            .collect()
    }

    /// Mark an endpoint as probing
    pub fn mark_probing(&mut self, addr: SocketAddr) {
        if let Some(ep) = self.endpoints.iter_mut().find(|e| e.addr == addr) {
            ep.mark_probing();
        }
    }

    /// Mark an endpoint as failed
    pub fn mark_failed(&mut self, addr: SocketAddr) {
        if let Some(ep) = self.endpoints.iter_mut().find(|e| e.addr == addr) {
            ep.mark_failed();
        }

        // If the failed endpoint was the best, re-select
        if self.best_addr() == Some(addr) {
            self.select_best_endpoint();
        }
    }

    /// Count of responsive endpoints
    pub fn responsive_count(&self, timeout: Duration) -> usize {
        self.endpoints
            .iter()
            .filter(|e| e.is_responsive(timeout))
            .count()
    }

    /// Check if we have any working connection
    pub fn has_working_connection(&self) -> bool {
        self.endpoints
            .iter()
            .any(|e| matches!(e.state, EndpointState::DirectOk | EndpointState::RelayOk))
    }

    /// Check if we need to try relay (all direct attempts failed)
    pub fn needs_relay(&self) -> bool {
        let direct_endpoints = self
            .endpoints
            .iter()
            .filter(|e| e.path_type != PathType::Relay);
        let all_failed = direct_endpoints
            .clone()
            .all(|e| e.state == EndpointState::Failed);
        let probed_enough = direct_endpoints.clone().all(|e| e.probe_count >= 3);

        all_failed && probed_enough && !self.has_working_connection()
    }
}

impl Default for EndpointSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Get priority of an endpoint source (higher = more trusted)
fn source_priority(source: EndpointSource) -> u8 {
    match source {
        EndpointSource::DirectProbe => 4, // Confirmed working
        EndpointSource::Stun => 3,        // Self-discovered
        EndpointSource::PortMap => 2,     // Configured mapping
        EndpointSource::Nucleus => 1,     // Signaled by server
        EndpointSource::Relay => 0,       // Fallback
    }
}

// ============================================================================
// Connection State Machine
// ============================================================================

/// Overall connection state for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state
    Init,
    /// Attempting direct connection
    DirectTry,
    /// Direct connection established
    DirectOk,
    /// Direct connection failed, attempting relay
    RelayTry,
    /// Relay connection established
    RelayOk,
    /// All connection attempts failed
    Failed,
}

/// Connection manager for a single peer
#[derive(Debug)]
pub struct PeerConnection {
    /// Peer's public key
    pub public_key: [u8; 32],
    /// Current connection state
    pub state: ConnectionState,
    /// Endpoint set with all known endpoints
    pub endpoints: EndpointSet,
    /// When state last changed
    pub state_changed_at: Instant,
    /// Whether we should try upgrading from relay to direct
    pub try_upgrade: bool,
    /// Last upgrade attempt
    pub last_upgrade_attempt: Option<Instant>,
}

impl PeerConnection {
    /// Create a new peer connection
    pub fn new(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            state: ConnectionState::Init,
            endpoints: EndpointSet::new(),
            state_changed_at: Instant::now(),
            try_upgrade: false,
            last_upgrade_attempt: None,
        }
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: ConnectionState) {
        if self.state != new_state {
            debug!(
                "Peer {:02x?}... state: {:?} -> {:?}",
                &self.public_key[..4],
                self.state,
                new_state
            );
            self.state = new_state;
            self.state_changed_at = Instant::now();
        }
    }

    /// Add an endpoint and update state if needed
    pub fn add_endpoint(&mut self, addr: SocketAddr, source: EndpointSource) {
        self.endpoints.upsert(addr, source);

        // If we're in init state and got an endpoint, start trying direct
        if self.state == ConnectionState::Init {
            self.transition(ConnectionState::DirectTry);
        }
    }

    /// Record successful probe response
    pub fn record_pong(&mut self, addr: SocketAddr, rtt: Duration) {
        self.endpoints.record_pong(addr, rtt);

        // Update connection state based on path type
        if let Some(ep) = self.endpoints.best() {
            match ep.path_type {
                PathType::DirectIPv4 | PathType::DirectIPv6 => {
                    self.transition(ConnectionState::DirectOk);
                    self.try_upgrade = false;
                }
                PathType::Relay => {
                    self.transition(ConnectionState::RelayOk);
                    self.try_upgrade = true; // Try to upgrade to direct later
                }
            }
        }
    }

    /// Mark probe failure for an endpoint
    pub fn record_probe_failure(&mut self, addr: SocketAddr) {
        self.endpoints.mark_failed(addr);

        // Check if we need to try relay
        if self.endpoints.needs_relay() && self.state == ConnectionState::DirectTry {
            self.transition(ConnectionState::RelayTry);
        } else if !self.endpoints.has_working_connection() {
            self.transition(ConnectionState::Failed);
        }
    }

    /// Check if we should attempt a relay-to-direct upgrade
    pub fn should_try_upgrade(&self, interval: Duration) -> bool {
        if !self.try_upgrade || self.state != ConnectionState::RelayOk {
            return false;
        }

        match self.last_upgrade_attempt {
            Some(t) => t.elapsed() > interval,
            None => true,
        }
    }

    /// Mark upgrade attempt
    pub fn mark_upgrade_attempt(&mut self) {
        self.last_upgrade_attempt = Some(Instant::now());
    }

    /// Get the current best endpoint for WireGuard
    pub fn best_endpoint(&self) -> Option<SocketAddr> {
        self.endpoints.best_addr()
    }

    /// Check if connection is usable
    pub fn is_connected(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::DirectOk | ConnectionState::RelayOk
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_creation() {
        let addr: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let ep = EndpointInfo::new(addr, EndpointSource::Nucleus);

        assert_eq!(ep.addr, addr);
        assert_eq!(ep.path_type, PathType::DirectIPv4);
        assert_eq!(ep.state, EndpointState::Init);
        assert!(ep.latency.is_none());
    }

    #[test]
    fn test_endpoint_pong_recording() {
        let addr: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let mut ep = EndpointInfo::new(addr, EndpointSource::Nucleus);

        ep.record_pong(Duration::from_millis(100));

        assert_eq!(ep.latency, Some(Duration::from_millis(50)));
        assert_eq!(ep.state, EndpointState::DirectOk);
        assert!(ep.last_pong.is_some());
    }

    #[test]
    fn test_endpoint_set_best_selection() {
        let mut set = EndpointSet::new();

        let addr1: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:51820".parse().unwrap();

        set.upsert(addr1, EndpointSource::Nucleus);
        set.upsert(addr2, EndpointSource::Nucleus);

        // Record pongs with different latencies
        set.record_pong(addr1, Duration::from_millis(100));
        set.record_pong(addr2, Duration::from_millis(50));

        // addr2 should be best (lower latency)
        assert_eq!(set.best_addr(), Some(addr2));
    }

    #[test]
    fn test_peer_connection_state_machine() {
        let mut conn = PeerConnection::new([0u8; 32]);
        assert_eq!(conn.state, ConnectionState::Init);

        // Add endpoint -> DirectTry
        conn.add_endpoint("1.2.3.4:51820".parse().unwrap(), EndpointSource::Nucleus);
        assert_eq!(conn.state, ConnectionState::DirectTry);

        // Successful pong -> DirectOk
        conn.record_pong("1.2.3.4:51820".parse().unwrap(), Duration::from_millis(50));
        assert_eq!(conn.state, ConnectionState::DirectOk);
        assert!(conn.is_connected());
    }

    #[test]
    fn test_ipv6_preference() {
        let mut set = EndpointSet::new();

        let addr_v4: SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let addr_v6: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();

        set.upsert(addr_v4, EndpointSource::Nucleus);
        set.upsert(addr_v6, EndpointSource::Nucleus);

        // Record pongs - IPv4 is slightly faster
        set.record_pong(addr_v4, Duration::from_millis(50));
        set.record_pong(addr_v6, Duration::from_millis(55)); // Within 5ms threshold

        // IPv6 should be preferred even though slightly slower
        assert_eq!(set.best_addr(), Some(addr_v6));
    }
}
