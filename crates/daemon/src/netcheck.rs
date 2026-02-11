//! NAT Type Detection via Multi-STUN Queries
//!
//! This module implements NAT type detection by querying multiple STUN servers
//! and comparing the results. If the same local socket receives different
//! public addresses from different STUN servers, we're behind a Symmetric NAT.
//!
//! ### NAT Types (RFC 3489 classification):
//! - **Open**: No NAT, direct internet connection
//! - **Full Cone**: Any external host can send to mapped port
//! - **Restricted Cone**: Only hosts we've sent to can reply (any port)
//! - **Port Restricted Cone**: Only hosts we've sent to can reply (same port)
//! - **Symmetric**: Mapping varies by destination (hardest to traverse)
//!
//! ### Detection Algorithm:
//! 1. Query 2+ STUN servers from the same local socket
//! 2. Compare XOR-MAPPED-ADDRESS results
//! 3. If addresses differ → Symmetric NAT
//! 4. If addresses match → Cone NAT (type TBD by further tests)

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::stun::{parse_xor_mapped_address, STUN_SERVERS};

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatType {
    /// Unknown - detection not yet run or failed
    Unknown,
    /// No NAT detected (public IP)
    Open,
    /// Full Cone NAT - easiest to traverse
    FullCone,
    /// Restricted Cone NAT - requires outbound packet first
    RestrictedCone,
    /// Port Restricted Cone NAT - stricter than Restricted
    PortRestrictedCone,
    /// Symmetric NAT - mapping varies by destination (hardest)
    Symmetric,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Unknown => write!(f, "Unknown"),
            NatType::Open => write!(f, "Open"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::RestrictedCone => write!(f, "Restricted Cone"),
            NatType::PortRestrictedCone => write!(f, "Port Restricted Cone"),
            NatType::Symmetric => write!(f, "Symmetric"),
        }
    }
}

/// Result of STUN query to a single server
#[derive(Debug, Clone)]
pub struct StunQueryResult {
    /// STUN server that was queried
    pub server: SocketAddr,
    /// Our public address as seen by this server
    pub mapped_addr: Option<SocketAddr>,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Whether the query succeeded
    pub success: bool,
}

/// Comprehensive NAT detection report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatReport {
    /// Detected NAT type
    pub nat_type: NatType,
    /// True if mapping varies by destination (definitive Symmetric NAT indicator)
    pub mapping_varies_by_dest: bool,
    /// Our public IPv4 address (if discovered)
    pub public_addr_v4: Option<SocketAddr>,
    /// Our public IPv6 address (if discovered)
    pub public_addr_v6: Option<SocketAddr>,
    /// Whether UDP works over IPv4
    pub ipv4_works: bool,
    /// Whether UDP works over IPv6
    pub ipv6_works: bool,
    /// Number of STUN servers that responded
    pub servers_responded: u32,
    /// Detection timestamp (seconds since UNIX epoch)
    pub detected_at: u64,
}

impl Default for NatReport {
    fn default() -> Self {
        Self {
            nat_type: NatType::Unknown,
            mapping_varies_by_dest: false,
            public_addr_v4: None,
            public_addr_v6: None,
            ipv4_works: false,
            ipv6_works: false,
            servers_responded: 0,
            detected_at: 0,
        }
    }
}

/// NAT checker that performs multi-STUN queries
pub struct NatChecker {
    /// STUN servers to query (IPv4)
    stun_servers_v4: Vec<String>,
    /// STUN servers to query (IPv6) - reserved for future use
    #[allow(dead_code)]
    stun_servers_v6: Vec<String>,
    /// Query timeout per server
    query_timeout: Duration,
    /// Number of retries per server
    retries: u32,
}

impl Default for NatChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl NatChecker {
    /// Create a new NAT checker with default STUN servers
    pub fn new() -> Self {
        Self {
            stun_servers_v4: STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            stun_servers_v6: vec![
                // These servers support IPv6
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun.cloudflare.com:3478".to_string(),
            ],
            query_timeout: Duration::from_secs(3),
            retries: 2,
        }
    }

    /// Create with custom STUN servers
    pub fn with_servers(stun_servers_v4: Vec<String>, stun_servers_v6: Vec<String>) -> Self {
        Self {
            stun_servers_v4,
            stun_servers_v6,
            query_timeout: Duration::from_secs(3),
            retries: 2,
        }
    }

    /// Set query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }

    /// Perform NAT type detection
    pub async fn check(&self, socket: &UdpSocket) -> NatReport {
        let start = Instant::now();
        let mut report = NatReport::default();

        // Query multiple STUN servers in parallel
        let results = self.query_multiple_servers(socket).await;

        // Analyze results
        let successful: Vec<_> = results
            .iter()
            .filter(|r| r.success && r.mapped_addr.is_some())
            .collect();

        report.servers_responded = successful.len() as u32;

        if successful.is_empty() {
            warn!("NAT check failed: no STUN servers responded");
            return report;
        }

        // Extract unique mapped addresses
        let mapped_addrs: Vec<SocketAddr> =
            successful.iter().filter_map(|r| r.mapped_addr).collect();

        // Check for IPv4/IPv6 results
        for addr in &mapped_addrs {
            match addr {
                SocketAddr::V4(_) => {
                    report.ipv4_works = true;
                    if report.public_addr_v4.is_none() {
                        report.public_addr_v4 = Some(*addr);
                    }
                }
                SocketAddr::V6(_) => {
                    report.ipv6_works = true;
                    if report.public_addr_v6.is_none() {
                        report.public_addr_v6 = Some(*addr);
                    }
                }
            }
        }

        // Detect Symmetric NAT by comparing addresses
        report.mapping_varies_by_dest = self.detect_symmetric_nat(&mapped_addrs);

        // Classify NAT type
        report.nat_type = if report.mapping_varies_by_dest {
            NatType::Symmetric
        } else if let Some(public_addr) = report.public_addr_v4 {
            // Check if public IP matches local IP (no NAT)
            if self.is_public_ip(public_addr.ip()) {
                NatType::Open
            } else {
                // We can't distinguish between Cone types with STUN alone
                // Default to PortRestrictedCone as most common
                NatType::PortRestrictedCone
            }
        } else {
            NatType::Unknown
        };

        report.detected_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        info!(
            "NAT check completed in {:?}: type={}, public_v4={:?}, public_v6={:?}, symmetric={}",
            start.elapsed(),
            report.nat_type,
            report.public_addr_v4,
            report.public_addr_v6,
            report.mapping_varies_by_dest
        );

        report
    }

    /// Query multiple STUN servers and return results
    async fn query_multiple_servers(&self, socket: &UdpSocket) -> Vec<StunQueryResult> {
        let mut results = Vec::new();

        // Resolve and query servers (limit to first 3 for speed)
        let servers_to_query: Vec<_> = self.stun_servers_v4.iter().take(3).cloned().collect();

        for server_str in servers_to_query {
            match self.resolve_stun_server(&server_str).await {
                Some(server_addr) => {
                    let result = self.query_single_server(socket, server_addr).await;
                    results.push(result);
                }
                None => {
                    debug!("Failed to resolve STUN server: {}", server_str);
                }
            }
        }

        results
    }

    /// Resolve STUN server hostname to SocketAddr
    async fn resolve_stun_server(&self, server: &str) -> Option<SocketAddr> {
        use tokio::net::lookup_host;

        match timeout(Duration::from_secs(2), lookup_host(server)).await {
            Ok(Ok(mut addrs)) => addrs.next(),
            Ok(Err(e)) => {
                debug!("DNS resolution failed for {}: {}", server, e);
                None
            }
            Err(_) => {
                debug!("DNS resolution timeout for {}", server);
                None
            }
        }
    }

    /// Query a single STUN server with retries
    async fn query_single_server(&self, socket: &UdpSocket, server: SocketAddr) -> StunQueryResult {
        for attempt in 0..=self.retries {
            let start = Instant::now();

            match self.send_stun_binding_request(socket, server).await {
                Ok(mapped_addr) => {
                    return StunQueryResult {
                        server,
                        mapped_addr: Some(mapped_addr),
                        rtt: Some(start.elapsed()),
                        success: true,
                    };
                }
                Err(e) => {
                    if attempt < self.retries {
                        debug!(
                            "STUN query to {} failed (attempt {}): {}, retrying...",
                            server,
                            attempt + 1,
                            e
                        );
                    } else {
                        debug!(
                            "STUN query to {} failed after {} attempts: {}",
                            server,
                            self.retries + 1,
                            e
                        );
                    }
                }
            }
        }

        StunQueryResult {
            server,
            mapped_addr: None,
            rtt: None,
            success: false,
        }
    }

    /// Send STUN Binding Request and parse response
    async fn send_stun_binding_request(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
    ) -> Result<SocketAddr, String> {
        // Build STUN Binding Request (RFC 5389)
        let tx_id: [u8; 12] = rand::random();
        let request = build_stun_binding_request(&tx_id);

        // Send request
        socket
            .send_to(&request, server)
            .await
            .map_err(|e| format!("send failed: {}", e))?;

        // Receive response with timeout
        let mut buf = [0u8; 1024];
        let (n, _src) = timeout(self.query_timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| format!("recv failed: {}", e))?;

        // Validate response
        if n < 20 {
            return Err("response too short".to_string());
        }

        // Check message type (Binding Success Response = 0x0101)
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        if msg_type != 0x0101 {
            return Err(format!("unexpected message type: 0x{:04x}", msg_type));
        }

        // Check transaction ID matches
        if buf[8..20] != tx_id {
            return Err("transaction ID mismatch".to_string());
        }

        // Parse XOR-MAPPED-ADDRESS
        parse_xor_mapped_address(&buf[..n])
            .ok_or_else(|| "no XOR-MAPPED-ADDRESS in response".to_string())
    }

    /// Detect Symmetric NAT by comparing mapped addresses from different servers
    fn detect_symmetric_nat(&self, mapped_addrs: &[SocketAddr]) -> bool {
        if mapped_addrs.len() < 2 {
            return false;
        }

        // Group by IP version
        let v4_addrs: Vec<_> = mapped_addrs.iter().filter(|a| a.is_ipv4()).collect();

        // Compare ports - if ports differ for same IP version, it's Symmetric
        if v4_addrs.len() >= 2 {
            let first_port = v4_addrs[0].port();
            for addr in &v4_addrs[1..] {
                if addr.port() != first_port {
                    info!(
                        "Symmetric NAT detected: ports vary ({} vs {})",
                        first_port,
                        addr.port()
                    );
                    return true;
                }
            }

            // Also check if IPs differ (very rare, but possible with multiple NATs)
            let first_ip = v4_addrs[0].ip();
            for addr in &v4_addrs[1..] {
                if addr.ip() != first_ip {
                    info!(
                        "Symmetric NAT detected: IPs vary ({} vs {})",
                        first_ip,
                        addr.ip()
                    );
                    return true;
                }
            }
        }

        false
    }

    /// Check if an IP address is public (not NAT)
    fn is_public_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => !is_private_ipv4(v4),
            IpAddr::V6(v6) => !is_private_ipv6(v6),
        }
    }
}

/// Build a STUN Binding Request message (RFC 5389)
fn build_stun_binding_request(tx_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);

    // Message Type: Binding Request (0x0001)
    msg.extend_from_slice(&0x0001u16.to_be_bytes());

    // Message Length: 0 (no attributes)
    msg.extend_from_slice(&0x0000u16.to_be_bytes());

    // Magic Cookie: 0x2112A442
    msg.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);

    // Transaction ID (12 bytes)
    msg.extend_from_slice(tx_id);

    msg
}

/// Check if IPv4 address is private
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    octets[0] == 10 ||
    // 172.16.0.0/12
    (octets[0] == 172 && (16..=31).contains(&octets[1])) ||
    // 192.168.0.0/16
    (octets[0] == 192 && octets[1] == 168) ||
    // 100.64.0.0/10 (CGNAT / Shared Address Space, RFC 6598)
    (octets[0] == 100 && (64..=127).contains(&octets[1])) ||
    // 127.0.0.0/8 (loopback)
    octets[0] == 127 ||
    // 169.254.0.0/16 (link-local)
    (octets[0] == 169 && octets[1] == 254)
}

/// Check if IPv6 address is private/local
fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    // ::1 (loopback)
    ip.is_loopback() ||
    // fe80::/10 (link-local)
    (ip.segments()[0] & 0xffc0) == 0xfe80 ||
    // fc00::/7 (unique local)
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_display() {
        assert_eq!(format!("{}", NatType::Symmetric), "Symmetric");
        assert_eq!(format!("{}", NatType::Open), "Open");
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_build_stun_request() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = build_stun_binding_request(&tx_id);

        assert_eq!(request.len(), 20);
        assert_eq!(&request[0..2], &[0x00, 0x01]); // Binding Request
        assert_eq!(&request[2..4], &[0x00, 0x00]); // Length = 0
        assert_eq!(&request[4..8], &[0x21, 0x12, 0xA4, 0x42]); // Magic cookie
        assert_eq!(&request[8..20], &tx_id);
    }

    #[test]
    fn test_detect_symmetric_nat() {
        let checker = NatChecker::new();

        // Same address - not symmetric
        let addrs = vec![
            "1.2.3.4:5000".parse().unwrap(),
            "1.2.3.4:5000".parse().unwrap(),
        ];
        assert!(!checker.detect_symmetric_nat(&addrs));

        // Different ports - symmetric
        let addrs = vec![
            "1.2.3.4:5000".parse().unwrap(),
            "1.2.3.4:5001".parse().unwrap(),
        ];
        assert!(checker.detect_symmetric_nat(&addrs));

        // Different IPs - symmetric
        let addrs = vec![
            "1.2.3.4:5000".parse().unwrap(),
            "1.2.3.5:5000".parse().unwrap(),
        ];
        assert!(checker.detect_symmetric_nat(&addrs));
    }
}
