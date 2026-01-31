//! Dual-Stack Socket Management for IPv4/IPv6
//!
//! Provides a unified interface for managing both IPv4 and IPv6 UDP sockets,
//! enabling seamless dual-stack networking for NAT traversal.
//!
//! ## Design
//! - Maintains separate pconn4 (IPv4) and pconn6 (IPv6) sockets
//! - Automatically routes packets to the appropriate socket based on address family
//! - Supports receiving from both sockets concurrently
//! - Handles systems where IPv6 may not be available

use anyhow::{Context, Result};
use log::{info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Represents either an IPv4 or IPv6 socket address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DualStackAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

impl From<SocketAddr> for DualStackAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => DualStackAddr::V4(v4),
            SocketAddr::V6(v6) => DualStackAddr::V6(v6),
        }
    }
}

impl From<DualStackAddr> for SocketAddr {
    fn from(addr: DualStackAddr) -> Self {
        match addr {
            DualStackAddr::V4(v4) => SocketAddr::V4(v4),
            DualStackAddr::V6(v6) => SocketAddr::V6(v6),
        }
    }
}

impl DualStackAddr {
    pub fn is_ipv4(&self) -> bool {
        matches!(self, DualStackAddr::V4(_))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, DualStackAddr::V6(_))
    }

    pub fn ip(&self) -> IpAddr {
        match self {
            DualStackAddr::V4(v4) => IpAddr::V4(*v4.ip()),
            DualStackAddr::V6(v6) => IpAddr::V6(*v6.ip()),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            DualStackAddr::V4(v4) => v4.port(),
            DualStackAddr::V6(v6) => v6.port(),
        }
    }
}

/// Result of a receive operation, indicating which socket received the data
#[derive(Debug)]
pub struct RecvResult {
    pub len: usize,
    pub addr: SocketAddr,
    pub is_ipv6: bool,
}

/// Dual-stack UDP socket manager
///
/// Manages both IPv4 and IPv6 sockets for seamless dual-stack networking.
/// Falls back to IPv4-only if IPv6 is not available on the system.
pub struct DualStackSocket {
    /// IPv4 socket (always present)
    pconn4: Arc<UdpSocket>,
    /// IPv6 socket (optional, may not be available)
    pconn6: Option<Arc<UdpSocket>>,
    /// Local IPv4 address
    local_addr4: SocketAddr,
    /// Local IPv6 address (if available)
    local_addr6: Option<SocketAddr>,
}

impl DualStackSocket {
    /// Create a new dual-stack socket bound to the specified port
    ///
    /// Attempts to bind both IPv4 and IPv6 sockets. If IPv6 fails,
    /// falls back to IPv4-only mode.
    pub async fn bind(port: u16) -> Result<Self> {
        // Bind IPv4 socket
        let addr4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let pconn4 = UdpSocket::bind(addr4)
            .await
            .context("Failed to bind IPv4 socket")?;
        let local_addr4 = pconn4.local_addr()?;
        let actual_port = local_addr4.port();

        info!("Bound IPv4 socket on {}", local_addr4);

        // Try to bind IPv6 socket on the same port
        let (pconn6, local_addr6) = match Self::try_bind_ipv6(actual_port).await {
            Ok((socket, addr)) => {
                info!("Bound IPv6 socket on {}", addr);
                (Some(Arc::new(socket)), Some(addr))
            }
            Err(e) => {
                warn!("IPv6 not available: {}. Running in IPv4-only mode.", e);
                (None, None)
            }
        };

        Ok(Self {
            pconn4: Arc::new(pconn4),
            pconn6,
            local_addr4,
            local_addr6,
        })
    }

    /// Try to bind an IPv6 socket
    async fn try_bind_ipv6(port: u16) -> Result<(UdpSocket, SocketAddr)> {
        let addr6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        let socket = UdpSocket::bind(addr6)
            .await
            .context("Failed to bind IPv6 socket")?;
        let local_addr = socket.local_addr()?;
        Ok((socket, local_addr))
    }

    /// Check if IPv6 is available
    pub fn has_ipv6(&self) -> bool {
        self.pconn6.is_some()
    }

    /// Get the local IPv4 address
    pub fn local_addr4(&self) -> SocketAddr {
        self.local_addr4
    }

    /// Get the local IPv6 address (if available)
    pub fn local_addr6(&self) -> Option<SocketAddr> {
        self.local_addr6
    }

    /// Get the bound port (same for both IPv4 and IPv6)
    pub fn port(&self) -> u16 {
        self.local_addr4.port()
    }

    /// Get a reference to the IPv4 socket
    pub fn socket4(&self) -> &Arc<UdpSocket> {
        &self.pconn4
    }

    /// Get a reference to the IPv6 socket (if available)
    pub fn socket6(&self) -> Option<&Arc<UdpSocket>> {
        self.pconn6.as_ref()
    }

    /// Send data to the specified address, automatically selecting the right socket
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        match addr {
            SocketAddr::V4(_) => self
                .pconn4
                .send_to(buf, addr)
                .await
                .context("Failed to send via IPv4"),
            SocketAddr::V6(_) => {
                if let Some(ref pconn6) = self.pconn6 {
                    pconn6
                        .send_to(buf, addr)
                        .await
                        .context("Failed to send via IPv6")
                } else {
                    anyhow::bail!("IPv6 not available, cannot send to {}", addr)
                }
            }
        }
    }

    /// Receive from the IPv4 socket
    pub async fn recv_from4(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.pconn4
            .recv_from(buf)
            .await
            .context("Failed to receive from IPv4 socket")
    }

    /// Receive from the IPv6 socket (if available)
    pub async fn recv_from6(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        if let Some(ref pconn6) = self.pconn6 {
            pconn6
                .recv_from(buf)
                .await
                .context("Failed to receive from IPv6 socket")
        } else {
            anyhow::bail!("IPv6 not available")
        }
    }

    /// Receive from either socket, returning which one received
    ///
    /// Uses tokio::select! to wait on both sockets concurrently
    pub async fn recv_from_any(&self, buf4: &mut [u8], buf6: &mut [u8]) -> Result<RecvResult> {
        if let Some(ref pconn6) = self.pconn6 {
            tokio::select! {
                result4 = self.pconn4.recv_from(buf4) => {
                    let (len, addr) = result4.context("Failed to receive from IPv4")?;
                    Ok(RecvResult { len, addr, is_ipv6: false })
                }
                result6 = pconn6.recv_from(buf6) => {
                    let (len, addr) = result6.context("Failed to receive from IPv6")?;
                    Ok(RecvResult { len, addr, is_ipv6: true })
                }
            }
        } else {
            // IPv6 not available, only receive from IPv4
            let (len, addr) = self.pconn4.recv_from(buf4).await?;
            Ok(RecvResult {
                len,
                addr,
                is_ipv6: false,
            })
        }
    }
}

/// Check if an IPv6 address is a 6to4 address (2002::/16)
pub fn is_6to4(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0x20 && octets[1] == 0x02
}

/// Check if an IPv6 address is a Teredo address (2001:0000::/32)
pub fn is_teredo(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && octets[3] == 0x00
}

/// Check if an IPv6 address is a native (non-tunneled) global unicast address
pub fn is_native_ipv6(addr: &Ipv6Addr) -> bool {
    // Global unicast, not 6to4 or Teredo
    !addr.is_loopback()
        && !addr.is_multicast()
        && !is_6to4(addr)
        && !is_teredo(addr)
        && !addr.is_unspecified()
        && !is_link_local_ipv6(addr)
}

/// Check if an IPv6 address is link-local (fe80::/10)
pub fn is_link_local_ipv6(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

/// Check if an IPv6 address is a unique local address (fc00::/7)
pub fn is_unique_local_ipv6(addr: &Ipv6Addr) -> bool {
    let octets = addr.octets();
    (octets[0] & 0xfe) == 0xfc
}

/// Map an IPv4 address to IPv6 (::ffff:IPv4)
pub fn map_ipv4_to_ipv6(addr: Ipv4Addr) -> Ipv6Addr {
    addr.to_ipv6_mapped()
}

/// Extract IPv4 from an IPv4-mapped IPv6 address, if applicable
pub fn unmap_ipv6_to_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    addr.to_ipv4_mapped()
}

/// Get the address family preference for a given address
/// Returns a score where lower is better:
/// - Native IPv6: 0 (preferred)
/// - IPv4: 1
/// - 6to4/Teredo: 2 (avoid if possible)
pub fn address_preference(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V6(v6) => {
            if is_native_ipv6(v6) {
                0 // Best: native IPv6
            } else {
                2 // Worst: tunneled IPv6
            }
        }
        IpAddr::V4(_) => 1, // Middle: IPv4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_stack_addr_conversion() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let dual = DualStackAddr::from(v4);
        assert!(dual.is_ipv4());
        assert!(!dual.is_ipv6());
        assert_eq!(dual.port(), 8080);
        assert_eq!(SocketAddr::from(dual), v4);

        let v6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9090,
        );
        let dual = DualStackAddr::from(v6);
        assert!(!dual.is_ipv4());
        assert!(dual.is_ipv6());
        assert_eq!(dual.port(), 9090);
    }

    #[test]
    fn test_is_6to4() {
        let addr = Ipv6Addr::new(0x2002, 0xc0a8, 0x0101, 0, 0, 0, 0, 1);
        assert!(is_6to4(&addr));

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!is_6to4(&addr));
    }

    #[test]
    fn test_is_teredo() {
        let addr = Ipv6Addr::new(0x2001, 0x0000, 0x4136, 0xe378, 0x8000, 0, 0, 1);
        assert!(is_teredo(&addr));

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!is_teredo(&addr));
    }

    #[test]
    fn test_is_link_local() {
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_link_local_ipv6(&addr));

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!is_link_local_ipv6(&addr));
    }

    #[test]
    fn test_is_unique_local() {
        let addr = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_unique_local_ipv6(&addr));

        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_unique_local_ipv6(&addr));

        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(!is_unique_local_ipv6(&addr));
    }

    #[test]
    fn test_ipv4_ipv6_mapping() {
        let v4 = Ipv4Addr::new(192, 168, 1, 1);
        let v6 = map_ipv4_to_ipv6(v4);

        // Should be ::ffff:192.168.1.1
        assert!(v6.to_ipv4_mapped().is_some());

        let back = unmap_ipv6_to_ipv4(v6);
        assert_eq!(back, Some(v4));
    }

    #[test]
    fn test_address_preference() {
        // Native IPv6 should be preferred
        let native_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(address_preference(&native_v6), 0);

        // IPv4 is middle preference
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(address_preference(&v4), 1);

        // 6to4 is least preferred
        let sixtofour = IpAddr::V6(Ipv6Addr::new(0x2002, 0xc0a8, 0x0101, 0, 0, 0, 0, 1));
        assert_eq!(address_preference(&sixtofour), 2);
    }

    #[test]
    fn test_is_native_ipv6() {
        // Global unicast (documentation range)
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(is_native_ipv6(&addr));

        // 6to4 - not native
        let addr = Ipv6Addr::new(0x2002, 0xc0a8, 0, 0, 0, 0, 0, 1);
        assert!(!is_native_ipv6(&addr));

        // Teredo - not native
        let addr = Ipv6Addr::new(0x2001, 0x0000, 0, 0, 0, 0, 0, 1);
        assert!(!is_native_ipv6(&addr));

        // Link-local - not native
        let addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(!is_native_ipv6(&addr));
    }
}
