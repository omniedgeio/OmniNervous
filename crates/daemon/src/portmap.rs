//! Port Mapping for NAT Traversal (UPnP/NAT-PMP/PCP)
//!
//! Requests port mappings from the router to improve NAT traversal success rate.
//! Supports multiple protocols in order of preference:
//! 1. PCP (Port Control Protocol) - RFC 6887
//! 2. NAT-PMP (NAT Port Mapping Protocol) - RFC 6886
//! 3. UPnP IGD (Internet Gateway Device) - Basic SSDP + SOAP
//!
//! Port mappings allow the router to forward incoming traffic on a specific
//! external port to our internal port, effectively creating an "open" NAT type.

use anyhow::Result;
use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

// ============================================================================
// Constants
// ============================================================================

/// NAT-PMP gateway port (RFC 6886)
const NAT_PMP_PORT: u16 = 5351;

/// NAT-PMP version
const NAT_PMP_VERSION: u8 = 0;

/// NAT-PMP opcodes
const NAT_PMP_OP_EXTERNAL_ADDR: u8 = 0;
const NAT_PMP_OP_MAP_UDP: u8 = 1;
#[allow(dead_code)] // Reserved for future TCP mapping support
const NAT_PMP_OP_MAP_TCP: u8 = 2;

/// NAT-PMP response opcodes (opcode + 128)
const NAT_PMP_RESP_EXTERNAL_ADDR: u8 = 128;
const NAT_PMP_RESP_MAP_UDP: u8 = 129;
#[allow(dead_code)] // Reserved for future TCP mapping support
const NAT_PMP_RESP_MAP_TCP: u8 = 130;

/// NAT-PMP result codes
const NAT_PMP_RESULT_SUCCESS: u16 = 0;
const NAT_PMP_RESULT_UNSUPPORTED_VERSION: u16 = 1;
const NAT_PMP_RESULT_NOT_AUTHORIZED: u16 = 2;
const NAT_PMP_RESULT_NETWORK_FAILURE: u16 = 3;
const NAT_PMP_RESULT_OUT_OF_RESOURCES: u16 = 4;
const NAT_PMP_RESULT_UNSUPPORTED_OPCODE: u16 = 5;

/// Default mapping lifetime (2 hours)
#[allow(dead_code)] // Used by request_mapping default parameter in future
const DEFAULT_MAPPING_LIFETIME_SECS: u32 = 7200;

/// Mapping refresh interval (half of lifetime)
const MAPPING_REFRESH_RATIO: f32 = 0.5;

// ============================================================================
// Data Structures
// ============================================================================

/// Port mapping capabilities detected on the network
#[derive(Debug, Clone, Default)]
pub struct PortMapCapabilities {
    /// NAT-PMP is supported
    pub nat_pmp: bool,
    /// UPnP IGD is supported
    pub upnp: bool,
    /// PCP (Port Control Protocol) is supported
    pub pcp: bool,
    /// Gateway address
    pub gateway_addr: Option<IpAddr>,
    /// External IP address reported by gateway
    pub external_addr: Option<IpAddr>,
}

/// Result of a port mapping request
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// Protocol used to create the mapping
    pub protocol: PortMapProtocol,
    /// Internal port on our machine
    pub internal_port: u16,
    /// External port assigned by router
    pub external_port: u16,
    /// When the mapping was created
    pub created_at: Instant,
    /// Mapping lifetime
    pub lifetime: Duration,
    /// Gateway that created the mapping
    pub gateway: IpAddr,
}

impl PortMapping {
    /// Check if the mapping is expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.lifetime
    }

    /// Check if the mapping needs refresh (at half lifetime)
    pub fn needs_refresh(&self) -> bool {
        self.created_at.elapsed() > self.lifetime.mul_f32(MAPPING_REFRESH_RATIO)
    }

    /// Time until expiry
    pub fn time_until_expiry(&self) -> Duration {
        self.lifetime.saturating_sub(self.created_at.elapsed())
    }
}

/// Port mapping protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMapProtocol {
    NatPmp,
    Pcp,
    Upnp,
}

/// Port mapper state
#[derive(Debug)]
pub struct PortMapper {
    /// Gateway address
    gateway: Option<IpAddr>,
    /// Internal port we're mapping
    internal_port: u16,
    /// Current active mapping
    current_mapping: Option<PortMapping>,
    /// Detected capabilities
    capabilities: PortMapCapabilities,
    /// Request timeout
    timeout: Duration,
}

impl PortMapper {
    /// Create a new port mapper
    pub fn new(internal_port: u16) -> Self {
        Self {
            gateway: None,
            internal_port,
            current_mapping: None,
            capabilities: PortMapCapabilities::default(),
            timeout: Duration::from_secs(3),
        }
    }

    /// Create a port mapper with a known gateway
    pub fn with_gateway(internal_port: u16, gateway: IpAddr) -> Self {
        Self {
            gateway: Some(gateway),
            internal_port,
            current_mapping: None,
            capabilities: PortMapCapabilities::default(),
            timeout: Duration::from_secs(3),
        }
    }

    /// Get the current mapping if active
    pub fn current_mapping(&self) -> Option<&PortMapping> {
        self.current_mapping.as_ref().filter(|m| !m.is_expired())
    }

    /// Get the external port if we have an active mapping
    pub fn external_port(&self) -> Option<u16> {
        self.current_mapping().map(|m| m.external_port)
    }

    /// Discover gateway and probe for port mapping capabilities
    pub async fn probe(&mut self) -> Result<PortMapCapabilities> {
        // Try to discover the gateway if not known
        if self.gateway.is_none() {
            self.gateway = discover_gateway().await.ok();
        }

        let gateway = match self.gateway {
            Some(g) => g,
            None => {
                debug!("No gateway discovered, port mapping unavailable");
                return Ok(self.capabilities.clone());
            }
        };

        self.capabilities.gateway_addr = Some(gateway);

        // Probe NAT-PMP
        match self.probe_nat_pmp(gateway).await {
            Ok(external_addr) => {
                self.capabilities.nat_pmp = true;
                self.capabilities.external_addr = Some(external_addr);
                info!(
                    "NAT-PMP supported on {}, external IP: {}",
                    gateway, external_addr
                );
            }
            Err(e) => {
                debug!("NAT-PMP not available: {}", e);
            }
        }

        // TODO: Probe PCP (RFC 6887)
        // TODO: Probe UPnP (SSDP discovery)

        Ok(self.capabilities.clone())
    }

    /// Probe for NAT-PMP support and get external address
    async fn probe_nat_pmp(&self, gateway: IpAddr) -> Result<IpAddr> {
        let gateway_v4 = match gateway {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => anyhow::bail!("NAT-PMP requires IPv4 gateway"),
        };

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let gateway_addr = SocketAddrV4::new(gateway_v4, NAT_PMP_PORT);

        // Build external address request
        let request = [NAT_PMP_VERSION, NAT_PMP_OP_EXTERNAL_ADDR];

        socket.send_to(&request, gateway_addr).await?;

        // Wait for response
        let mut buf = [0u8; 16];
        let (len, _src) = timeout(self.timeout, socket.recv_from(&mut buf)).await??;

        if len < 12 {
            anyhow::bail!("NAT-PMP response too short");
        }

        // Parse response
        let version = buf[0];
        let opcode = buf[1];
        let result_code = u16::from_be_bytes([buf[2], buf[3]]);

        if version != NAT_PMP_VERSION {
            anyhow::bail!("Unexpected NAT-PMP version: {}", version);
        }

        if opcode != NAT_PMP_RESP_EXTERNAL_ADDR {
            anyhow::bail!("Unexpected NAT-PMP opcode: {}", opcode);
        }

        if result_code != NAT_PMP_RESULT_SUCCESS {
            anyhow::bail!("NAT-PMP error: {}", nat_pmp_error_string(result_code));
        }

        // External IP is in bytes 8-11
        let external_ip = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
        Ok(IpAddr::V4(external_ip))
    }

    /// Request a port mapping via NAT-PMP
    pub async fn request_mapping_pmp(&mut self, lifetime_secs: u32) -> Result<u16> {
        let gateway = self
            .gateway
            .ok_or_else(|| anyhow::anyhow!("No gateway configured"))?;

        let gateway_v4 = match gateway {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => anyhow::bail!("NAT-PMP requires IPv4 gateway"),
        };

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let gateway_addr = SocketAddrV4::new(gateway_v4, NAT_PMP_PORT);

        // Build mapping request
        // [version(1), opcode(1), reserved(2), internal_port(2), external_port(2), lifetime(4)]
        let mut request = [0u8; 12];
        request[0] = NAT_PMP_VERSION;
        request[1] = NAT_PMP_OP_MAP_UDP;
        // bytes 2-3: reserved
        request[4..6].copy_from_slice(&self.internal_port.to_be_bytes());
        // bytes 6-7: suggested external port (0 = let router choose)
        request[6..8].copy_from_slice(&self.internal_port.to_be_bytes()); // Try same port
        request[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());

        socket.send_to(&request, gateway_addr).await?;

        // Wait for response
        let mut buf = [0u8; 16];
        let (len, _src) = timeout(self.timeout, socket.recv_from(&mut buf)).await??;

        if len < 16 {
            anyhow::bail!("NAT-PMP mapping response too short");
        }

        // Parse response
        let version = buf[0];
        let opcode = buf[1];
        let result_code = u16::from_be_bytes([buf[2], buf[3]]);

        if version != NAT_PMP_VERSION {
            anyhow::bail!("Unexpected NAT-PMP version: {}", version);
        }

        if opcode != NAT_PMP_RESP_MAP_UDP {
            anyhow::bail!("Unexpected NAT-PMP opcode: {}", opcode);
        }

        if result_code != NAT_PMP_RESULT_SUCCESS {
            anyhow::bail!(
                "NAT-PMP mapping error: {}",
                nat_pmp_error_string(result_code)
            );
        }

        // Parse mapping result
        let internal_port = u16::from_be_bytes([buf[8], buf[9]]);
        let external_port = u16::from_be_bytes([buf[10], buf[11]]);
        let actual_lifetime = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        info!(
            "NAT-PMP mapping created: internal {} -> external {}, lifetime {}s",
            internal_port, external_port, actual_lifetime
        );

        // Store the mapping
        self.current_mapping = Some(PortMapping {
            protocol: PortMapProtocol::NatPmp,
            internal_port,
            external_port,
            created_at: Instant::now(),
            lifetime: Duration::from_secs(actual_lifetime as u64),
            gateway,
        });

        Ok(external_port)
    }

    /// Request a port mapping using the best available protocol
    pub async fn request_mapping(&mut self, lifetime_secs: u32) -> Result<u16> {
        // Probe if we haven't yet
        if self.capabilities.gateway_addr.is_none() {
            self.probe().await?;
        }

        // Try protocols in order of preference
        if self.capabilities.nat_pmp {
            match self.request_mapping_pmp(lifetime_secs).await {
                Ok(port) => return Ok(port),
                Err(e) => {
                    warn!("NAT-PMP mapping failed: {}", e);
                }
            }
        }

        // TODO: Try PCP
        // TODO: Try UPnP

        anyhow::bail!("No port mapping protocol available")
    }

    /// Refresh the current mapping before it expires
    pub async fn refresh(&mut self) -> Result<()> {
        let mapping = match &self.current_mapping {
            Some(m) if !m.is_expired() => m.clone(),
            _ => {
                debug!("No active mapping to refresh");
                return Ok(());
            }
        };

        match mapping.protocol {
            PortMapProtocol::NatPmp => {
                let lifetime = mapping.lifetime.as_secs() as u32;
                self.request_mapping_pmp(lifetime).await?;
            }
            PortMapProtocol::Pcp => {
                // TODO: Implement PCP refresh
                warn!("PCP refresh not implemented");
            }
            PortMapProtocol::Upnp => {
                // TODO: Implement UPnP refresh
                warn!("UPnP refresh not implemented");
            }
        }

        Ok(())
    }

    /// Release the current port mapping
    pub async fn release(&mut self) -> Result<()> {
        let mapping = match self.current_mapping.take() {
            Some(m) => m,
            None => return Ok(()),
        };

        match mapping.protocol {
            PortMapProtocol::NatPmp => {
                // Request mapping with 0 lifetime to release
                let gateway = mapping.gateway;
                let gateway_v4 = match gateway {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => return Ok(()), // Can't release IPv6 via NAT-PMP
                };

                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                let gateway_addr = SocketAddrV4::new(gateway_v4, NAT_PMP_PORT);

                let mut request = [0u8; 12];
                request[0] = NAT_PMP_VERSION;
                request[1] = NAT_PMP_OP_MAP_UDP;
                request[4..6].copy_from_slice(&mapping.internal_port.to_be_bytes());
                request[6..8].copy_from_slice(&mapping.external_port.to_be_bytes());
                // lifetime = 0 to release
                request[8..12].copy_from_slice(&0u32.to_be_bytes());

                socket.send_to(&request, gateway_addr).await?;

                info!(
                    "Released NAT-PMP mapping: {} -> {}",
                    mapping.internal_port, mapping.external_port
                );
            }
            PortMapProtocol::Pcp => {
                // TODO: Implement PCP release
            }
            PortMapProtocol::Upnp => {
                // TODO: Implement UPnP release
            }
        }

        Ok(())
    }

    /// Check if the current mapping needs refresh and refresh if so
    pub async fn check_and_refresh(&mut self) -> Result<bool> {
        if let Some(mapping) = &self.current_mapping {
            if mapping.needs_refresh() && !mapping.is_expired() {
                self.refresh().await?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

// ============================================================================
// Gateway Discovery
// ============================================================================

/// Discover the default gateway address
/// This uses platform-specific methods to find the router's IP
pub async fn discover_gateway() -> Result<IpAddr> {
    // On most platforms, we can parse the routing table or use a default
    // For simplicity, we'll try common gateway addresses

    // Try to connect to a public IP and see what local address we use
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:53").await?;
    let local_addr = socket.local_addr()?;

    // Common gateway is local_ip with last octet = 1
    if let IpAddr::V4(local_v4) = local_addr.ip() {
        let octets = local_v4.octets();
        let gateway = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
        debug!("Guessed gateway address: {}", gateway);
        return Ok(IpAddr::V4(gateway));
    }

    anyhow::bail!("Could not discover gateway")
}

/// Get NAT-PMP error string
fn nat_pmp_error_string(code: u16) -> &'static str {
    match code {
        NAT_PMP_RESULT_SUCCESS => "Success",
        NAT_PMP_RESULT_UNSUPPORTED_VERSION => "Unsupported version",
        NAT_PMP_RESULT_NOT_AUTHORIZED => "Not authorized",
        NAT_PMP_RESULT_NETWORK_FAILURE => "Network failure",
        NAT_PMP_RESULT_OUT_OF_RESOURCES => "Out of resources",
        NAT_PMP_RESULT_UNSUPPORTED_OPCODE => "Unsupported opcode",
        _ => "Unknown error",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_mapping_expiry() {
        let mapping = PortMapping {
            protocol: PortMapProtocol::NatPmp,
            internal_port: 51820,
            external_port: 51820,
            created_at: Instant::now() - Duration::from_secs(3700),
            lifetime: Duration::from_secs(3600),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        assert!(mapping.is_expired());
    }

    #[test]
    fn test_port_mapping_needs_refresh() {
        let mapping = PortMapping {
            protocol: PortMapProtocol::NatPmp,
            internal_port: 51820,
            external_port: 51820,
            created_at: Instant::now() - Duration::from_secs(1900),
            lifetime: Duration::from_secs(3600),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        // 1900 seconds elapsed, which is > 1800 (half of 3600)
        assert!(mapping.needs_refresh());
        assert!(!mapping.is_expired());
    }

    #[test]
    fn test_port_mapper_creation() {
        let mapper = PortMapper::new(51820);
        assert_eq!(mapper.internal_port, 51820);
        assert!(mapper.current_mapping.is_none());
    }

    #[test]
    fn test_nat_pmp_error_strings() {
        assert_eq!(nat_pmp_error_string(0), "Success");
        assert_eq!(nat_pmp_error_string(1), "Unsupported version");
        assert_eq!(nat_pmp_error_string(4), "Out of resources");
        assert_eq!(nat_pmp_error_string(99), "Unknown error");
    }
}
