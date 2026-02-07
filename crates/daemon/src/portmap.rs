//! Port Mapping for NAT Traversal (UPnP/NAT-PMP/PCP)
//!
//! Requests port mappings from the router to improve NAT traversal success rate.
//! Supports multiple protocols in order of preference:
//! 1. PCP (Port Control Protocol) - RFC 6887
//! 2. NAT-PMP (NAT Port Mapping Protocol) - RFC 6886
//! 3. UPnP IGD (Internet Gateway Device) - SSDP discovery + SOAP control
//!
//! Port mappings allow the router to forward incoming traffic on a specific
//! external port to our internal port, effectively creating an "open" NAT type.

use anyhow::Result;
use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
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
// UPnP Constants
// ============================================================================

/// SSDP multicast address for UPnP discovery
const SSDP_MULTICAST_ADDR: &str = "239.255.255.250:1900";

/// SSDP search target for Internet Gateway Device (WANIPConnection)
const SSDP_ST_WAN_IP: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// Alternative SSDP search target (WANIPConnection v2)
const SSDP_ST_WAN_IP_V2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";

/// Alternative SSDP search target (WANPPPConnection for DSL routers)
const SSDP_ST_WAN_PPP: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

/// SSDP M-SEARCH request template
const SSDP_MSEARCH_TEMPLATE: &str = "M-SEARCH * HTTP/1.1\r\n\
Host: 239.255.255.250:1900\r\n\
Man: \"ssdp:discover\"\r\n\
ST: {}\r\n\
MX: 2\r\n\
\r\n";

/// UPnP SOAP action namespace for WANIPConnection
const UPNP_SERVICE_WAN_IP: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// UPnP SOAP action namespace for WANPPPConnection
const UPNP_SERVICE_WAN_PPP: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

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
    /// UPnP device info (if discovered)
    pub upnp_device: Option<UpnpDevice>,
}

/// UPnP Internet Gateway Device information
#[derive(Debug, Clone)]
pub struct UpnpDevice {
    /// Control URL for SOAP requests
    pub control_url: String,
    /// Service type (WANIPConnection or WANPPPConnection)
    pub service_type: String,
    /// Device location (base URL)
    pub location: String,
    /// Host address
    pub host: SocketAddr,
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

        // Probe UPnP IGD (SSDP discovery)
        match self.probe_upnp().await {
            Ok(device) => {
                // Try to get external IP via UPnP
                if let Ok(external_ip) = upnp_get_external_ip(&device, self.timeout).await {
                    if self.capabilities.external_addr.is_none() {
                        self.capabilities.external_addr = Some(external_ip);
                    }
                    info!("UPnP IGD external IP: {}", external_ip);
                }
                self.capabilities.upnp = true;
                self.capabilities.upnp_device = Some(device);
            }
            Err(e) => {
                debug!("UPnP not available: {}", e);
            }
        }

        // TODO: Probe PCP (RFC 6887)

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

        // Try UPnP
        if self.capabilities.upnp {
            match self.request_mapping_upnp(lifetime_secs).await {
                Ok(port) => return Ok(port),
                Err(e) => {
                    warn!("UPnP mapping failed: {}", e);
                }
            }
        }

        // TODO: Try PCP

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
                // UPnP refresh is the same as creating a new mapping
                let lifetime = mapping.lifetime.as_secs() as u32;
                self.request_mapping_upnp(lifetime).await?;
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
                if let Err(e) = self.release_upnp(&mapping).await {
                    warn!("Failed to release UPnP mapping: {}", e);
                }
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

    // ========================================================================
    // UPnP Methods
    // ========================================================================

    /// Probe for UPnP IGD support via SSDP discovery
    async fn probe_upnp(&mut self) -> Result<UpnpDevice> {
        // Try multiple service types
        let search_targets = [SSDP_ST_WAN_IP, SSDP_ST_WAN_IP_V2, SSDP_ST_WAN_PPP];

        for st in &search_targets {
            match upnp_discover(st, self.timeout).await {
                Ok(device) => {
                    info!("UPnP device discovered: {} at {}", device.service_type, device.host);
                    return Ok(device);
                }
                Err(e) => {
                    debug!("SSDP discovery for {} failed: {}", st, e);
                }
            }
        }

        anyhow::bail!("No UPnP IGD device found")
    }

    /// Request a port mapping via UPnP
    pub async fn request_mapping_upnp(&mut self, lifetime_secs: u32) -> Result<u16> {
        let device = self.capabilities.upnp_device.clone()
            .ok_or_else(|| anyhow::anyhow!("No UPnP device discovered"))?;

        // Get our local IP address
        let local_ip = get_local_ip().await?;

        // Try to map the same port first, then fall back to router-assigned
        let external_port = upnp_add_port_mapping(
            &device,
            self.internal_port,
            self.internal_port, // Try same port
            &local_ip.to_string(),
            lifetime_secs,
            self.timeout,
        ).await?;

        info!(
            "UPnP mapping created: internal {} -> external {}, lifetime {}s",
            self.internal_port, external_port, lifetime_secs
        );

        // Store the mapping
        self.current_mapping = Some(PortMapping {
            protocol: PortMapProtocol::Upnp,
            internal_port: self.internal_port,
            external_port,
            created_at: Instant::now(),
            lifetime: Duration::from_secs(lifetime_secs as u64),
            gateway: device.host.ip(),
        });

        Ok(external_port)
    }

    /// Release a UPnP port mapping
    async fn release_upnp(&self, mapping: &PortMapping) -> Result<()> {
        let device = self.capabilities.upnp_device.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No UPnP device for release"))?;

        upnp_delete_port_mapping(device, mapping.external_port, self.timeout).await?;

        info!(
            "Released UPnP mapping: {} -> {}",
            mapping.internal_port, mapping.external_port
        );

        Ok(())
    }
}

// ============================================================================
// UPnP Implementation
// ============================================================================

/// Discover UPnP IGD devices via SSDP
async fn upnp_discover(search_target: &str, timeout_duration: Duration) -> Result<UpnpDevice> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    // Build M-SEARCH request
    let request = SSDP_MSEARCH_TEMPLATE.replace("{}", search_target);

    // Send to SSDP multicast address
    let multicast_addr: SocketAddr = SSDP_MULTICAST_ADDR.parse()?;
    socket.send_to(request.as_bytes(), multicast_addr).await?;

    // Wait for response
    let mut buf = [0u8; 2048];
    let (len, src) = timeout(timeout_duration, socket.recv_from(&mut buf)).await??;

    let response = String::from_utf8_lossy(&buf[..len]);
    debug!("SSDP response from {}: {}", src, response);

    // Parse LOCATION header from response
    let location = parse_ssdp_header(&response, "LOCATION")
        .ok_or_else(|| anyhow::anyhow!("No LOCATION in SSDP response"))?;

    // Parse ST (Service Type) header
    let service_type = parse_ssdp_header(&response, "ST")
        .unwrap_or_else(|| search_target.to_string());

    // Parse location URL to get host
    let host = parse_url_host(&location)?;

    // Fetch device description to get control URL
    let control_url = upnp_get_control_url(&location, &service_type, timeout_duration).await?;

    Ok(UpnpDevice {
        control_url,
        service_type,
        location,
        host,
    })
}

/// Parse a header value from SSDP response
fn parse_ssdp_header(response: &str, header: &str) -> Option<String> {
    for line in response.lines() {
        let line_upper = line.to_uppercase();
        let header_upper = header.to_uppercase();
        if line_upper.starts_with(&format!("{}:", header_upper)) {
            let value = line[header.len() + 1..].trim();
            return Some(value.to_string());
        }
    }
    None
}

/// Parse host:port from a URL
fn parse_url_host(url: &str) -> Result<SocketAddr> {
    // URL format: http://host:port/path
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    let host_port = url.split('/').next().unwrap_or(url);

    // Parse host:port
    if let Ok(addr) = host_port.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Try adding default port 80
    if !host_port.contains(':') {
        if let Ok(addr) = format!("{}:80", host_port).parse::<SocketAddr>() {
            return Ok(addr);
        }
    }

    anyhow::bail!("Could not parse URL host: {}", url)
}

/// Fetch UPnP device description and extract control URL
async fn upnp_get_control_url(location: &str, service_type: &str, timeout_duration: Duration) -> Result<String> {
    let host = parse_url_host(location)?;
    let path = location.split(&format!("{}", host)).nth(1).unwrap_or("/");

    // Fetch device description XML
    let xml = http_get(&host, path, timeout_duration).await?;

    // Parse control URL from XML (simple string search, not full XML parsing)
    // Look for the serviceType and then the controlURL
    let service_marker = format!("<serviceType>{}</serviceType>", service_type);
    
    // Also check without version number suffix
    let base_service = service_type.trim_end_matches(char::is_numeric).trim_end_matches(':');
    let alt_markers = [
        service_marker.clone(),
        format!("<serviceType>{}1</serviceType>", base_service),
        format!("<serviceType>{}2</serviceType>", base_service),
    ];

    for marker in &alt_markers {
        if let Some(service_idx) = xml.find(marker) {
            // Find controlURL after this service definition
            if let Some(control_start) = xml[service_idx..].find("<controlURL>") {
                let control_section = &xml[service_idx + control_start..];
                if let Some(control_end) = control_section.find("</controlURL>") {
                    let control_url = &control_section[12..control_end];
                    
                    // Make absolute URL if relative
                    let full_url = if control_url.starts_with('/') {
                        control_url.to_string()
                    } else if control_url.starts_with("http") {
                        // Extract path from full URL
                        if let Some(path_start) = control_url.find(&format!("{}", host.ip())) {
                            control_url[path_start..].split('/').skip(1).collect::<Vec<_>>().join("/")
                        } else {
                            control_url.to_string()
                        }
                    } else {
                        format!("/{}", control_url)
                    };

                    debug!("Found UPnP control URL: {}", full_url);
                    return Ok(full_url);
                }
            }
        }
    }

    // Try common default paths
    for default_path in &["/ctl/IPConn", "/upnp/control/WANIPConnection", "/upnp/control/WANIPConn1"] {
        debug!("Trying default control URL: {}", default_path);
        return Ok(default_path.to_string());
    }

    anyhow::bail!("Could not find control URL in device description")
}

/// Add a UPnP port mapping via SOAP
async fn upnp_add_port_mapping(
    device: &UpnpDevice,
    internal_port: u16,
    external_port: u16,
    internal_client: &str,
    lifetime_secs: u32,
    timeout_duration: Duration,
) -> Result<u16> {
    let service_urn = if device.service_type.contains("PPP") {
        UPNP_SERVICE_WAN_PPP
    } else {
        UPNP_SERVICE_WAN_IP
    };

    let soap_body = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="{}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{}</NewExternalPort>
<NewProtocol>UDP</NewProtocol>
<NewInternalPort>{}</NewInternalPort>
<NewInternalClient>{}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>OmniEdge VPN</NewPortMappingDescription>
<NewLeaseDuration>{}</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"#,
        service_urn, external_port, internal_port, internal_client, lifetime_secs
    );

    let soap_action = format!("\"{}#AddPortMapping\"", service_urn);

    let response = http_soap_request(
        &device.host,
        &device.control_url,
        &soap_action,
        &soap_body,
        timeout_duration,
    ).await?;

    // Check for error in response
    if response.contains("<errorCode>") {
        // Extract error code
        if let Some(error_start) = response.find("<errorCode>") {
            if let Some(error_end) = response[error_start..].find("</errorCode>") {
                let error_code = &response[error_start + 11..error_start + error_end];
                anyhow::bail!("UPnP AddPortMapping failed: error code {}", error_code);
            }
        }
        anyhow::bail!("UPnP AddPortMapping failed");
    }

    Ok(external_port)
}

/// Delete a UPnP port mapping via SOAP
async fn upnp_delete_port_mapping(
    device: &UpnpDevice,
    external_port: u16,
    timeout_duration: Duration,
) -> Result<()> {
    let service_urn = if device.service_type.contains("PPP") {
        UPNP_SERVICE_WAN_PPP
    } else {
        UPNP_SERVICE_WAN_IP
    };

    let soap_body = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="{}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{}</NewExternalPort>
<NewProtocol>UDP</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>"#,
        service_urn, external_port
    );

    let soap_action = format!("\"{}#DeletePortMapping\"", service_urn);

    let _ = http_soap_request(
        &device.host,
        &device.control_url,
        &soap_action,
        &soap_body,
        timeout_duration,
    ).await;

    // Ignore errors on delete (mapping might already be gone)
    Ok(())
}

/// Get external IP address via UPnP SOAP
pub async fn upnp_get_external_ip(device: &UpnpDevice, timeout_duration: Duration) -> Result<IpAddr> {
    let service_urn = if device.service_type.contains("PPP") {
        UPNP_SERVICE_WAN_PPP
    } else {
        UPNP_SERVICE_WAN_IP
    };

    let soap_body = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetExternalIPAddress xmlns:u="{}">
</u:GetExternalIPAddress>
</s:Body>
</s:Envelope>"#,
        service_urn
    );

    let soap_action = format!("\"{}#GetExternalIPAddress\"", service_urn);

    let response = http_soap_request(
        &device.host,
        &device.control_url,
        &soap_action,
        &soap_body,
        timeout_duration,
    ).await?;

    // Parse external IP from response
    if let Some(ip_start) = response.find("<NewExternalIPAddress>") {
        if let Some(ip_end) = response[ip_start..].find("</NewExternalIPAddress>") {
            let ip_str = &response[ip_start + 22..ip_start + ip_end];
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                return Ok(IpAddr::V4(ip));
            }
        }
    }

    anyhow::bail!("Could not parse external IP from UPnP response")
}

// ============================================================================
// HTTP Helpers (minimal implementation for UPnP SOAP)
// ============================================================================

/// Simple HTTP GET request
async fn http_get(host: &SocketAddr, path: &str, timeout_duration: Duration) -> Result<String> {
    let mut stream = timeout(timeout_duration, TcpStream::connect(host)).await??;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );

    stream.write_all(request.as_bytes()).await?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();

    // Skip headers
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    // Read body
    reader.read_to_string(&mut response).await?;

    Ok(response)
}

/// HTTP POST request with SOAP headers
async fn http_soap_request(
    host: &SocketAddr,
    path: &str,
    soap_action: &str,
    body: &str,
    timeout_duration: Duration,
) -> Result<String> {
    let mut stream = timeout(timeout_duration, TcpStream::connect(host)).await??;

    let request = format!(
        "POST {} HTTP/1.1\r\n\
Host: {}\r\n\
Content-Type: text/xml; charset=\"utf-8\"\r\n\
Content-Length: {}\r\n\
SOAPAction: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        path,
        host,
        body.len(),
        soap_action,
        body
    );

    stream.write_all(request.as_bytes()).await?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();

    // Skip HTTP status line and headers
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    // Read body
    reader.read_to_string(&mut response).await?;

    Ok(response)
}

/// Get the local IP address
async fn get_local_ip() -> Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:53").await?;
    let local_addr = socket.local_addr()?;
    Ok(local_addr.ip())
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
        // Create a mapping with a very short lifetime that will be expired immediately
        let mapping = PortMapping {
            protocol: PortMapProtocol::NatPmp,
            internal_port: 51820,
            external_port: 51820,
            created_at: Instant::now(),
            lifetime: Duration::from_nanos(1), // Expires almost immediately
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        // Small sleep to ensure we're past the lifetime
        std::thread::sleep(Duration::from_millis(1));
        assert!(mapping.is_expired());

        // Also test a non-expired mapping
        let fresh_mapping = PortMapping {
            protocol: PortMapProtocol::NatPmp,
            internal_port: 51820,
            external_port: 51820,
            created_at: Instant::now(),
            lifetime: Duration::from_secs(3600),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        assert!(!fresh_mapping.is_expired());
    }

    #[test]
    fn test_port_mapping_needs_refresh() {
        // Create a mapping with a short lifetime where half has passed
        let mapping = PortMapping {
            protocol: PortMapProtocol::NatPmp,
            internal_port: 51820,
            external_port: 51820,
            created_at: Instant::now(),
            lifetime: Duration::from_millis(10), // Very short lifetime
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        // Initially should not need refresh (just created)
        assert!(!mapping.needs_refresh());
        assert!(!mapping.is_expired());

        // Wait for more than half the lifetime (>5ms)
        std::thread::sleep(Duration::from_millis(6));
        assert!(mapping.needs_refresh());

        // Wait until fully expired
        std::thread::sleep(Duration::from_millis(10));
        assert!(mapping.is_expired());
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

    #[test]
    fn test_parse_ssdp_header() {
        let response = "HTTP/1.1 200 OK\r\n\
            LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\
            ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\
            USN: uuid:test-device\r\n\r\n";

        let location = parse_ssdp_header(response, "LOCATION");
        assert_eq!(location, Some("http://192.168.1.1:5000/rootDesc.xml".to_string()));

        let st = parse_ssdp_header(response, "ST");
        assert_eq!(st, Some("urn:schemas-upnp-org:service:WANIPConnection:1".to_string()));

        let missing = parse_ssdp_header(response, "NONEXISTENT");
        assert_eq!(missing, None);

        // Test case-insensitivity
        let location_lower = parse_ssdp_header(response, "location");
        assert_eq!(location_lower, Some("http://192.168.1.1:5000/rootDesc.xml".to_string()));
    }

    #[test]
    fn test_parse_url_host() {
        // Standard URL with port
        let host = parse_url_host("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert_eq!(host.ip().to_string(), "192.168.1.1");
        assert_eq!(host.port(), 5000);

        // URL without port (should default to 80)
        let host_no_port = parse_url_host("http://192.168.1.1/rootDesc.xml").unwrap();
        assert_eq!(host_no_port.ip().to_string(), "192.168.1.1");
        assert_eq!(host_no_port.port(), 80);
    }

    #[test]
    fn test_upnp_device_creation() {
        let device = UpnpDevice {
            control_url: "/ctl/IPConn".to_string(),
            service_type: SSDP_ST_WAN_IP.to_string(),
            location: "http://192.168.1.1:5000/rootDesc.xml".to_string(),
            host: "192.168.1.1:5000".parse().unwrap(),
        };

        assert_eq!(device.control_url, "/ctl/IPConn");
        assert!(device.service_type.contains("WANIPConnection"));
    }

    #[test]
    fn test_upnp_mapping_expiry() {
        let mapping = PortMapping {
            protocol: PortMapProtocol::Upnp,
            internal_port: 51820,
            external_port: 51820,
            created_at: Instant::now(),
            lifetime: Duration::from_secs(3600),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        assert!(!mapping.is_expired());
        assert!(!mapping.needs_refresh());
        assert_eq!(mapping.protocol, PortMapProtocol::Upnp);
    }

    #[test]
    fn test_port_map_capabilities_default() {
        let caps = PortMapCapabilities::default();
        assert!(!caps.nat_pmp);
        assert!(!caps.upnp);
        assert!(!caps.pcp);
        assert!(caps.gateway_addr.is_none());
        assert!(caps.external_addr.is_none());
        assert!(caps.upnp_device.is_none());
    }
}
