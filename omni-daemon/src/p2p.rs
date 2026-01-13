use std::net::SocketAddr;
use tokio::net::UdpSocket;
use anyhow::{Result, Context};
use log::{info, warn};

/// Represents the public endpoint discovered via STUN.
#[derive(Debug, Clone)]
pub struct PublicEndpoint {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

/// Simple STUN client for discovering the public-facing address.
pub struct StunClient {
    stun_server: SocketAddr,
}

impl StunClient {
    pub fn new(stun_server: &str) -> Result<Self> {
        let addr: SocketAddr = stun_server.parse()
            .context("Invalid STUN server address")?;
        Ok(Self { stun_server: addr })
    }

    /// Discover our public IP and port via a STUN Binding Request.
    pub async fn discover(&self, local_socket: &UdpSocket) -> Result<PublicEndpoint> {
        // Minimal STUN Binding Request (RFC 5389)
        // Type: 0x0001 (Binding Request), Length: 0, Magic Cookie, Transaction ID
        let mut request = [0u8; 20];
        request[0] = 0x00; // Message Type: Binding Request
        request[1] = 0x01;
        request[2] = 0x00; // Message Length: 0 (no attributes)
        request[3] = 0x00;
        // Magic Cookie
        request[4] = 0x21;
        request[5] = 0x12;
        request[6] = 0xa4;
        request[7] = 0x42;
        // Transaction ID (random 12 bytes, simplified here)
        for i in 8..20 {
            request[i] = rand::random();
        }

        local_socket.send_to(&request, self.stun_server).await?;

        let mut buf = [0u8; 256];
        let (len, _) = local_socket.recv_from(&mut buf).await?;

        // Parse STUN Binding Response (simplified)
        if len < 20 || buf[0] != 0x01 || buf[1] != 0x01 {
            anyhow::bail!("Invalid STUN response");
        }

        // Look for XOR-MAPPED-ADDRESS (0x0020) attribute
        let mut offset = 20;
        while offset + 4 <= len {
            let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            
            if attr_type == 0x0020 && attr_len >= 8 {
                // XOR-MAPPED-ADDRESS: Family, X-Port, X-Address
                let family = buf[offset + 5];
                let x_port = u16::from_be_bytes([buf[offset + 6], buf[offset + 7]]);
                let port = x_port ^ 0x2112; // XOR with magic cookie high bits

                if family == 0x01 {
                    // IPv4
                    let x_ip = [
                        buf[offset + 8] ^ 0x21,
                        buf[offset + 9] ^ 0x12,
                        buf[offset + 10] ^ 0xa4,
                        buf[offset + 11] ^ 0x42,
                    ];
                    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        x_ip[0], x_ip[1], x_ip[2], x_ip[3]
                    ));
                    info!("STUN discovered (IPv4): {}:{}", ip, port);
                    return Ok(PublicEndpoint { ip, port });
                } else if family == 0x02 && attr_len >= 20 {
                    // IPv6: XOR with magic cookie + transaction ID
                    let mut x_ip6 = [0u8; 16];
                    // First 4 bytes XOR with magic cookie
                    x_ip6[0] = buf[offset + 8] ^ 0x21;
                    x_ip6[1] = buf[offset + 9] ^ 0x12;
                    x_ip6[2] = buf[offset + 10] ^ 0xa4;
                    x_ip6[3] = buf[offset + 11] ^ 0x42;
                    // Remaining 12 bytes XOR with transaction ID (from request)
                    for i in 4..16 {
                        x_ip6[i] = buf[offset + 8 + i] ^ request[8 + i - 4];
                    }
                    let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(x_ip6));
                    info!("STUN discovered (IPv6): [{}]:{}", ip, port);
                    return Ok(PublicEndpoint { ip, port });
                }
            }
            offset += 4 + attr_len;
        }

        anyhow::bail!("XOR-MAPPED-ADDRESS not found in STUN response")
    }
}

/// Represents a discovered peer.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub public_key: [u8; 32],
    pub endpoint: SocketAddr,
}

/// Manages peer discovery and NAT traversal.
pub struct P2PDiscovery {
    stun_client: Option<StunClient>,
    pub local_endpoint: Option<PublicEndpoint>,
    pub peers: Vec<DiscoveredPeer>,
}

impl P2PDiscovery {
    pub fn new(stun_server: Option<&str>) -> Result<Self> {
        let stun_client = stun_server
            .map(|s| StunClient::new(s))
            .transpose()?;
        Ok(Self {
            stun_client,
            local_endpoint: None,
            peers: Vec::new(),
        })
    }

    /// Perform STUN discovery to find our public endpoint.
    pub async fn discover_self(&mut self) -> Result<()> {
        if let Some(ref client) = self.stun_client {
            // Use ephemeral socket for STUN to avoid confusion with data packets
            let stun_socket = UdpSocket::bind("0.0.0.0:0").await
                .context("Failed to bind ephemeral STUN socket")?;
            
            self.local_endpoint = Some(client.discover(&stun_socket).await?);
            
            // Socket is dropped here, keeping STUN isolated
        } else {
            warn!("No STUN server configured, skipping self-discovery");
        }
        Ok(())
    }

    /// Add a known peer to the discovery list.
    pub fn add_peer(&mut self, public_key: [u8; 32], endpoint: SocketAddr) {
        self.peers.push(DiscoveredPeer { public_key, endpoint });
        info!("Added peer at {}", endpoint);
    }
}
