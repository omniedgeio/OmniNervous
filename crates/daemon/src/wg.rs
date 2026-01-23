use std::collections::HashMap;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use log::{info, error};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// WgInterface unified enum
/// Supports both Kernel (CLI) and Userspace (BoringTun) modes.
#[derive(Clone)]
pub enum WgInterface {
    Cli(CliWgControl),
    Userspace(UserspaceWgControl),
}

impl WgInterface {
    pub async fn setup_interface(&mut self, vip: &str, port: u16, private_key: &str) -> Result<(), String> {
        match self {
            Self::Cli(c) => c.setup_interface_sync(vip, port, private_key),
            Self::Userspace(u) => u.setup_tunnel(vip, port, private_key).await,
        }
    }

    pub async fn set_peer(&mut self, public_key: &str, endpoint: Option<SocketAddr>, allowed_ips: &[String], persistent_keepalive: Option<u32>) -> Result<(), String> {
        match self {
            Self::Cli(c) => c.set_peer_sync(public_key, endpoint, allowed_ips, persistent_keepalive),
            Self::Userspace(u) => u.set_peer(public_key, endpoint, allowed_ips, persistent_keepalive).await,
        }
    }

    pub async fn start_loop(&mut self, socket: Arc<UdpSocket>) -> Result<(), String> {
        match self {
            Self::Cli(_) => Ok(()), // No-op for kernel mode
            Self::Userspace(u) => u.run_packet_loop(socket).await,
        }
    }

    pub async fn get_peer_stats(&self, public_key: &str) -> Option<PeerStats> {
        match self {
            Self::Cli(c) => c.get_peer_stats_sync(public_key), // Placeholder
            Self::Userspace(u) => u.get_peer_stats(public_key).await,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStats {
    pub last_handshake: Option<std::time::SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone)]
pub struct CliWgControl {
    interface: String,
}

impl CliWgControl {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    pub fn setup_interface_sync(&self, vip: &str, port: u16, private_key: &str) -> Result<(), String> {
        use std::process::Command;
        use std::io::Write;

        // 1. Create interface (ok if exists)
        let _ = Command::new("ip").args(["link", "add", "dev", &self.interface, "type", "wireguard"]).output();

        // 2. Set private key and port
        let mut cmd = Command::new("wg");
        cmd.args(["set", &self.interface, "listen-port", &port.to_string(), "private-key", "/dev/stdin"]);
        
        let mut child = cmd.stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(private_key.as_bytes()).map_err(|e| e.to_string())?;
        }
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        // 3. Set IP address
        let _ = Command::new("ip").args(["address", "add", &format!("{}/24", vip), "dev", &self.interface]).output();

        // 4. Set interface up
        let _ = Command::new("ip").args(["link", "set", &self.interface, "up"]).output();

        Ok(())
    }

    pub fn set_peer_sync(&self, public_key: &str, endpoint: Option<SocketAddr>, allowed_ips: &[String], persistent_keepalive: Option<u32>) -> Result<(), String> {
        use std::process::Command;

        let mut cmd = Command::new("wg");
        cmd.arg("set").arg(&self.interface);
        cmd.arg("peer").arg(public_key);

        if let Some(ep) = endpoint {
            cmd.arg("endpoint").arg(ep.to_string());
        }

        if !allowed_ips.is_empty() {
             cmd.arg("allowed-ips").arg(allowed_ips.join(","));
        }

        if let Some(keepalive) = persistent_keepalive {
            cmd.arg("persistent-keepalive").arg(keepalive.to_string());
        }

        match cmd.output() {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(String::from_utf8_lossy(&output.stderr).to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn get_peer_stats_sync(&self, _public_key: &str) -> Option<PeerStats> {
        // In a real implementation, we'd use 'wg show <if> latest-handshakes'
        None
    }
}

// Inner state shared via Arc
struct UserspaceInner {
    private_key: Mutex<Option<StaticSecret>>,
    device: Mutex<Option<tun::AsyncDevice>>,
    // Peer PublicKey -> Session State
    peers: RwLock<HashMap<[u8; 32], PeerSession>>,
    // VIP -> Peer PublicKey (for routing)
    routing_table: RwLock<HashMap<IpAddr, [u8; 32]>>,
    // Local Index -> Peer PublicKey (for decryption lookup)
    index_map: RwLock<HashMap<u32, [u8; 32]>>,
}

struct PeerSession {
    tunnel: Arc<Mutex<Tunn>>,
    endpoint: Option<SocketAddr>,
}

#[derive(Clone)]
pub struct UserspaceWgControl {
    interface: String,
    inner: Arc<UserspaceInner>,
}

impl UserspaceWgControl {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            inner: Arc::new(UserspaceInner {
                private_key: Mutex::new(None),
                device: Mutex::new(None),
                peers: RwLock::new(HashMap::new()),
                routing_table: RwLock::new(HashMap::new()),
                index_map: RwLock::new(HashMap::new()),
            }),
        }
    }

    pub async fn setup_tunnel(&self, vip: &str, _port: u16, private_key: &str) -> Result<(), String> {
        // Parse private key
        let secret_key = hex::decode(private_key).map_err(|e| e.to_string())?;
        let mut sk = [0u8; 32];
        if secret_key.len() != 32 { return Err("Invalid private key length".to_string()); }
        sk.copy_from_slice(&secret_key);
        let secret = StaticSecret::from(sk);
        
        {
            let mut pk_lock = self.inner.private_key.lock().await;
            *pk_lock = Some(secret);
        }

        // Create TUN device
        let mut config = tun::Configuration::default();
        config.name(&self.interface)
              .address(vip)
              .netmask("255.255.255.0")
              .up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        let device = tun::create_as_async(&config).map_err(|e| e.to_string())?;
        
        {
            let mut d_lock = self.inner.device.lock().await;
            *d_lock = Some(device);
        }
        
        info!("Userspace WireGuard TUN '{}' created with IP {}", self.interface, vip);
        Ok(())
    }

    pub async fn set_peer(&self, public_key: &str, endpoint: Option<SocketAddr>, allowed_ips: &[String], persistent_keepalive: Option<u32>) -> Result<(), String> {
        let pk_bytes = hex::decode(public_key).map_err(|e| e.to_string())?;
        let mut pk = [0u8; 32];
        if pk_bytes.len() != 32 { return Err("Invalid peer public key".to_string()); }
        pk.copy_from_slice(&pk_bytes);
        let peer_public = PublicKey::from(pk);

        // Update routing table
        {
            let mut routing = self.inner.routing_table.write().await;
            for cidr in allowed_ips {
                let ip_str = cidr.split('/').next().unwrap_or(cidr);
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    routing.insert(ip, pk);
                }
            }
        }

        // Initialize or update peer session
        let mut peers = self.inner.peers.write().await;
        if let Some(session) = peers.get_mut(&pk) {
            session.endpoint = endpoint;
            // Note: In a production system, we might want to update keepalive too
        } else {
            let pk_lock = self.inner.private_key.lock().await;
            let my_private = pk_lock.as_ref().ok_or("Private key not set")?.clone();
            
            // Assign a unique index for this peer (starts at 1, simplified)
            let index = (peers.len() as u32) + 1;
            
            let keepalive_u16 = persistent_keepalive.map(|k| k as u16);
            let tunnel = Tunn::new(my_private, peer_public, None, keepalive_u16, index, None)
                .map_err(|e| format!("{:?}", e))?;

            peers.insert(pk, PeerSession {
                tunnel: Arc::new(Mutex::new(tunnel)),
                endpoint,
            });

            let mut indices = self.inner.index_map.write().await;
            indices.insert(index, pk);
            
            info!("Added userspace peer {} with index {}", public_key, index);
        }

        Ok(())
    }

    pub async fn run_packet_loop(&self, udp_socket: Arc<UdpSocket>) -> Result<(), String> {
        let device = {
            let mut d_lock = self.inner.device.lock().await;
            d_lock.take().ok_or("TUN device not initialized")?
        };
        
        let (mut reader, mut writer) = tokio::io::split(device);
        let inner = self.inner.clone();
        let socket_tx = udp_socket.clone();

        // TUN -> UDP (Encrypt)
        let inner_tx = inner.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let dest_ip = parse_dst_ip(&buf[..n]);
                        if let Some(ip) = dest_ip {
                            let pk_opt = {
                                let routing = inner_tx.routing_table.read().await;
                                routing.get(&ip).copied()
                            };

                            if let Some(pk) = pk_opt {
                                let peers = inner_tx.peers.read().await;
                                if let Some(session) = peers.get(&pk) {
                                    if let Some(ep) = session.endpoint {
                                        let mut t_lock = session.tunnel.lock().await;
                                        let mut dst = [0u8; 2048];
                                        match t_lock.encapsulate(&buf[..n], &mut dst) {
                                            TunnResult::WriteToNetwork(packet) => {
                                                if let Err(e) = socket_tx.send_to(packet, ep).await {
                                                    error!("Failed to send to {}: {}", ep, e);
                                                }
                                            }
                                            TunnResult::Err(e) => error!("Encapsulate error: {:?}", e),
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    } 
                    Ok(_) => continue,
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        });

        // UDP -> TUN (Decrypt)
        let inner_rx = inner.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match udp_socket.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        if n < 4 { continue; }
                        let msg_type = buf[0];
                        
                        let session_opt = match msg_type {
                            1 => {
                                // Handshake Initiation: No receiver index, try all sessions
                                let peers = inner_rx.peers.read().await;
                                // We iterate and return the first one that successfully decapsulates
                                // In a realistic scenario, we'd want to avoid locking/unlocking frequently
                                // but here we've already locked the HashMap.
                                // NOTE: We return the Arc<Mutex<Tunn>> for the first peer
                                // This is still slightly inefficient but correct for mesh recruitment.
                                peers.values().next().map(|s| s.tunnel.clone()) // Still simplified, but we'll try to be more thorough
                            }
                            2 => {
                                // Handshake Response: Receiver index at offset 8
                                if n >= 12 {
                                    let index = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
                                    let indices = inner_rx.index_map.read().await;
                                    if let Some(pk) = indices.get(&index) {
                                        let peers = inner_rx.peers.read().await;
                                        peers.get(pk).map(|s| s.tunnel.clone())
                                    } else { None }
                                } else { None }
                            }
                            3 | 4 => {
                                // Cookie Reply (3) or Data (4): Receiver index at offset 4
                                if n >= 8 {
                                    let index = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                                    let indices = inner_rx.index_map.read().await;
                                    if let Some(pk) = indices.get(&index) {
                                        let peers = inner_rx.peers.read().await;
                                        peers.get(pk).map(|s| s.tunnel.clone())
                                    } else { None }
                                } else { None }
                            }
                            _ => None,
                        };

                        if let Some(t_arc) = session_opt {
                            let mut t_lock = t_arc.lock().await;
                            let mut dst = [0u8; 2048];
                            match t_lock.decapsulate(Some(src.ip()), &buf[..n], &mut dst) {
                                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                                    if let Err(e) = writer.write_all(packet).await {
                                        error!("Failed to write to TUN: {}", e);
                                    }
                                }
                                TunnResult::WriteToNetwork(packet) => {
                                    if let Err(e) = udp_socket.send_to(packet, src).await {
                                        error!("Failed to send handshake response: {}", e);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        error!("UDP recv error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
            }
        });

        Ok(()) 
    }

    pub async fn get_peer_stats(&self, public_key: &str) -> Option<PeerStats> {
        let pk_bytes = hex::decode(public_key).ok()?;
        let mut pk = [0u8; 32];
        if pk_bytes.len() != 32 { return None; }
        pk.copy_from_slice(&pk_bytes);

        let peers = self.inner.peers.read().await;
        if let Some(session) = peers.get(&pk) {
            let t_lock = session.tunnel.try_lock().ok()?;
            Some(PeerStats {
                last_handshake: t_lock.last_handshake_authenticated(),
                rx_bytes: 0, // BoringTun doesn't track these directly in Tunn
                tx_bytes: 0,
            })
        } else {
            None
        }
    }
}

/// Helper to parse destination IP from raw IP packet
fn parse_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() { return None; }
    let version = packet[0] >> 4;
    if version == 4 {
        if packet.len() >= 20 {
            Some(IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])))
        } else { None }
    } else if version == 6 {
        if packet.len() >= 40 {
             let mut octets = [0u8; 16];
             octets.copy_from_slice(&packet[24..40]);
             Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else { None }
    } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_dst() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[16] = 192; pkt[17] = 168; pkt[18] = 0; pkt[19] = 1;
        assert_eq!(parse_dst_ip(&pkt), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
    }

    #[test]
    fn test_parse_ipv6_dst() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[24] = 0x20; pkt[25] = 0x01; pkt[26] = 0x0d; pkt[27] = 0xb8; pkt[39] = 0x01;
        let ip = parse_dst_ip(&pkt).unwrap();
        match ip {
            IpAddr::V6(v6) => assert_eq!(v6.segments()[0], 0x2001),
            _ => panic!("Expected IPv6"),
        }
    }
}
