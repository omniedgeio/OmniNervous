use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use log::{info, error};
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::{Tunn, TunnResult};

pub trait WgInterface {
    fn setup_interface(&self, vip: &str, port: u16, private_key: &str) -> Result<(), String>;
    fn set_peer(&self, public_key: &str, endpoint: Option<SocketAddr>, allowed_ips: &[String], persistent_keepalive: Option<u32>) -> Result<(), String>;
}

pub struct CliWgControl {
    interface: String,
}

impl CliWgControl {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }
}

impl WgInterface for CliWgControl {
    fn setup_interface(&self, vip: &str, port: u16, private_key: &str) -> Result<(), String> {
        use std::process::Command;

        // 1. Create interface (ignore if exists)
        let _ = Command::new("ip").args(["link", "add", "dev", &self.interface, "type", "wireguard"]).output();

        // 2. Set private key and port
        let mut cmd = Command::new("wg");
        cmd.args(["set", &self.interface, "listen-port", &port.to_string(), "private-key", "/dev/stdin"]);
        use std::io::Write;
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

    fn set_peer(&self, public_key: &str, endpoint: Option<SocketAddr>, allowed_ips: &[String], persistent_keepalive: Option<u32>) -> Result<(), String> {
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

        info!("Executing: {:?}", cmd);

        match cmd.output() {
            Ok(output) if output.status.success() => {
                info!("Successfully configured peer {}", public_key);
                Ok(())
            }
            Ok(output) => {
                let err = String::from_utf8_lossy(&output.stderr).to_string();
                error!("Failed to configure peer {}: {}", public_key, err);
                Err(err)
            }
            Err(e) => {
                let err = e.to_string();
                error!("Failed to execute wg command: {}", err);
                Err(err)
            }
        }
    }
}

pub struct UserspaceWgControl {
    interface: String,
    device: Option<tun::AsyncDevice>,
    tunnel: Option<Arc<Mutex<Tunn>>>,
    peers: HashMap<[u8; 32], PeerInfo>,
}

struct PeerInfo {
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<String>,
}

impl UserspaceWgControl {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            device: None,
            tunnel: None,
            peers: HashMap::new(),
        }
    }

    pub async fn setup_tunnel(&mut self, private_key: &str, port: u16) -> Result<(), String> {
        // Parse private key
        let secret_key = hex::decode(private_key).map_err(|e| e.to_string())?;
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&secret_key);
        let secret = X25519SecretKey::from(sk);

        // Create tunnel
        let tunnel = Tunn::new(secret, 0, None).map_err(|e| e.to_string())?;
        self.tunnel = Some(Arc::new(Mutex::new(tunnel)));

        // Create TUN device
        let config = tun::Configuration::default()
            .name(&self.interface)
            .address("10.200.0.1") // Will be set later
            .netmask("255.255.255.0")
            .up();
        let device = tun::create_as_async(&config).map_err(|e| e.to_string())?;
        self.device = Some(device);

        Ok(())
    }

    pub async fn run_packet_loop(&self, udp_socket: Arc<UdpSocket>) -> Result<(), String> {
        // Placeholder for packet processing loop
        // This would read from TUN, encrypt with boringtun, send via UDP
        // And read from UDP, decrypt, write to TUN
        Ok(())
    }
}

impl WgInterface for UserspaceWgControl {
    fn setup_interface(&self, vip: &str, port: u16, private_key: &str) -> Result<(), String> {
        // For userspace, setup is async, so this is a no-op
        // Actual setup done in setup_tunnel
        Ok(())
    }

    fn set_peer(&self, public_key: &str, endpoint: Option<SocketAddr>, allowed_ips: &[String], persistent_keepalive: Option<u32>) -> Result<(), String> {
        // Parse public key
        let pk_bytes = hex::decode(public_key).map_err(|e| e.to_string())?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);

        let peer = PeerInfo {
            endpoint,
            allowed_ips: allowed_ips.to_vec(),
        };

        // In real impl, update boringtun tunnel with peer
        // For now, just store
        // self.peers.insert(pk, peer);

        info!("Configured userspace peer {}", public_key);
        Ok(())
    }
}
