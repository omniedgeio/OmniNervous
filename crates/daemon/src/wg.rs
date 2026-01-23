use std::process::Command;
use std::net::SocketAddr;
use log::{info, error};

pub struct WgControl {
    interface: String,
}

impl WgControl {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    /// Initialize the interface (create if needed, set IP, up)
    pub fn setup_interface(&self, vip: &str, port: u16, private_key: &str) -> Result<(), String> {
        // 1. Create interface (ignore if exists)
        let _ = Command::new("ip").args(["link", "add", "dev", &self.interface, "type", "wireguard"]).output();

        // 2. Set private key and port
        let mut cmd = Command::new("wg");
        cmd.args(["set", &self.interface, "listen-port", &port.to_string(), "private-key", "/dev/stdin"]);
        // We pipe the private key to stdin for security
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

    /// Update or add a peer on the WireGuard interface
    pub fn set_peer(
        &self,
        public_key: &str,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[String],
        persistent_keepalive: Option<u32>,
    ) -> Result<(), String> {
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
