use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
#[cfg(target_os = "windows")]
use log::warn;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

/// WgInterface unified enum
/// Supports both Kernel (CLI) and Userspace (BoringTun) modes.
#[derive(Clone)]
pub enum WgInterface {
    Cli(CliWgControl),
    Userspace(UserspaceWgControl),
}

impl WgInterface {
    pub async fn setup_interface(
        &mut self,
        vip: &str,
        port: u16,
        private_key: &str,
    ) -> Result<(), String> {
        match self {
            Self::Cli(c) => c.setup_interface_sync(vip, port, private_key),
            Self::Userspace(u) => u.setup_tunnel(vip, port, private_key).await,
        }
    }

    pub async fn set_peer(
        &mut self,
        public_key: &str,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[String],
        persistent_keepalive: Option<u32>,
    ) -> Result<(), String> {
        match self {
            Self::Cli(c) => {
                c.set_peer_sync(public_key, endpoint, allowed_ips, persistent_keepalive)
            }
            Self::Userspace(u) => {
                u.set_peer(public_key, endpoint, allowed_ips, persistent_keepalive)
                    .await
            }
        }
    }

    pub async fn start_loop(&mut self, socket: Arc<UdpSocket>) -> Result<(), String> {
        match self {
            Self::Cli(_) => Ok(()), // No-op for kernel mode
            Self::Userspace(u) => u.start_tun_loop(socket).await,
        }
    }

    pub async fn handle_incoming_packet(
        &mut self,
        buf: &[u8],
        src: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<(), String> {
        match self {
            Self::Cli(_) => Ok(()), // Kernel handles this automatically
            Self::Userspace(u) => u.handle_udp_packet(buf, src, socket).await,
        }
    }

    pub async fn get_peer_stats(&self, public_key: &str) -> Option<PeerStats> {
        match self {
            Self::Cli(c) => c.get_peer_stats_sync(public_key), // Placeholder
            Self::Userspace(u) => u.get_peer_stats(public_key).await,
        }
    }

    /// Shutdown the WireGuard interface and release the TUN device
    pub async fn shutdown(&self) {
        match self {
            Self::Cli(c) => c.shutdown_sync(),
            Self::Userspace(u) => u.shutdown().await,
        }
    }

    /// Soft shutdown - clears peers and routing but keeps TUN device alive.
    /// Use this on Windows to prevent adapter accumulation on disconnect/reconnect.
    pub async fn soft_shutdown(&self) {
        match self {
            Self::Cli(_) => {
                // For CLI mode, we can't soft shutdown - do nothing
            }
            Self::Userspace(u) => u.soft_shutdown().await,
        }
    }

    /// Check if the TUN loop is active (device is in use by reader/writer tasks)
    pub async fn is_tun_active(&self) -> bool {
        match self {
            Self::Cli(_) => true, // CLI mode is always "active" when created
            Self::Userspace(u) => u.is_tun_active().await,
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

    pub fn setup_interface_sync(
        &self,
        vip: &str,
        port: u16,
        private_key: &str,
    ) -> Result<(), String> {
        use std::io::Write;
        use std::process::Command;

        // 1. Create interface (ok if exists)
        let _ = Command::new("ip")
            .args(["link", "add", "dev", &self.interface, "type", "wireguard"])
            .output();

        // 2. Set private key and port
        let mut cmd = Command::new("wg");
        cmd.args([
            "set",
            &self.interface,
            "listen-port",
            &port.to_string(),
            "private-key",
            "/dev/stdin",
        ]);

        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(private_key.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        // 3. Set IP address
        let _ = Command::new("ip")
            .args([
                "address",
                "add",
                &format!("{}/24", vip),
                "dev",
                &self.interface,
            ])
            .output();

        // 4. Set interface up
        let _ = Command::new("ip")
            .args(["link", "set", &self.interface, "up"])
            .output();

        Ok(())
    }

    pub fn set_peer_sync(
        &self,
        public_key: &str,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[String],
        persistent_keepalive: Option<u32>,
    ) -> Result<(), String> {
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

    /// Shutdown the CLI WireGuard interface
    pub fn shutdown_sync(&self) {
        use std::process::Command;
        info!("[WG] Shutting down CLI interface: {}", self.interface);

        // Bring interface down
        let _ = Command::new("ip")
            .args(["link", "set", &self.interface, "down"])
            .output();

        // Delete the interface
        let _ = Command::new("ip")
            .args(["link", "delete", &self.interface])
            .output();

        info!("[WG] CLI interface {} shutdown complete", self.interface);
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
    // Channel to TUN writer
    tun_writer: RwLock<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
    // Task handles for TUN reader/writer - needed for cleanup
    tun_task_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

#[allow(dead_code)]  // public_key is kept for future optimizations
struct PeerSession {
    tunnel: Arc<Mutex<Tunn>>,
    endpoint: Option<SocketAddr>,
    public_key: [u8; 32],  // Store public key for reverse lookup
}

#[derive(Clone)]
pub struct UserspaceWgControl {
    interface: String,
    inner: Arc<UserspaceInner>,
}

impl UserspaceWgControl {
    pub fn new(interface: &str) -> Self {
        info!(
            "[WG] UserspaceWgControl::new() called with interface: '{}'",
            interface
        );
        Self {
            interface: interface.to_string(),
            inner: Arc::new(UserspaceInner {
                private_key: Mutex::new(None),
                device: Mutex::new(None),
                peers: RwLock::new(HashMap::new()),
                routing_table: RwLock::new(HashMap::new()),
                index_map: RwLock::new(HashMap::new()),
                tun_writer: RwLock::new(None),
                tun_task_handles: Mutex::new(Vec::new()),
            }),
        }
    }

    pub async fn setup_tunnel(
        &self,
        vip: &str,
        _port: u16,
        private_key: &str,
    ) -> Result<(), String> {
        info!(
            "[WG] Setting up tunnel with interface '{}', VIP {}",
            self.interface, vip
        );
        // Parse private key
        let secret_key = hex::decode(private_key).map_err(|e| {
            error!("[WG] Failed to decode private key hex: {}", e);
            e.to_string()
        })?;
        let mut sk = [0u8; 32];
        if secret_key.len() != 32 {
            error!("[WG] Invalid private key length: {}", secret_key.len());
            return Err("Invalid private key length".to_string());
        }
        sk.copy_from_slice(&secret_key);
        let secret = StaticSecret::from(sk);

        {
            let mut pk_lock = self.inner.private_key.lock().await;
            *pk_lock = Some(secret);
        }

        // Check if we already have a TUN device (reconnect scenario)
        {
            let device_lock = self.inner.device.lock().await;
            if device_lock.is_some() {
                info!("[WG] TUN device already exists, reusing for reconnect");
                return Ok(());
            }
        }

        // Create TUN device
        info!("[WG] Configuring TUN device...");

        // On Windows, try to reuse existing WinTun adapter to avoid accumulation
        #[cfg(target_os = "windows")]
        {
            let device = self.setup_windows_tun(vip).await?;
            let mut d_lock = self.inner.device.lock().await;
            *d_lock = Some(device);
            Ok(())
        }

        // Non-Windows path
        #[cfg(not(target_os = "windows"))]
        {
            let mut config = tun::Configuration::default();

            // On macOS, TUN interfaces must be named utunN - we cannot set custom names.
            // Only set the interface name on Linux where custom names are supported.
            // On macOS, the system will auto-assign the next available utun interface.
            #[cfg(target_os = "linux")]
            if !self.interface.is_empty() {
                config.name(&self.interface);
            }

            config.address(vip).netmask("255.255.255.0").up();

            #[cfg(target_os = "linux")]
            config.platform(|config| {
                config.packet_information(false);
            });

            #[cfg(target_os = "macos")]
            info!("[WG] Calling tun::create_as_async (macOS will auto-assign utunN)...");
            #[cfg(target_os = "linux")]
            info!(
                "[WG] Calling tun::create_as_async for interface '{}'...",
                self.interface
            );

            let device = tun::create_as_async(&config).map_err(|e| {
                let err_msg = format!("[WG] Failed to create TUN device: {:?}", e);
                error!("{}", err_msg);
                err_msg
            })?;

            #[cfg(target_os = "macos")]
            info!("[WG] Userspace WireGuard TUN created successfully (macOS utun)");
            #[cfg(target_os = "linux")]
            info!(
                "[WG] Userspace WireGuard TUN '{}' created successfully",
                self.interface
            );

            {
                let mut d_lock = self.inner.device.lock().await;
                *d_lock = Some(device);
            }

            Ok(())
        }
    }

    /// Windows-specific TUN setup that reuses existing WinTun adapters
    #[cfg(target_os = "windows")]
    async fn setup_windows_tun(&self, vip: &str) -> Result<tun::AsyncDevice, String> {
        use std::sync::Arc as StdArc;

        info!(
            "[WG] Windows TUN setup - interface name: '{}'",
            self.interface
        );

        // Try to load WinTun library
        let wintun_dll = match unsafe { wintun::load() } {
            Ok(dll) => StdArc::new(dll),
            Err(e) => {
                warn!(
                    "[WG] Failed to load WinTun DLL, falling back to tun crate: {}",
                    e
                );
                return self.create_tun_fallback(vip);
            }
        };

        let adapter_name = if self.interface.is_empty() {
            "wintun"
        } else {
            &self.interface
        };

        info!("[WG] Using adapter name: '{}'", adapter_name);

        // First, try to open an existing adapter with the same name
        info!(
            "[WG] Checking for existing WinTun adapter '{}'...",
            adapter_name
        );

        // Try to open existing adapter
        match wintun::Adapter::open(&wintun_dll, adapter_name) {
            Ok(existing_adapter) => {
                info!(
                    "[WG] Found existing WinTun adapter '{}', reusing it",
                    adapter_name
                );

                // The existing adapter is already open. Now we need to create a session
                // and wrap it in a tun::AsyncDevice. Unfortunately the tun crate doesn't
                // expose a way to use an existing adapter directly.
                //
                // For now, we'll close the old adapter and recreate - this at least
                // prevents accumulation since we're using the same name/GUID
                drop(existing_adapter);

                // Small delay to let Windows clean up
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            Err(_) => {
                info!("[WG] No existing adapter found, will create new one");
            }
        }

        // Create the TUN device using the tun crate
        // On Windows with a fixed interface name, this should reuse or recreate cleanly
        info!(
            "[WG] Calling create_tun_fallback with interface name: '{}'",
            self.interface
        );
        self.create_tun_fallback(vip)
    }

    /// Fallback TUN creation using the tun crate directly
    #[cfg(target_os = "windows")]
    fn create_tun_fallback(&self, vip: &str) -> Result<tun::AsyncDevice, String> {
        use tun::Device as TunDevice; // Import the Device trait for set_name()

        let mut config = tun::Configuration::default();

        // Set interface name on Windows
        info!(
            "[WG] create_tun_fallback: self.interface = '{}', is_empty = {}",
            self.interface,
            self.interface.is_empty()
        );

        let adapter_name = if self.interface.is_empty() {
            "OmniEdge" // Default to OmniEdge if somehow empty
        } else {
            &self.interface
        };

        info!("[WG] Setting config.name to '{}'", adapter_name);
        config.name(adapter_name);
        info!("[WG] config.name set successfully");

        config.address(vip).netmask("255.255.255.0").up();

        info!(
            "[WG] Calling tun::create_as_async for Windows interface '{}'...",
            adapter_name
        );

        let mut device = tun::create_as_async(&config).map_err(|e| {
            let err_msg = format!("[WG] Failed to create TUN device: {:?}", e);
            error!("{}", err_msg);
            err_msg
        })?;

        // Verify and fix the adapter name if needed
        match device.get_ref().name() {
            Ok(current_name) => {
                info!("[WG] Created adapter with name: '{}'", current_name);
                if current_name != adapter_name {
                    info!(
                        "[WG] Adapter name mismatch! Expected '{}', got '{}'. Renaming...",
                        adapter_name, current_name
                    );
                    if let Err(e) = device.get_mut().set_name(adapter_name) {
                        warn!(
                            "[WG] Failed to rename adapter to '{}': {:?}",
                            adapter_name, e
                        );
                    } else {
                        info!("[WG] Successfully renamed adapter to '{}'", adapter_name);
                    }
                }
            }
            Err(e) => {
                warn!("[WG] Could not get adapter name: {:?}", e);
            }
        }

        info!(
            "[WG] Userspace WireGuard TUN '{}' created successfully",
            adapter_name
        );

        Ok(device)
    }

    pub async fn set_peer(
        &self,
        public_key: &str,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[String],
        persistent_keepalive: Option<u32>,
    ) -> Result<(), String> {
        let pk_bytes = hex::decode(public_key).map_err(|e| e.to_string())?;
        let mut pk = [0u8; 32];
        if pk_bytes.len() != 32 {
            return Err("Invalid peer public key".to_string());
        }
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

            peers.insert(
                pk,
                PeerSession {
                    tunnel: Arc::new(Mutex::new(tunnel)),
                    endpoint,
                    public_key: pk,
                },
            );

            let mut indices = self.inner.index_map.write().await;
            indices.insert(index, pk);

            info!("Added userspace peer {} with index {}", public_key, index);
        }

        Ok(())
    }

    pub async fn start_tun_loop(&self, udp_socket: Arc<UdpSocket>) -> Result<(), String> {
        let device = {
            let mut d_lock = self.inner.device.lock().await;
            d_lock.take().ok_or("TUN device not initialized")?
        };

        let (mut reader, mut writer) = tokio::io::split(device);
        let inner = self.inner.clone();
        let socket_tx = udp_socket.clone();

        // TUN -> UDP (Encrypt)
        let reader_handle = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut packet_count: u64 = 0;
            info!("[TUN] Reader loop started");
            loop {
                match reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        packet_count += 1;
                        let dest_ip = parse_dst_ip(&buf[..n]);
                        
                        // Log first few packets and then every 100th for debugging
                        let should_log = packet_count <= 5 || packet_count % 100 == 0;
                        
                        if should_log {
                            debug!("[TUN] Read packet #{}: {} bytes, dest_ip={:?}", packet_count, n, dest_ip);
                        }
                        
                        if let Some(ip) = dest_ip {
                            let pk_opt = {
                                let routing = inner.routing_table.read().await;
                                let result = routing.get(&ip).copied();
                                if should_log {
                                    debug!("[TUN] Routing lookup for {}: found={}", ip, result.is_some());
                                }
                                result
                            };

                            if let Some(pk) = pk_opt {
                                // OPTIMIZATION: Cache tunnel Arc and endpoint to minimize lock scope
                                // This allows us to release the peers lock before crypto operations
                                let tunnel_and_endpoint = {
                                    let peers = inner.peers.read().await;
                                    peers.get(&pk).map(|session| {
                                        (session.tunnel.clone(), session.endpoint)
                                    })
                                };
                                // peers lock released here

                                if let Some((tunnel_arc, Some(ep))) = tunnel_and_endpoint {
                                    // OPTIMIZATION: Perform encryption, then release lock before network I/O
                                    // This prevents holding Mutex during UDP send which was a major bottleneck
                                    let send_result = {
                                        let mut t_lock = tunnel_arc.lock().await;
                                        let mut dst = [0u8; 2048];
                                        match t_lock.encapsulate(&buf[..n], &mut dst) {
                                            TunnResult::WriteToNetwork(packet) => {
                                                let msg_type = if !packet.is_empty() { packet[0] } else { 0 };
                                                
                                                // Extract sender_index from HandshakeInit (bytes 4-7) and store in index_map
                                                // This enables O(1) routing for incoming Data packets
                                                if msg_type == 1 && packet.len() >= 8 {
                                                    let sender_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
                                                    drop(t_lock); // Release tunnel lock before index_map write
                                                    let mut indices = inner.index_map.write().await;
                                                    indices.insert(sender_index, pk);
                                                    debug!("[WG-TX] Registered sender_index {} for peer", sender_index);
                                                    // Re-encapsulate after re-acquiring lock (handshakes are rare)
                                                    let mut t_lock = tunnel_arc.lock().await;
                                                    let mut dst2 = [0u8; 2048];
                                                    if let TunnResult::WriteToNetwork(p) = t_lock.encapsulate(&[], &mut dst2) {
                                                        Some((p.to_vec(), msg_type))
                                                    } else {
                                                        Some((packet.to_vec(), msg_type))
                                                    }
                                                } else {
                                                    // For Data packets (most common case), copy and release lock immediately
                                                    Some((packet.to_vec(), msg_type))
                                                }
                                            }
                                            TunnResult::Err(e) => {
                                                error!("[WG-TX] Encapsulate error for {}: {:?}", ip, e);
                                                None
                                            }
                                            TunnResult::Done => {
                                                if should_log {
                                                    debug!("[WG-TX] Encapsulate returned Done (no packet to send)");
                                                }
                                                None
                                            }
                                            _ => {
                                                if should_log {
                                                    debug!("[WG-TX] Encapsulate returned other result");
                                                }
                                                None
                                            }
                                        }
                                    }; // tunnel lock released here

                                    // Now send outside of any lock - this is the key optimization!
                                    if let Some((packet_data, msg_type)) = send_result {
                                        // Only log handshakes, NEVER log Data packets (critical for performance)
                                        if msg_type <= 3 {
                                            let type_name = match msg_type {
                                                1 => "HandshakeInit",
                                                2 => "HandshakeResponse",
                                                3 => "CookieReply",
                                                _ => "Unknown",
                                            };
                                            info!("[WG-TX] Sending {} ({} bytes) to {}", type_name, packet_data.len(), ep);
                                        }
                                        if let Err(e) = socket_tx.send_to(&packet_data, ep).await {
                                            error!("[WG-TX] Failed to send to {}: {}", ep, e);
                                        }
                                    }
                                } else if tunnel_and_endpoint.is_some() {
                                    if should_log {
                                        debug!("[TUN] Peer {} has no endpoint set", hex::encode(&pk[..8]));
                                    }
                                } else {
                                    if should_log {
                                        debug!("[TUN] Peer not found for public key");
                                    }
                                }
                            } else {
                                if should_log {
                                    debug!("[TUN] No route to {}", ip);
                                }
                            }
                        } else {
                            if should_log {
                                debug!("[TUN] Could not parse destination IP from packet");
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        error!("[TUN] Read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Store writer in inner for the UDP -> TUN handler
        // Actually, we can just spawn the writer task or use a channel
        // Let's use a channel to communicate with the writer
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        {
            let mut writer_lock = self.inner.tun_writer.write().await;
            *writer_lock = Some(tx);
        }

        let writer_handle = tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                if let Err(e) = writer.write_all(&packet).await {
                    error!("Failed to write to TUN: {}", e);
                }
            }
        });

        // Store task handles for cleanup
        {
            let mut handles = self.inner.tun_task_handles.lock().await;
            handles.push(reader_handle);
            handles.push(writer_handle);
        }

        Ok(())
    }

    pub async fn handle_udp_packet(
        &self,
        buf: &[u8],
        src: SocketAddr,
        udp_socket: &UdpSocket,
    ) -> Result<(), String> {
        if buf.len() < 4 {
            return Ok(());
        }
        let msg_type = buf[0];
        
        // Log incoming WireGuard packets
        let type_name = match msg_type {
            1 => "HandshakeInit",
            2 => "HandshakeResponse",
            3 => "CookieReply", 
            4 => "Data",
            _ => "Unknown",
        };
        
        // Always log handshake messages, sample data messages
        if msg_type <= 3 {
            info!("[WG-RX] Received {} ({} bytes) from {}", type_name, buf.len(), src);
        }

        let tunnels_to_try = match msg_type {
            1 => {
                // Handshake Initiation: Try all sessions
                let peers = self.inner.peers.read().await;
                let count = peers.len();
                debug!("[WG-RX] HandshakeInit: trying {} peer sessions", count);
                peers.values().map(|s| s.tunnel.clone()).collect::<Vec<_>>()
            }
            2 => {
                // Handshake Response: Try all sessions because BoringTun uses internal indices
                // that don't match our index_map. BoringTun will internally validate the handshake.
                let peers = self.inner.peers.read().await;
                let count = peers.len();
                debug!("[WG-RX] HandshakeResponse: trying {} peer sessions", count);
                peers.values().map(|s| s.tunnel.clone()).collect::<Vec<_>>()
            }
            3 => {
                // Cookie Reply: Try all sessions (BoringTun uses internal indices)
                let peers = self.inner.peers.read().await;
                debug!("[WG-RX] CookieReply: trying {} peer sessions", peers.len());
                peers.values().map(|s| s.tunnel.clone()).collect::<Vec<_>>()
            }
            4 => {
                // Data packet: Use receiver_index (bytes 4-7) for O(1) direct lookup
                // This is the key optimization - avoids O(n) trial loop
                if buf.len() >= 8 {
                    let receiver_index = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    let indices = self.inner.index_map.read().await;
                    if let Some(pk) = indices.get(&receiver_index) {
                        let peers = self.inner.peers.read().await;
                        if let Some(session) = peers.get(pk) {
                            debug!("[WG-RX] Data packet: found peer via index {}", receiver_index);
                            vec![session.tunnel.clone()]
                        } else {
                            debug!("[WG-RX] Data packet: index {} maps to unknown peer", receiver_index);
                            // Fallback: try all peers
                            let peers = self.inner.peers.read().await;
                            peers.values().map(|s| s.tunnel.clone()).collect::<Vec<_>>()
                        }
                    } else {
                        debug!("[WG-RX] Data packet: receiver_index {} not in index_map, trying all peers", receiver_index);
                        // Fallback: try all peers (handles initial packets before index is registered)
                        let peers = self.inner.peers.read().await;
                        peers.values().map(|s| s.tunnel.clone()).collect::<Vec<_>>()
                    }
                } else {
                    vec![]
                }
            }
            _ => vec![],
        };

        if tunnels_to_try.is_empty() && msg_type <= 4 {
            debug!("[WG-RX] No tunnels to try for {} from {}", type_name, src);
        }

        for t_arc in tunnels_to_try {
            let mut t_lock = t_arc.lock().await;
            let mut dst = [0u8; 2048];
            match t_lock.decapsulate(Some(src.ip()), buf, &mut dst) {
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    debug!("[WG-RX] Decapsulated {} bytes to TUN", packet.len());
                    let packet_vec = packet.to_vec();
                    let tun_writer = self.inner.tun_writer.read().await;
                    if let Some(tx) = tun_writer.as_ref() {
                        let _ = tx.try_send(packet_vec);
                    }
                    return Ok(()); // Success
                }
                TunnResult::WriteToNetwork(packet) => {
                    let resp_type = if !packet.is_empty() { packet[0] } else { 0 };
                    let resp_name = match resp_type {
                        1 => "HandshakeInit",
                        2 => "HandshakeResponse",
                        3 => "CookieReply",
                        4 => "Data",
                        _ => "Unknown",
                    };
                    
                    // When sending HandshakeResponse (as responder), register our sender_index
                    // This enables O(1) routing for incoming Data packets
                    if resp_type == 2 && packet.len() >= 8 {
                        let sender_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
                        // We need to find the public key for this tunnel - look it up from peers
                        let peers = self.inner.peers.read().await;
                        for (pk, session) in peers.iter() {
                            // Check if this is the tunnel we just used
                            if Arc::ptr_eq(&session.tunnel, &t_arc) {
                                let mut indices = self.inner.index_map.write().await;
                                indices.insert(sender_index, *pk);
                                debug!("[WG-TX] Registered sender_index {} for peer (responder)", sender_index);
                                break;
                            }
                        }
                    }
                    
                    info!("[WG-TX] Sending {} ({} bytes) to {} in response", resp_name, packet.len(), src);
                    if let Err(e) = udp_socket.send_to(packet, src).await {
                        error!("[WG-TX] Failed to send handshake response to {}: {}", src, e);
                    }
                    return Ok(()); // Handshake progression
                }
                TunnResult::Err(boringtun::noise::errors::WireGuardError::WrongIndex) => {
                    debug!("[WG-RX] WrongIndex error, trying next peer");
                    continue;
                }
                TunnResult::Err(e) => {
                    debug!("[WG-RX] Decapsulate error: {:?}", e);
                    // Might be wrong peer, continue
                }
                TunnResult::Done => {
                    debug!("[WG-RX] Handshake progressed (Done)");
                    return Ok(());
                }
                _ => {
                    // Handshake progression or nothing, but we found the peer
                    debug!("[WG-RX] Decapsulate returned other result");
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    pub async fn get_peer_stats(&self, public_key: &str) -> Option<PeerStats> {
        let pk_bytes = hex::decode(public_key).ok()?;
        let mut pk = [0u8; 32];
        if pk_bytes.len() != 32 {
            return None;
        }
        pk.copy_from_slice(&pk_bytes);

        let peers = self.inner.peers.read().await;
        if let Some(session) = peers.get(&pk) {
            let t_lock = session.tunnel.try_lock().ok()?;
            Some(PeerStats {
                last_handshake: t_lock
                    .time_since_last_handshake()
                    .map(|d| std::time::SystemTime::now() - d),
                rx_bytes: 0, // BoringTun doesn't track these directly in Tunn
                tx_bytes: 0,
            })
        } else {
            None
        }
    }

    /// Shutdown the userspace WireGuard interface and release the TUN device.
    /// This closes the TUN file descriptor which causes macOS to remove the utun interface.
    pub async fn shutdown(&self) {
        info!("[WG] Shutting down userspace interface: {}", self.interface);

        // Clear the TUN writer channel first to stop any pending writes
        // This will cause the writer task to exit when channel closes
        {
            let mut writer = self.inner.tun_writer.write().await;
            *writer = None;
        }

        // Abort the TUN reader/writer tasks - this is critical!
        // The reader task holds the TUN device reader half, aborting releases it
        {
            let mut handles = self.inner.tun_task_handles.lock().await;
            for handle in handles.drain(..) {
                info!("[WG] Aborting TUN task...");
                handle.abort();
            }
        }

        // Clear peer sessions
        {
            let mut peers = self.inner.peers.write().await;
            peers.clear();
        }

        // Clear routing table
        {
            let mut routing = self.inner.routing_table.write().await;
            routing.clear();
        }

        // Clear index map
        {
            let mut index_map = self.inner.index_map.write().await;
            index_map.clear();
        }

        // Drop the TUN device if it's still there (shouldn't be after start_tun_loop)
        // On macOS, closing the fd causes the kernel to remove the utun interface
        {
            let mut device = self.inner.device.lock().await;
            if device.is_some() {
                info!("[WG] Dropping TUN device to release interface");
                *device = None;
            }
        }

        // Clear private key
        {
            let mut pk = self.inner.private_key.lock().await;
            *pk = None;
        }

        info!(
            "[WG] Userspace interface {} shutdown complete",
            self.interface
        );
    }

    /// Soft shutdown - clears peers and routing but keeps TUN device/tasks alive.
    /// This is used on Windows to allow reconnect without recreating the WinTun adapter.
    pub async fn soft_shutdown(&self) {
        info!(
            "[WG] Soft shutdown userspace interface: {} (keeping TUN alive)",
            self.interface
        );

        // Clear peer sessions - stops WireGuard encryption/decryption
        {
            let mut peers = self.inner.peers.write().await;
            peers.clear();
        }

        // Clear routing table - no packets will be routed
        {
            let mut routing = self.inner.routing_table.write().await;
            routing.clear();
        }

        // Clear index map
        {
            let mut index_map = self.inner.index_map.write().await;
            index_map.clear();
        }

        // NOTE: We do NOT:
        // - Clear the TUN writer channel (tasks keep running)
        // - Abort the TUN reader/writer tasks (device stays open)
        // - Drop the TUN device (stays alive)
        // - Clear the private key (can be reused)

        info!(
            "[WG] Soft shutdown complete for {} - TUN device still active",
            self.interface
        );
    }

    /// Check if the TUN loop is active (tasks are running with device)
    pub async fn is_tun_active(&self) -> bool {
        // If we have task handles and tun_writer, the loop is active
        let has_handles = {
            let handles = self.inner.tun_task_handles.lock().await;
            !handles.is_empty()
        };
        let has_writer = {
            let writer = self.inner.tun_writer.read().await;
            writer.is_some()
        };
        has_handles && has_writer
    }
}

/// Helper to parse destination IP from raw IP packet
fn parse_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    if version == 4 {
        if packet.len() >= 20 {
            Some(IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )))
        } else {
            None
        }
    } else if version == 6 {
        if packet.len() >= 40 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_dst() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[16] = 192;
        pkt[17] = 168;
        pkt[18] = 0;
        pkt[19] = 1;
        assert_eq!(
            parse_dst_ip(&pkt),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
        );
    }

    #[test]
    fn test_parse_ipv6_dst() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[24] = 0x20;
        pkt[25] = 0x01;
        pkt[26] = 0x0d;
        pkt[27] = 0xb8;
        pkt[39] = 0x01;
        let ip = parse_dst_ip(&pkt).unwrap();
        match ip {
            IpAddr::V6(v6) => assert_eq!(v6.segments()[0], 0x2001),
            _ => panic!("Expected IPv6"),
        }
    }
}
