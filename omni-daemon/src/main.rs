// Allow dead_code for utility modules with functions ready for future use
#![allow(dead_code)]

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use clap::Parser;
use log::{info, error, warn, debug};
use tokio::net::UdpSocket;
use tokio::signal;

mod noise;
mod session;
mod p2p;
mod fdb;
mod identity;
mod ratelimit;
mod metrics;
mod config;
mod bpf_sync;
mod http;
mod nonce;
mod crypto_util;
mod poly1305;
mod tun;
mod peers;
mod signaling;

use noise::NoiseSession;
use session::{SessionManager, SessionState};
use p2p::P2PDiscovery;
use fdb::Fdb;
use identity::Identity;
use ratelimit::{RateLimiter, RateLimitConfig};
use metrics::Metrics;
use bpf_sync::BpfSync;

use std::time::Duration;
use tokio::time::interval;

/// Embedded eBPF program binary (built by CI and placed in omni-daemon/ebpf/)
#[cfg(target_os = "linux")]
static EBPF_PROGRAM: &[u8] = include_bytes!("../ebpf/omni-ebpf-core");

/// Try to load eBPF/XDP program on Linux
/// Returns Ok(Bpf) if successful, Err if not available or failed
#[cfg(target_os = "linux")]
fn try_load_ebpf(iface: &str, bpf_sync: &mut BpfSync) -> Result<Bpf> {
    use std::process::Command;
    
    // Check if eBPF binary is available (not empty placeholder)
    if EBPF_PROGRAM.is_empty() {
        anyhow::bail!("eBPF program not embedded (placeholder only)");
    }
    
    // Check kernel version (need 5.4+ for good XDP support)
    let kernel_version = Command::new("uname")
        .arg("-r")
        .output()
        .context("Failed to get kernel version")?;
    let kernel_str = String::from_utf8_lossy(&kernel_version.stdout);
    let version_parts: Vec<&str> = kernel_str.trim().split('.').collect();
    
    if version_parts.len() >= 2 {
        let major: u32 = version_parts[0].parse().unwrap_or(0);
        let minor: u32 = version_parts[1].parse().unwrap_or(0);
        if major < 5 || (major == 5 && minor < 4) {
            anyhow::bail!("Kernel {}.{} too old (need 5.4+)", major, minor);
        }
        info!("Kernel {}.{} detected, XDP supported", major, minor);
    }
    
    // Check if interface exists
    let ip_output = Command::new("ip")
        .args(["link", "show", iface])
        .output()
        .context("Failed to check interface")?;
    if !ip_output.status.success() {
        anyhow::bail!("Interface {} not found", iface);
    }
    
    // Load embedded eBPF program
    info!("Loading embedded XDP program ({} bytes)...", EBPF_PROGRAM.len());
    let mut bpf = Bpf::load(EBPF_PROGRAM)
        .context("Failed to load eBPF program")?;
    
    // Get and load the XDP program
    let program: &mut Xdp = bpf.program_mut("xdp_synapse")
        .context("xdp_synapse program not found")?
        .try_into()
        .context("Failed to cast to XDP program")?;
    
    program.load()
        .context("Failed to load XDP program into kernel")?;
    
    // Attach to interface
    program.attach(iface, XdpFlags::default())
        .context(format!("Failed to attach XDP to {}", iface))?;
    
    info!("XDP program attached to interface {}", iface);
    
    // Initialize BPF map sync
    bpf_sync.init_from_bpf(&mut bpf)
        .context("Failed to initialize BPF map sync")?;
    
    Ok(bpf)
}

#[derive(Parser, Debug)]
#[command(
    name = "omni-daemon",
    author = "OmniEdge <contact@omniedge.io>",
    version,
    about = "OmniNervous P2P VPN Daemon - Secure mesh networking for edge devices",
    long_about = "OmniNervous Ganglion Daemon\n\n\
        A high-performance P2P VPN daemon with:\n\
        - Noise_IKpsk2 protocol (X25519 + ChaCha20-Poly1305)\n\
        - Cluster-based PSK authentication\n\
        - XDP/eBPF acceleration (Linux)\n\
        - Cross-platform TUN support\n\n\
        Examples:\n  \
          # Run as Nucleus (signaling server)\n  \
          omni-daemon --mode nucleus --port 51820\n\n  \
          # Run as Edge (P2P client)\n  \
          omni-daemon --nucleus 1.2.3.4:51820 --cluster mynet --secret MySecret123456 --vip 10.200.0.1"
)]
struct Args {
    /// Network interface for eBPF attachment (Linux only)
    #[arg(short, long, default_value = "eth0")]
    iface: String,
    
    /// UDP port for VPN traffic
    #[arg(short, long, default_value = "51820")]
    port: u16,
    
    /// Run mode: 'nucleus' for signaling server, omit for edge client
    #[arg(short, long)]
    mode: Option<String>,
    
    /// Nucleus server address (host:port) for edge clients
    #[arg(short, long)]
    nucleus: Option<String>,
    
    /// Cluster/network name to join
    #[arg(short, long)]
    cluster: Option<String>,
    
    /// Cluster secret for authentication (minimum 16 characters)
    #[arg(long)]
    secret: Option<String>,
    
    /// Initialize new identity and exit
    #[arg(long)]
    init: bool,
    
    /// Path to identity directory
    #[arg(long)]
    identity: Option<std::path::PathBuf>,
    
    /// Path to config file
    #[arg(long, short = 'C')]
    config: Option<std::path::PathBuf>,
    
    /// Disable eBPF/XDP acceleration (Linux only)
    #[arg(long)]
    no_ebpf: bool,
    
    /// Virtual IP address (e.g., 10.200.0.1)
    #[arg(long)]
    vip: Option<std::net::Ipv4Addr>,
    
    /// Virtual network mask
    #[arg(long, default_value = "255.255.255.0")]
    netmask: std::net::Ipv4Addr,
    
    /// Virtual interface name
    #[arg(long, default_value = "omni0")]
    tun_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::init();

    info!("Starting OmniNervous Ganglion Daemon on port {}...", args.port);

    // Handle --init flag
    if args.init {
        let id = Identity::generate();
        id.save(args.identity.as_ref())?;
        info!("Generated new identity: {}", id.public_key_hex());
        println!("Your Public Identity: {}", id.public_key_hex());
        return Ok(());
    }

    // Load or generate identity
    let identity = Identity::load_or_generate(args.identity.as_ref())?;
    info!("Using identity: {}", identity.public_key_hex());

    // Derive PSK from cluster + secret if provided
    let psk: Option<[u8; 32]> = match (&args.cluster, &args.secret) {
        (Some(cluster), Some(secret)) => {
            // Validate secret length
            noise::validate_secret(secret)?;
            let psk = noise::derive_psk(cluster, secret);
            info!("Cluster '{}' with authenticated secret (PSK enabled)", cluster);
            Some(psk)
        }
        (Some(cluster), None) => {
            warn!("⚠️ Cluster '{}' without secret - OPEN MODE (any peer can join)", cluster);
            None
        }
        (None, Some(_)) => {
            anyhow::bail!("--secret requires --cluster to be specified");
        }
        (None, None) => {
            info!("No cluster specified, running in standalone mode");
            None
        }
    };

    let mut session_manager = SessionManager::new();
    let _fdb = Fdb::new();
    let mut p2p = P2PDiscovery::new(None).await?;
    let mut rate_limiter = RateLimiter::new(RateLimitConfig::default());
    let metrics = Metrics::new();
    let mut bpf_sync = BpfSync::new();
    let mut peer_table = peers::PeerTable::new();
    
    // Our virtual IP (used for self-identification in peer exchange)
    let _our_vip = args.vip;
    
    // Try to load eBPF/XDP on Linux if not disabled
    #[cfg(target_os = "linux")]
    let _bpf = if !args.no_ebpf {
        match try_load_ebpf(&args.iface, &mut bpf_sync) {
            Ok(bpf) => {
                info!("✅ eBPF/XDP enabled on interface {}", args.iface);
                Some(bpf)
            }
            Err(e) => {
                warn!("eBPF/XDP not available: {}. Using userspace processing.", e);
                None
            }
        }
    } else {
        info!("eBPF/XDP disabled via --no-ebpf flag");
        None
    };
    
    #[cfg(not(target_os = "linux"))]
    info!("Running on non-Linux platform, using userspace processing");
    
    // Create virtual interface if VIP is specified
    let mut _tun = if let Some(vip) = args.vip {
        // Check permissions first
        if let Err(e) = tun::check_tun_permissions() {
            warn!("TUN permission check: {}", e);
        }
        
        let tun_config = tun::TunConfig {
            name: args.tun_name.clone(),
            address: vip,
            netmask: args.netmask,
            mtu: 1420,
        };
        
        match tun::VirtualInterface::create(tun_config).await {
            Ok(tun) => {
                info!("✅ Virtual interface '{}' active with IP {}", tun.name(), tun.address());
                Some(tun)
            }
            Err(e) => {
                error!("❌ Failed to create TUN interface: {}", e);
                error!("   Ensure you have root/admin privileges");
                error!("   On Linux: sudo or CAP_NET_ADMIN capability required");
                #[cfg(target_os = "linux")]
                error!("   Run: sudo modprobe tun (if TUN module not loaded)");
                #[cfg(target_os = "windows")]
                error!("   Windows: Ensure wintun.dll is in the same directory");
                // Exit with error - TUN is required when --vip is specified
                anyhow::bail!("TUN interface creation failed: {}. Cannot operate VPN without interface.", e);
            }
        }
    } else {
        info!("No --vip specified, running in signaling-only mode (Nucleus)");
        None
    };
    
    // Cleanup interval - runs every 60 seconds
    let mut cleanup_interval = interval(Duration::from_secs(60));
    // Heartbeat interval - runs every 30 seconds (for edge mode)
    let mut heartbeat_interval = interval(Duration::from_secs(30));

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", args.port)).await
        .context("failed to bind UDP socket")?;
    
    info!("Ganglion listening on UDP/{}", args.port);

    // Determine mode: Nucleus (signaling server) or Edge (P2P client)
    let is_nucleus_mode = args.mode.as_ref().map(|m| m == "nucleus").unwrap_or(false);
    
    // Nucleus state (only used in nucleus mode)
    let mut nucleus_state = signaling::NucleusState::new();
    
    // Nucleus client (only used in edge mode when --nucleus is specified)
    let nucleus_client: Option<signaling::NucleusClient> = if !is_nucleus_mode {
        if let (Some(nucleus_addr), Some(cluster)) = (&args.nucleus, &args.cluster) {
            if let Some(vip) = args.vip {
                match signaling::NucleusClient::new(
                    nucleus_addr,
                    cluster.clone(),
                    identity.public_key_bytes(),
                    vip,
                    args.port,
                ).await {
                    Ok(client) => {
                        // Register with nucleus immediately
                        if let Err(e) = client.register(&socket).await {
                            warn!("Failed to register with nucleus: {}", e);
                        }
                        Some(client)
                    }
                    Err(e) => {
                        warn!("Failed to create nucleus client: {}", e);
                        None
                    }
                }
            } else {
                warn!("--nucleus requires --vip to be specified");
                None
            }
        } else {
            info!("No nucleus specified, running in standalone mode");
            None
        }
    } else {
        info!("Running as Nucleus (signaling server)");
        None
    };

    // Spawn metrics HTTP server
    let metrics_clone = metrics.clone();
    tokio::spawn(async move {
        if let Err(e) = http::serve_metrics(metrics_clone, 9090).await {
            error!("Metrics server failed: {}", e);
        }
    });

    // Perform STUN discovery (using isolated ephemeral socket)
    if let Err(e) = p2p.discover_self().await {
        warn!("STUN discovery failed: {}", e);
    } else if let Some(ref endpoint) = p2p.local_endpoint {
        info!("Public endpoint: {}:{}", endpoint.ip, endpoint.port);
    }

    let mut buf = [0u8; 2048];
    let mut tun_buf = [0u8; 2048];
    
    loop {
        // TUN read future - only if TUN is active
        let tun_read = async {
            if let Some(ref mut tun) = _tun {
                tun.read(&mut tun_buf).await
            } else {
                // No TUN, sleep forever on this branch
                std::future::pending::<Result<usize>>().await
            }
        };
        
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            _ = cleanup_interval.tick() => {
                // Periodic cleanup: rate limiter, expired sessions, BPF map
                rate_limiter.cleanup();
                let expired = rate_limiter.expired_sessions();
                for sid in expired {
                    let _ = bpf_sync.remove_session(sid);
                    info!("Expired session {}", sid);
                }
                
                // Nucleus mode: cleanup stale peers
                if is_nucleus_mode {
                    nucleus_state.cleanup();
                }
            }
            _ = heartbeat_interval.tick() => {
                // Edge mode: send heartbeat to nucleus
                if let Some(ref client) = nucleus_client {
                    let peer_count = peer_table.len() as u32;
                    if let Err(e) = client.heartbeat(&socket, peer_count).await {
                        warn!("Failed to send heartbeat: {}", e);
                    }
                }
                
                // Initiate handshakes to discovered peers that haven't been contacted yet
                if !is_nucleus_mode {
                    let peers_to_connect = peer_table.peers_needing_handshake();
                    for peer in peers_to_connect {
                        if let Some(pubkey) = peer.public_key {
                            // Create initiator session
                            match NoiseSession::new_initiator(&identity.private_key, &pubkey, psk.as_ref()) {
                                Ok(mut session) => {
                                    // Build handshake message 1 with our VIP
                                    let mut payload = vec![];
                                    if let Some(our_vip) = args.vip {
                                        payload.extend_from_slice(&our_vip.octets());
                                    }
                                    
                                    let mut msg = vec![0u8; 128];
                                    match session.handshake.write_message(&payload, &mut msg) {
                                        Ok(len) => {
                                            // Build packet: [session_id(8)] [handshake]
                                            let mut packet = peer.session_id.to_be_bytes().to_vec();
                                            packet.extend_from_slice(&msg[..len]);
                                            
                                            if let Err(e) = socket.send_to(&packet, peer.endpoint).await {
                                                warn!("Failed to send handshake to {}: {}", peer.virtual_ip, e);
                                            } else {
                                                // Store session and mark peer
                                                session_manager.create_session(
                                                    peer.session_id,
                                                    SessionState::Handshaking(session)
                                                );
                                                peer_table.mark_handshake_initiated(&peer.virtual_ip);
                                                info!("Initiated handshake to {} at {}", peer.virtual_ip, peer.endpoint);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to write handshake message: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to create initiator session for {}: {}", peer.virtual_ip, e);
                                }
                            }
                        }
                    }
                }
            }
            // Read from TUN interface (local packets to send to VPN)
            tun_result = tun_read => {
                match tun_result {
                    Ok(len) if len > 0 => {
                        // IP packet from local TUN: encrypt + send to peer
                        let ip_version = (tun_buf[0] >> 4) & 0xF;
                        if ip_version == 4 && len >= 20 {
                            let dst_ip = std::net::Ipv4Addr::new(
                                tun_buf[16], tun_buf[17], tun_buf[18], tun_buf[19]
                            );
                            
                            // Lookup peer by destination VIP
                            if let Some(peer) = peer_table.lookup_by_vip(&dst_ip) {
                                // Get session for encryption
                                if let Some(SessionState::Active(transport)) = session_manager.get_session_mut(peer.session_id) {
                                    // Encrypt packet: [session_id(8)] [nonce(8)] [encrypted_data] [tag(16)]
                                    let mut nonce_counter = [0u8; 8];
                                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_counter);
                                    
                                    let mut encrypted = vec![0u8; len + 16]; // 16 bytes for tag
                                    match transport.write_message(peer.session_id, &tun_buf[..len], &mut encrypted) {
                                        Ok(enc_len) => {
                                            // Build packet: session_id + encrypted
                                            let mut packet = peer.session_id.to_be_bytes().to_vec();
                                            packet.extend_from_slice(&encrypted[..enc_len]);
                                            
                                            if let Err(e) = socket.send_to(&packet, peer.endpoint).await {
                                                error!("Failed to send encrypted packet: {}", e);
                                            } else {
                                                metrics.inc_packets_tx();
                                                info!("TUN→UDP: {} bytes to {} (session {})", len, dst_ip, peer.session_id);
                                            }
                                        }
                                        Err(e) => {
                                            error!("Encryption failed: {}", e);
                                        }
                                    }
                                } else {
                                    warn!("No active session for peer {} (session {})", dst_ip, peer.session_id);
                                }
                            } else {
                                // On-demand discovery: query nucleus for unknown peer
                                if let Some(ref client) = nucleus_client {
                                    if let Err(e) = client.query_peer(&socket, dst_ip).await {
                                        warn!("Failed to query peer {}: {}", dst_ip, e);
                                    } else {
                                        debug!("Queried nucleus for peer {}", dst_ip);
                                    }
                                }
                                // Packet will be dropped; retry after peer info arrives
                            }
                        }
                    }
                    Ok(_) => {} // Zero-length read, ignore
                    Err(e) => {
                        error!("TUN read error: {}", e);
                    }
                }
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        metrics.inc_packets_rx();
                        
                        // Check if this is a signaling message (first byte indicates type)
                        if len > 0 && buf[0] < 0x10 {
                            // Signaling message types are 0x01-0x0F
                            if is_nucleus_mode {
                                // Nucleus: handle registration/heartbeat
                                if let Some(response) = signaling::handle_nucleus_message(
                                    &mut nucleus_state,
                                    &buf[..len],
                                    src,
                                ) {
                                    if let Err(e) = socket.send_to(&response, src).await {
                                        warn!("Failed to send signaling response: {}", e);
                                    }
                                }
                            } else if signaling::is_signaling_message(&buf[..len]) {
                                // Edge: received response from nucleus
                                let msg_type = signaling::get_signaling_type(&buf[..len]);
                                
                                match msg_type {
                                    Some(signaling::SIGNALING_REGISTER_ACK) => {
                                        // Registration confirmed with recent peers
                                        match signaling::parse_register_ack(&buf[..len]) {
                                            Ok(ack) => {
                                                info!("Registration confirmed, {} recent peers", ack.recent_peers.len());
                                                for peer_info in ack.recent_peers {
                                                    if let Ok(endpoint) = peer_info.endpoint.parse::<std::net::SocketAddr>() {
                                                        let session_id = session_manager.generate_session_id(endpoint.ip());
                                                        peer_table.register(
                                                            peer_info.public_key,
                                                            endpoint,
                                                            peer_info.vip,
                                                            session_id,
                                                        );
                                                        info!("Discovered peer {} at {}", peer_info.vip, endpoint);
                                                    }
                                                }
                                            }
                                            Err(e) => warn!("Failed to parse REGISTER_ACK: {}", e),
                                        }
                                    }
                                    Some(signaling::SIGNALING_HEARTBEAT_ACK) => {
                                        // Delta update: new peers and removed peers
                                        match signaling::parse_heartbeat_ack(&buf[..len]) {
                                            Ok(ack) => {
                                                // Add new peers
                                                for peer_info in ack.new_peers {
                                                    if let Ok(endpoint) = peer_info.endpoint.parse::<std::net::SocketAddr>() {
                                                        let session_id = session_manager.generate_session_id(endpoint.ip());
                                                        peer_table.register(
                                                            peer_info.public_key,
                                                            endpoint,
                                                            peer_info.vip,
                                                            session_id,
                                                        );
                                                        info!("New peer joined: {} at {}", peer_info.vip, endpoint);
                                                    }
                                                }
                                                // Handle removed peers
                                                for vip in ack.removed_vips {
                                                    peer_table.remove_by_vip(&vip);
                                                    info!("Peer left: {}", vip);
                                                }
                                            }
                                            Err(e) => warn!("Failed to parse HEARTBEAT_ACK: {}", e),
                                        }
                                    }
                                    Some(signaling::SIGNALING_PEER_INFO) => {
                                        // Response to QUERY_PEER
                                        match signaling::parse_peer_info(&buf[..len]) {
                                            Ok(info) => {
                                                if info.found {
                                                    if let Some(peer_info) = info.peer {
                                                        if let Ok(endpoint) = peer_info.endpoint.parse::<std::net::SocketAddr>() {
                                                            let session_id = session_manager.generate_session_id(endpoint.ip());
                                                            peer_table.register(
                                                                peer_info.public_key,
                                                                endpoint,
                                                                peer_info.vip,
                                                                session_id,
                                                            );
                                                            info!("Query result: {} at {}", peer_info.vip, endpoint);
                                                        }
                                                    }
                                                } else {
                                                    debug!("Peer not found in nucleus");
                                                }
                                            }
                                            Err(e) => warn!("Failed to parse PEER_INFO: {}", e),
                                        }
                                    }
                                    _ => {
                                        debug!("Unknown signaling message type");
                                    }
                                }
                            }
                            continue; // Skip normal packet processing for signaling
                        }
                        
                        info!("Received {} bytes from {}", len, src);
                        
                        // All data/handshake packets start with 8-byte session_id
                        if len >= 8 {
                            let session_id = u64::from_be_bytes([
                                buf[0], buf[1], buf[2], buf[3],
                                buf[4], buf[5], buf[6], buf[7]
                            ]);
                            
                            // Check session state to determine packet type
                            let session_state = session_manager.get_session_mut(session_id)
                                .map(|s| match s {
                                    SessionState::Handshaking(_) => "handshaking",
                                    SessionState::Active(_) => "active",
                                });
                            
                            match session_state {
                                Some("active") => {
                                    // DATA PACKET: decrypt and forward to TUN
                                    if let Some(SessionState::Active(transport)) = session_manager.get_session_mut(session_id) {
                                        let mut decrypted = vec![0u8; len - 8];
                                        match transport.read_message(session_id, &buf[8..len], &mut decrypted) {
                                            Ok(dec_len) => {
                                                // Write decrypted IP packet to TUN
                                                if let Some(ref mut tun) = _tun {
                                                    if let Err(e) = tun.write(&decrypted[..dec_len]).await {
                                                        error!("TUN write error: {}", e);
                                                    } else {
                                                        info!("UDP→TUN: {} bytes from session {}", dec_len, session_id);
                                                    }
                                                }
                                                
                                                // Update peer last_seen
                                                if let Some(peer) = peer_table.lookup_by_session(session_id) {
                                                    let vip = peer.virtual_ip;
                                                    peer_table.touch(&vip);
                                                }
                                            }
                                            Err(e) => {
                                                error!("Decryption failed: {}", e);
                                            }
                                        }
                                    }
                                }
                                Some("handshaking") => {
                                    // HANDSHAKE PACKET: advance handshake state
                                    let mut peer_vip_from_handshake: Option<std::net::Ipv4Addr> = None;
                                    
                                    match session_manager.advance_handshake(session_id, &buf[8..len]) {
                                        Ok(Some((response, peer_payload))) => {
                                            // Extract peer VIP from payload (first 4 bytes)
                                            if peer_payload.len() >= 4 {
                                                peer_vip_from_handshake = Some(std::net::Ipv4Addr::new(
                                                    peer_payload[0], peer_payload[1], 
                                                    peer_payload[2], peer_payload[3]
                                                ));
                                            }
                                            
                                            let mut reply = session_id.to_be_bytes().to_vec();
                                            reply.extend(response);
                                            if let Err(e) = socket.send_to(&reply, src).await {
                                                error!("Failed to send response: {}", e);
                                            }
                                        }
                                        Ok(None) => {
                                            warn!("Session {} not in handshaking state", session_id);
                                        }
                                        Err(e) => {
                                            error!("Handshake error: {}", e);
                                        }
                                    }

                                    // Try to finalize
                                    if let Ok(true) = session_manager.finalize_session(session_id) {
                                        // Sync to BPF map
                                        let key = [0u8; 32]; // TODO: Extract from transport state
                                        if let Err(e) = bpf_sync.insert_session(session_id, key, src.ip(), src.port()) {
                                            error!("BPF sync failed: {}", e);
                                        } else {
                                            metrics.inc_handshakes_completed();
                                            info!("Session {} finalized and synced to BPF!", session_id);
                                        }
                                        
                                        // Register peer with VIP from handshake (or fallback)
                                        let peer_vip = peer_vip_from_handshake.unwrap_or_else(|| {
                                            // Fallback: check if peer already exists in table (from signaling)
                                            if let Some(peer) = peer_table.lookup_by_session(session_id) {
                                                peer.virtual_ip
                                            } else {
                                                // Last resort: derive from session (not ideal)
                                                std::net::Ipv4Addr::new(10, 200, 0, ((session_id % 250) + 1) as u8)
                                            }
                                        });
                                        peer_table.upsert(peer_vip, session_id, src);
                                        info!("Registered peer: {} at {} (session {})", peer_vip, src, session_id);
                                    }
                                }
                                None => {
                                    // NEW SESSION: create responder and start handshake
                                    // Rate limiting check
                                    if !rate_limiter.allow_new_session(src.ip()) {
                                        metrics.inc_ratelimit_drops();
                                        warn!("Rate limited: {} (session {})", src.ip(), session_id);
                                        continue;
                                    }
                                    
                                    match NoiseSession::new_responder(&identity.private_key, psk.as_ref()) {
                                        Ok(new_session) => {
                                            session_manager.create_session(session_id, SessionState::Handshaking(new_session));
                                            rate_limiter.record_session_start(session_id);
                                            metrics.inc_sessions();
                                            info!("Created new session: {} from {}", session_id, src);
                                            
                                            // Process first handshake message
                                            let mut peer_vip_from_handshake: Option<std::net::Ipv4Addr> = None;
                                            
                                            match session_manager.advance_handshake(session_id, &buf[8..len]) {
                                                Ok(Some((response, peer_payload))) => {
                                                    if peer_payload.len() >= 4 {
                                                        peer_vip_from_handshake = Some(std::net::Ipv4Addr::new(
                                                            peer_payload[0], peer_payload[1], 
                                                            peer_payload[2], peer_payload[3]
                                                        ));
                                                    }
                                                    
                                                    let mut reply = session_id.to_be_bytes().to_vec();
                                                    reply.extend(response);
                                                    if let Err(e) = socket.send_to(&reply, src).await {
                                                        error!("Failed to send response: {}", e);
                                                    }
                                                }
                                                Ok(None) => {}
                                                Err(e) => {
                                                    error!("Handshake error: {}", e);
                                                }
                                            }
                                            
                                            // Try to finalize
                                            if let Ok(true) = session_manager.finalize_session(session_id) {
                                                let key = [0u8; 32];
                                                if let Err(e) = bpf_sync.insert_session(session_id, key, src.ip(), src.port()) {
                                                    error!("BPF sync failed: {}", e);
                                                } else {
                                                    metrics.inc_handshakes_completed();
                                                    info!("Session {} finalized!", session_id);
                                                }
                                                
                                                let peer_vip = peer_vip_from_handshake.unwrap_or_else(|| {
                                                    std::net::Ipv4Addr::new(10, 200, 0, ((session_id % 250) + 1) as u8)
                                                });
                                                peer_table.upsert(peer_vip, session_id, src);
                                                info!("Registered peer: {} at {} (session {})", peer_vip, src, session_id);
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to create session: {}", e);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        error!("Socket error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

