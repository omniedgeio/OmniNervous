// Allow dead_code for utility modules with functions ready for future use
#![allow(dead_code)]

use anyhow::{Context, Result};
mod identity;
mod metrics;
mod config;
mod http;
mod peers;
mod signaling;

mod wg;

use identity::Identity;
use metrics::Metrics;
use wg::WgControl;
use clap::Parser;
use log::{info, warn, error, debug};
use tokio::time::{interval, Duration};
use tokio::net::UdpSocket;
use tokio::signal;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

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
        - Native WireGuard data plane integration\n\
        - Cross-platform support\n\n\
        Examples:\n  \
          # Run as Nucleus (signaling server)\n  \
          omni-daemon --mode nucleus --port 51820\n\n  \
          # Run as Edge (P2P client)\n  \
          omni-daemon --nucleus 1.2.3.4:51820 --cluster mynet --secret MySecret123456 --vip 10.200.0.1"
)]
struct Args {
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
    
    /// Virtual IP address (e.g., 10.200.0.1)
    #[arg(long)]
    vip: Option<std::net::Ipv4Addr>,
    
    /// Virtual network mask
    #[arg(long, default_value = "255.255.255.0")]
    netmask: std::net::Ipv4Addr,
    
    /// Virtual interface name
    #[arg(long, default_value = "omni0")]
    tun_name: String,

    /// Encryption cipher: 'chachapoly' or 'aesgcm'
    #[arg(long, default_value = "chachapoly")]
    cipher: String,
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

    let _metrics = Metrics::new();
    let mut peer_table = peers::PeerTable::new();

    // Create WireGuard interface if VIP is specified
    let wg_api_opt = if let Some(vip) = args.vip {
        let ifname = args.tun_name.clone();
        let wg_control = WgControl::new(&ifname);
        
        info!("🔧 Initializing WireGuard interface '{}' with IP {}", ifname, vip);
        if let Err(e) = wg_control.setup_interface(
            &vip.to_string(), 
            args.port, 
            &BASE64.encode(identity.private_key_bytes())
        ) {
            warn!("⚠️ Failed to setup WireGuard interface via CLI: {}. Continuing in signaling-only mode.", e);
            None
        } else {
            info!("✅ WireGuard interface '{}' is ready.", ifname);
            Some(wg_control)
        }
    } else {
        info!("ℹ️ No --vip specified, running in signaling-only mode (Nucleus)");
        None
    };

    
    // Cleanup interval - runs every 60 seconds
    let mut cleanup_interval = interval(Duration::from_secs(60));
    // Heartbeat interval - runs every 30 seconds (for edge mode)
    let mut heartbeat_interval = interval(Duration::from_secs(30));

    // Determine mode: Nucleus (signaling server) or Edge (P2P client)
    let is_nucleus_mode = args.mode.as_ref().map(|m| m == "nucleus").unwrap_or(false);

    // Bind signaling socket
    // In Nucleus mode, we bind to the specified port.
    // In Edge mode, we bind to an ephemeral port (0) to avoid conflict with the kernel WireGuard interface
    // which also binds to args.port.
    let bind_port = if is_nucleus_mode { args.port } else { 0 };
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", bind_port)).await
        .context("failed to bind UDP socket")?;
    
    let local_addr = socket.local_addr()?;
    info!("Ganglion signaling listening on UDP/{} (Signaling)", local_addr.port());
    if !is_nucleus_mode {
        info!("WireGuard data plane will use UDP/{}", args.port);
    }
    
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
    let metrics_clone = _metrics.clone();
    tokio::spawn(async move {
        if let Err(e) = http::serve_metrics(metrics_clone, 9090).await {
            error!("Metrics server failed: {}", e);
        }
    });


    
    let mut buf = [0u8; 2048];
    
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            _ = cleanup_interval.tick() => {
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
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        _metrics.inc_packets_rx();
                        
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
                                                        peer_table.register(
                                                            peer_info.public_key,
                                                            endpoint,
                                                            peer_info.vip,
                                                        );
                                                        info!("Discovered peer {} at {}", peer_info.vip, endpoint);

                                                        // Configure WireGuard peer
                                                        if let Some(ref wg_api) = wg_api_opt {
                                                            let pubkey_b64 = BASE64.encode(&peer_info.public_key);
                                                            if let Err(e) = wg_api.set_peer(
                                                                &pubkey_b64,
                                                                Some(endpoint),
                                                                &[peer_info.vip.to_string()],
                                                                Some(25),
                                                            ) {
                                                                warn!("Failed to configure WG peer {}: {}", peer_info.vip, e);
                                                            } else {
                                                                info!("Configured WG peer {} at {}", peer_info.vip, peer_info.endpoint);
                                                            }
                                                        }
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
                                                        peer_table.register(
                                                            peer_info.public_key,
                                                            endpoint,
                                                            peer_info.vip,
                                                        );
                                                        info!("New peer joined: {} at {}", peer_info.vip, endpoint);

                                                        // Configure WireGuard peer
                                                        if let Some(ref wg_api) = wg_api_opt {
                                                            let pubkey_b64 = BASE64.encode(&peer_info.public_key);
                                                            if let Err(e) = wg_api.set_peer(
                                                                &pubkey_b64,
                                                                Some(endpoint),
                                                                &[peer_info.vip.to_string()],
                                                                Some(25),
                                                            ) {
                                                                warn!("Failed to configure WG peer {}: {}", peer_info.vip, e);
                                                            } else {
                                                                info!("Configured WG peer {} at {}", peer_info.vip, peer_info.endpoint);
                                                            }
                                                        }
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
                                                            peer_table.register(
                                                                peer_info.public_key,
                                                                endpoint,
                                                                peer_info.vip,
                                                            );
                                                            info!("Query result: {} at {}", peer_info.vip, endpoint);

                                                            // Configure WireGuard peer
                                                            if let Some(ref wg_api) = wg_api_opt {
                                                                let pubkey_b64 = BASE64.encode(&peer_info.public_key);
                                                                if let Err(e) = wg_api.set_peer(
                                                                    &pubkey_b64,
                                                                    Some(endpoint),
                                                                    &[peer_info.vip.to_string()],
                                                                    Some(25),
                                                                ) {
                                                                    warn!("Failed to configure WG peer {}: {}", peer_info.vip, e);
                                                                } else {
                                                                    info!("Configured WG peer {} at {}", peer_info.vip, peer_info.endpoint);
                                                                }
                                                            }
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

