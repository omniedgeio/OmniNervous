// Allow dead_code for utility modules with functions ready for future use
#![allow(dead_code)]

use anyhow::{Context, Result};
mod identity;
mod metrics;
mod config;
mod http;
mod peers;
mod signaling;
mod handler;
mod wg;
mod stun;

use handler::MessageHandler;

use identity::Identity;
use metrics::Metrics;
use wg::{WgInterface, CliWgControl, UserspaceWgControl};
use clap::Parser;
use log::{info, warn, error};
use tokio::time::{interval, Duration};
use tokio::net::UdpSocket;
use tokio::signal;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::sync::Arc;
use serde_json;
use log::debug;

#[derive(Parser, Debug)]
#[command(
    name = "omninervous",
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
          omninervous --mode nucleus --port 51820\n\n  \
          # Run as Edge (P2P client)\n  \
          omninervous --nucleus 1.2.3.4:51820 --cluster mynet --secret MySecret123456 --vip 10.200.0.1"
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

    /// Use userspace WireGuard implementation (cross-platform, no kernel modules)
    #[arg(long)]
    userspace: bool,
    
    /// Virtual IP address (e.g., 10.200.0.1)
    #[arg(long)]
    vip: Option<std::net::Ipv4Addr>,
    
    /// Virtual network mask
    #[arg(long, default_value = "255.255.255.0")]
    netmask: std::net::Ipv4Addr,
    
    /// Virtual interface name
    #[arg(long, default_value = "omni0")]
    tun_name: String,

    /// STUN servers for NAT discovery (repeatable, space-separated, or JSON array)
    #[arg(long, short = 's', action = clap::ArgAction::Append)]
    stun: Vec<String>,

    /// Disable built-in Nucleus STUN fallback
    #[arg(long)]
    disable_builtin_stun: bool,

}

/// Standard STUN Binding Request (minimal) - Try multiple servers and return first success
async fn discover_public_endpoint_standard_stun(stun_servers: &[String]) -> Result<std::net::SocketAddr> {
    use tokio::time::timeout;
    
    if stun_servers.is_empty() {
        anyhow::bail!("No STUN servers provided");
    }

    for stun_server in stun_servers {
        info!("Trying STUN server: {}", stun_server);
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if socket.connect(stun_server).await.is_err() {
            continue;
        }

        // Create a minimal STUN binding request
        let mut request = [0u8; 20];
        request[0..2].copy_from_slice(&[0x00, 0x01]); // Binding Request
        request[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
        // Transaction ID (random-ish)
        for i in 8..20 {
            request[i] = rand::random();
        }

        if socket.send(&request).await.is_err() {
            continue;
        }

        let mut response = [0u8; 1024];
        let n = match timeout(Duration::from_secs(3), socket.recv(&mut response)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };

        if n < 20 || (response[0] != 0x01 || response[1] != 0x01) {
            continue;
        }

        // Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
        let mut pos = 20;
        while pos + 4 <= n {
            let attr_type = u16::from_be_bytes([response[pos], response[pos+1]]);
            let attr_len = u16::from_be_bytes([response[pos+2], response[pos+3]]) as usize;
            pos += 4;
            
            if attr_type == 0x0001 { // MAPPED-ADDRESS
                if attr_len >= 8 {
                    let family = response[pos + 1];
                    let port = u16::from_be_bytes([response[pos+2], response[pos+3]]);
                    if family == 0x01 { // IPv4
                        let ip = std::net::Ipv4Addr::new(response[pos+4], response[pos+5], response[pos+6], response[pos+7]);
                        return Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port));
                    }
                }
            } else if attr_type == 0x0020 { // XOR-MAPPED-ADDRESS
                 if attr_len >= 8 {
                    let _family = response[pos + 1];
                    let x_port = u16::from_be_bytes([response[pos+2], response[pos+3]]);
                    let port = x_port ^ 0x2112; // XOR with magic cookie top 16 bits
                    let x_ip = [response[pos+4], response[pos+5], response[pos+6], response[pos+7]];
                    let cookie = [0x21, 0x12, 0xA4, 0x42];
                    let ip = std::net::Ipv4Addr::new(
                        x_ip[0] ^ cookie[0],
                        x_ip[1] ^ cookie[1],
                        x_ip[2] ^ cookie[2],
                        x_ip[3] ^ cookie[3],
                    );
                    return Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port));
                }
            }
            pos += attr_len;
            if attr_len % 4 != 0 {
                pos += 4 - (attr_len % 4);
            }
        }
    }

    anyhow::bail!("All STUN servers failed")
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

    // Load config
    let config = if let Some(path) = &args.config {
        config::Config::load(path).unwrap_or_else(|e| {
            warn!("Failed to load config from {:?}: {}. Using defaults.", path, e);
            config::Config::default()
        })
    } else {
        config::Config::load_or_default()
    };

    // Merge STUN servers: CLI takes priority if provided, otherwise config.
    // The --stun flag is intelligent and handles:
    // 1. Single values: -s stun.l.google.com:19302
    // 2. Space-separated: -s "stun1 stun2"
    // 3. JSON arrays: -s '["stun1", "stun2"]'
    // 4. Repeatable: -s server1 -s server2
    let mut stun_servers = if !args.stun.is_empty() {
        let mut list = Vec::new();
        for s in &args.stun {
            // Try JSON first, then space-separated
            match serde_json::from_str::<Vec<String>>(s) {
                Ok(json_list) => list.extend(json_list),
                Err(_) => {
                    for entry in s.split_whitespace() {
                        list.push(entry.to_string());
                    }
                }
            }
        }
        list
    } else if !config.network.stun_servers.is_empty() {
        config.network.stun_servers.clone()
    } else {
        stun::STUN_SERVERS.iter().map(|&s| s.to_string()).collect()
    };

    // Remove duplicates
    stun_servers.sort();
    stun_servers.dedup();

    let use_builtin_stun = if args.disable_builtin_stun {
        false
    } else {
        config.network.use_builtin_stun
    };

    let cluster_secret = if let Some(s) = args.secret {
        if s.len() < 16 {
            anyhow::bail!("Cluster secret must be at least 16 characters for security");
        } else {
            Some(s)
        }
    } else {
        None
    };

    let _metrics = Metrics::new();
    let mut peer_table = peers::PeerTable::new();

    // Create WireGuard interface if VIP is specified
    let wg_api_opt = if let Some(vip) = args.vip {
        let ifname = args.tun_name.clone();
        let wg_control: Box<dyn WgInterface> = if args.userspace {
            Box::new(UserspaceWgControl::new(&ifname))
        } else {
            Box::new(CliWgControl::new(&ifname))
        };
        
        info!("🔧 Initializing WireGuard interface '{}' with IP {}", ifname, vip);
        if let Err(e) = wg_control.setup_interface_sync(
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
    // STUN interval - runs every 5 minutes
    let mut stun_interval = interval(Duration::from_secs(300));

    // Determine mode: Nucleus (signaling server) or Edge (P2P client)
    let is_nucleus_mode = args.mode.as_ref().map(|m| m == "nucleus").unwrap_or(false);

    // Bind signaling socket
    // In Nucleus mode, we bind to the specified port.
    // In Edge mode, we bind to an ephemeral port (0) to avoid conflict with the kernel WireGuard interface
    // which also binds to args.port.
    let bind_port = if is_nucleus_mode { args.port } else { 0 };
    let socket_raw = UdpSocket::bind(format!("0.0.0.0:{}", bind_port)).await
        .context("failed to bind UDP socket")?;
    
    let local_addr = socket_raw.local_addr()?;
    info!("Ganglion signaling listening on UDP/{} (Signaling)", local_addr.port());
    if !is_nucleus_mode {
        info!("WireGuard data plane will use UDP/{}", args.port);
    }

    let socket = std::sync::Arc::new(socket_raw);
    
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
                    cluster_secret.clone(),
                ).await {
                    Ok(client) => {
                        // Register with nucleus immediately
                        if let Err(e) = client.register(&socket).await {
                            warn!("Failed to register with nucleus: {}", e);
                        }
                        
                        // Initial STUN discovery
                        let client_clone = client.clone();
                        let socket_task = Arc::clone(&socket);
                        let stun_list = stun_servers.clone();
                        
                        tokio::spawn(async move {
                            info!("🔍 Performing STUN discovery...");
                            let mut built_in_tried = false;

                            // 1. Try Nucleus built-in STUN first (Primary)
                            if use_builtin_stun {
                                debug!("Querying Nucleus for public endpoint...");
                                if let Err(e) = client_clone.query_stun(&socket_task).await {
                                    warn!("❌ Nucleus STUN query failed: {}", e);
                                } else {
                                    built_in_tried = true;
                                }
                            }

                            // 2. Fallback to public STUNs if provided
                            if !stun_list.is_empty() {
                                if built_in_tried {
                                    // Give Nucleus a moment to respond
                                    tokio::time::sleep(Duration::from_secs(2)).await;
                                }

                                match discover_public_endpoint_standard_stun(&stun_list).await {
                                    Ok(addr) => {
                                        info!("✅ Public endpoint discovered via standard STUN: {}", addr);
                                    }
                                    Err(e) => {
                                        warn!("❌ Public STUNs failed: {}", e);
                                    }
                                }
                            }
                        });
                        
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
        let mut handler = MessageHandler {
            socket: &socket,
            peer_table: &mut peer_table,
            wg_api: wg_api_opt.as_mut(),
            metrics: &_metrics,
            nucleus_state: &mut nucleus_state,
            nucleus_client: nucleus_client.as_ref(),
            is_nucleus_mode,
            secret: cluster_secret.as_deref(),
        };

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            _ = cleanup_interval.tick() => {
                if is_nucleus_mode {
                    nucleus_state.cleanup();
                }
            }
            _ = heartbeat_interval.tick() => {
                if let Some(ref client) = nucleus_client {
                    let peer_count = peer_table.len() as u32;
                    if let Err(e) = client.heartbeat(&socket, peer_count).await {
                        warn!("Failed to send heartbeat: {}", e);
                    }
                }
            }
            _ = stun_interval.tick() => {
                if let Some(ref client) = nucleus_client {
                    // Periodic STUN discovery
                    let client_clone = client.clone();
                    let socket_task = Arc::clone(&socket);
                    let stun_list = stun_servers.clone();
                    tokio::spawn(async move {
                        let mut built_in_tried = false;
                        if use_builtin_stun {
                            if let Err(e) = client_clone.query_stun(&socket_task).await {
                                debug!("Periodic Nucleus STUN failed: {}", e);
                            } else {
                                built_in_tried = true;
                            }
                        }

                        if !stun_list.is_empty() {
                            if built_in_tried {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                            let _ = discover_public_endpoint_standard_stun(&stun_list).await;
                        }
                    });
                }
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        if let Err(e) = handler.handle_packet(&buf[..len], src).await {
                            error!("Error handling packet from {}: {}", src, e);
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

