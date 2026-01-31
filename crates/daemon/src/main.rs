use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::Parser;
use log::debug;
use log::{error, info, warn};
use omninervous::{
    config,
    handler::{DiscoConfig, MessageHandler},
    http,
    identity::Identity,
    metrics::Metrics,
    peers, signaling, stun,
    wg::{CliWgControl, UserspaceWgControl, WgInterface},
};
use serde_json;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::{interval, Duration};

fn load_config(args: &Args) -> config::Config {
    if let Some(path) = &args.config {
        config::Config::load(path).unwrap_or_else(|e| {
            warn!(
                "Failed to load config from {:?}: {}. Using defaults.",
                path, e
            );
            config::Config::default()
        })
    } else {
        config::Config::load_or_default()
    }
}

fn collect_stun_servers(args: &Args, config: &config::Config) -> Vec<String> {
    if !args.stun.is_empty() {
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
        // Built-in fallback from stun module
        stun::STUN_SERVERS.iter().map(|s| s.to_string()).collect()
    }
}

async fn setup_wireguard(args: &Args, identity: &Identity) -> Result<Option<WgInterface>> {
    if let Some(vip) = args.vip {
        let ifname = args.tun_name.clone();

        let mut wg_control = if args.userspace {
            WgInterface::Userspace(UserspaceWgControl::new(&ifname))
        } else {
            WgInterface::Cli(CliWgControl::new(&ifname))
        };

        info!(
            "🔧 Initializing WireGuard interface '{}' in {} mode with IP {}",
            ifname,
            if args.userspace {
                "USERSPACE"
            } else {
                "KERNEL"
            },
            vip
        );

        if let Err(e) = wg_control
            .setup_interface(
                &vip.to_string(),
                args.port,
                &BASE64.encode(identity.private_key_bytes()),
            )
            .await
        {
            warn!(
                "⚠️ Failed to setup WireGuard interface: {}. Continuing in signaling-only mode.",
                e
            );
            Ok(None)
        } else {
            info!("✅ WireGuard interface '{}' is ready.", ifname);
            Ok(Some(wg_control))
        }
    } else {
        Ok(None)
    }
}

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
async fn discover_public_endpoint_standard_stun(
    stun_servers: &[String],
) -> Result<std::net::SocketAddr> {
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

        if n >= 28 && response[0..2] == [0x01, 0x01] {
            // Binding Success Response
            if let Some(addr) = stun::parse_xor_mapped_address(&response[..n]) {
                info!("Public endpoint: {}", addr);
                return Ok(addr);
            }
        }
    }

    anyhow::bail!("All STUN servers failed")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::init();

    info!(
        "Starting OmniNervous Ganglion Daemon on port {}...",
        args.port
    );

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
    let config = load_config(&args);

    // Collect STUN servers
    let stun_servers = collect_stun_servers(&args, &config);

    let use_builtin_stun = if args.disable_builtin_stun {
        false
    } else {
        config.network.use_builtin_stun
    };

    // Determine mode: Nucleus (signaling server) or Edge (P2P client)
    let is_nucleus_mode = args.mode.as_ref().map(|m| m == "nucleus").unwrap_or(false);

    let cluster_secret = if let Some(ref s) = args.secret {
        if s.len() < 16 {
            anyhow::bail!("Cluster secret must be at least 16 characters for security");
        } else {
            Some(s)
        }
    } else {
        if is_nucleus_mode || args.cluster.is_some() {
            anyhow::bail!(
                "--secret is REQUIRED for security. Please provide a secret (min 16 chars)."
            );
        }
        None
    };

    #[cfg(target_os = "linux")]
    {
        if !args.userspace && args.vip.is_some() {
            let output = std::process::Command::new("id").arg("-u").output()?;
            let uid = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .unwrap_or(0);
            if uid != 0 {
                anyhow::bail!(
                    "Root/sudo privileges are REQUIRED for KERNEL mode WireGuard on Linux."
                );
            }
        }
    }

    let _metrics = Metrics::new();
    let mut peer_table = peers::PeerTable::new();

    // Cleanup interval - runs every cleanup_interval_secs
    let mut cleanup_interval = interval(config.timing.cleanup_interval());
    // Heartbeat interval - for edge mode peer state sync
    let mut heartbeat_interval = interval(config.timing.heartbeat_interval());
    // STUN interval - detect endpoint changes from NAT rebinding
    let mut stun_interval = interval(config.timing.stun_refresh());

    // Bind signaling socket first
    let bind_port = if is_nucleus_mode { args.port } else { 0 };
    let socket_raw = UdpSocket::bind(format!("0.0.0.0:{}", bind_port))
        .await
        .context("failed to bind UDP socket")?;

    let local_addr = socket_raw.local_addr()?;
    info!(
        "Ganglion signaling listening on UDP/{} (Signaling)",
        local_addr.port()
    );
    if !is_nucleus_mode {
        info!("WireGuard data plane will use UDP/{}", args.port);
    }
    let socket = std::sync::Arc::new(socket_raw);

    // Create WireGuard interface if VIP is specified
    let mut wg_api_opt = setup_wireguard(&args, &identity).await?;

    if let Some(mut wg) = wg_api_opt.clone() {
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            if let Err(e) = wg.start_loop(socket_clone).await {
                error!("Packet processing loop failed: {}", e);
            }
        });
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
                    cluster_secret.cloned(),
                )
                .await
                {
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
                                        info!(
                                            "✅ Public endpoint discovered via standard STUN: {}",
                                            addr
                                        );
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
            secret: cluster_secret.map(|s| s.as_str()),
            our_public_key: Some(identity.public_key_bytes()),
            our_vip: args.vip,
            pending_pings: std::collections::HashMap::new(),
            disco_config: DiscoConfig::default(),
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
                        let pkt = &buf[..len];
                        if pkt.is_empty() { continue; }

                        let first_byte = pkt[0];

                        if first_byte >= 0x11 {
                            // Signaling message
                            if let Err(e) = handler.handle_packet(pkt, src).await {
                                error!("Error handling signaling packet from {}: {}", src, e);
                            }
                        } else if first_byte >= 0x01 && first_byte <= 0x04 {
                            // WireGuard packet
                            if let Some(wg) = wg_api_opt.as_mut() {
                                if let Err(e) = wg.handle_incoming_packet(pkt, src, &socket).await {
                                    error!("Error handling WireGuard packet from {}: {}", src, e);
                                }
                            }
                        } else {
                            debug!("Ignored unknown packet type {} from {}", first_byte, src);
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
