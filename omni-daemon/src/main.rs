use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use clap::Parser;
use log::{info, error, warn};
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

use noise::NoiseSession;
use session::{SessionManager, SessionState};
use p2p::P2PDiscovery;
use fdb::Fdb;
use identity::Identity;
use ratelimit::{RateLimiter, RateLimitConfig};
use metrics::Metrics;
use config::Config;
use bpf_sync::BpfSync;

use std::time::Duration;
use tokio::time::interval;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "eth0")]
    iface: String,
    #[arg(short, long, default_value = "51820")]
    port: u16,
    #[arg(short, long)]
    mode: Option<String>,
    #[arg(short, long)]
    nucleus: Option<String>,
    #[arg(short, long)]
    cluster: Option<String>,
    #[arg(long, help = "Initialize new identity and exit")]
    init: bool,
    #[arg(long, help = "Path to identity directory")]
    identity: Option<std::path::PathBuf>,
    #[arg(long, short = 'C', help = "Path to config file")]
    config: Option<std::path::PathBuf>,
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

    let mut session_manager = SessionManager::new();
    let _fdb = Fdb::new();
    let mut p2p = P2PDiscovery::new(Some("stun.l.google.com:19302"))?;
    let mut rate_limiter = RateLimiter::new(RateLimitConfig::default());
    let metrics = Metrics::new();
    let mut bpf_sync = BpfSync::new();
    
    // Cleanup interval - runs every 60 seconds
    let mut cleanup_interval = interval(Duration::from_secs(60));

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", args.port)).await
        .context("failed to bind UDP socket")?;
    
    info!("Ganglion listening on UDP/{}", args.port);

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
    loop {
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
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        info!("Received {} bytes from {}", len, src);
                        metrics.inc_packets_rx();
                        
                        // For initial handshake, check if this is a new connection
                        // Client sends session_id in header, but we validate/generate our own
                        if len >= 4 {
                            let client_session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                            
                            // Generate secure session ID based on source IP
                            let session_id = session_manager.generate_session_id(src.ip());
                            
                            // Check if session exists, otherwise create a new one
                            if session_manager.get_session_mut(session_id).is_none() {
                                // Rate limiting check
                                if !rate_limiter.allow_new_session(src.ip()) {
                                    metrics.inc_ratelimit_drops();
                                    warn!("Rate limited: {} (session {})", src.ip(), session_id);
                                    continue;
                                }
                                
                                match NoiseSession::new_responder(&identity.private_key) {
                                    Ok(new_session) => {
                                        session_manager.create_session(session_id, SessionState::Handshaking(new_session));
                                        rate_limiter.record_session_start(session_id);
                                        metrics.inc_sessions();
                                        info!("Created new session: {} (client sent: {})", session_id, client_session_id);
                                    }
                                    Err(e) => {
                                        error!("Failed to create session: {}", e);
                                        continue;
                                    }
                                }
                            }

                            // Advance handshake
                            match session_manager.advance_handshake(session_id, &buf[4..len]) {
                                Ok(Some(response)) => {
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
