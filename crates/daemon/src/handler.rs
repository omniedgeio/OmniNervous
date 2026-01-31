use crate::metrics::Metrics;
use crate::peers::PeerTable;
use crate::relay::{self, RelayClient, RelayServer};
use crate::signaling::{self, NucleusClient, NucleusState};
use crate::wg::WgInterface;
use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Pending disco ping awaiting pong response
#[derive(Debug, Clone)]
pub struct PendingPing {
    /// Transaction ID
    pub tx_id: [u8; 12],
    /// Target endpoint
    pub target: SocketAddr,
    /// Target VIP
    pub target_vip: Ipv4Addr,
    /// When the ping was sent
    pub sent_at: Instant,
    /// Number of retries attempted
    pub retries: u32,
}

/// Result of a successful disco ping/pong exchange
#[derive(Debug, Clone)]
pub struct DiscoResult {
    /// Target VIP
    pub vip: Ipv4Addr,
    /// Confirmed endpoint
    pub endpoint: SocketAddr,
    /// Round-trip time
    pub rtt: Duration,
    /// Our address as observed by peer (for NAT hairpin detection)
    pub observed_addr: Option<SocketAddr>,
}

/// Configuration for disco probing
pub struct DiscoConfig {
    /// Timeout for each ping attempt
    pub ping_timeout: Duration,
    /// Number of retries before giving up
    pub max_retries: u32,
}

impl Default for DiscoConfig {
    fn default() -> Self {
        Self {
            ping_timeout: Duration::from_secs(5),
            max_retries: 3,
        }
    }
}

pub struct MessageHandler<'a> {
    pub socket: &'a UdpSocket,
    pub peer_table: &'a mut PeerTable,
    pub wg_api: Option<&'a mut WgInterface>,
    pub metrics: &'a Metrics,
    pub nucleus_state: &'a mut NucleusState,
    pub nucleus_client: Option<&'a NucleusClient>,
    pub is_nucleus_mode: bool,
    pub secret: Option<&'a str>,
    /// Our WireGuard public key (for disco messages)
    pub our_public_key: Option<[u8; 32]>,
    /// Our VIP (for disco messages)
    pub our_vip: Option<Ipv4Addr>,
    /// Pending disco pings awaiting responses
    pub pending_pings: HashMap<[u8; 12], PendingPing>,
    /// Disco configuration
    pub disco_config: DiscoConfig,
    /// Relay server (for nucleus mode)
    pub relay_server: Option<&'a mut RelayServer>,
    /// Relay client (for edge mode)
    pub relay_client: Option<&'a mut RelayClient>,
}

impl<'a> MessageHandler<'a> {
    pub async fn handle_packet(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        self.metrics.inc_packets_rx();

        if buf.is_empty() {
            return Ok(());
        }

        // Check for relay messages (0x20-0x24)
        if relay::is_relay_message(buf) {
            return self.handle_relay_message(buf, src).await;
        }

        // Signaling message types are 0x11-0x1F
        if buf[0] >= 0x11 {
            if self.is_nucleus_mode {
                self.handle_nucleus_signaling(buf, src).await?;
            } else if signaling::is_signaling_message(buf) {
                self.handle_edge_signaling(buf, src).await?;
            }
        }

        Ok(())
    }

    /// Handle relay protocol messages
    async fn handle_relay_message(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        let msg_type = buf[0];

        match msg_type {
            relay::MSG_RELAY_BIND => {
                // Only nucleus/relay server handles bind requests
                if let Some(relay_server) = self.relay_server.as_mut() {
                    match relay::parse_relay_bind(buf) {
                        Ok(request) => {
                            let mut ack = relay_server.allocate_session(&request, src)?;

                            // Fill in the relay endpoint (our listening address)
                            if ack.success {
                                if let Ok(local) = self.socket.local_addr() {
                                    ack.relay_endpoint = Some(local.to_string());
                                }
                            }

                            // Send acknowledgement
                            if let Ok(ack_data) = relay::encode_relay_bind_ack(&ack) {
                                if let Err(e) = self.socket.send_to(&ack_data, src).await {
                                    warn!("Failed to send RELAY_BIND_ACK: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse RELAY_BIND from {}: {}", src, e);
                        }
                    }
                }
            }

            relay::MSG_RELAY_BIND_ACK => {
                // Edge clients handle bind acknowledgements
                if let Some(relay_client) = self.relay_client.as_mut() {
                    match relay::parse_relay_bind_ack(buf) {
                        Ok(ack) => {
                            // Find which peer this ack is for
                            // (In a full implementation, we'd track pending requests)
                            if ack.success {
                                info!("Relay session established");
                            } else {
                                warn!("Relay bind failed: {:?}", ack.error);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse RELAY_BIND_ACK: {}", e);
                        }
                    }
                }
            }

            relay::MSG_RELAY_DATA => {
                // Forward relayed data
                if let Some(relay_server) = self.relay_server.as_mut() {
                    match relay::parse_relay_data(buf) {
                        Ok((session_id, wg_packet)) => {
                            // Determine destination and forward
                            if let Some(dest) =
                                relay_server.relay_packet(&session_id, src, wg_packet.len())
                            {
                                // Forward the packet (keep the relay header for the receiver)
                                if let Err(e) = self.socket.send_to(buf, dest).await {
                                    debug!("Failed to relay packet: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Failed to parse RELAY_DATA: {}", e);
                        }
                    }
                }
            }

            relay::MSG_RELAY_UNBIND => {
                if let Some(relay_server) = self.relay_server.as_mut() {
                    match relay::parse_relay_unbind(buf) {
                        Ok(session_id) => {
                            relay_server.release_session(&session_id);
                        }
                        Err(e) => {
                            debug!("Failed to parse RELAY_UNBIND: {}", e);
                        }
                    }
                }
            }

            relay::MSG_RELAY_KEEPALIVE => {
                // Just touch the session to prevent timeout
                debug!("Relay keepalive from {}", src);
            }

            _ => {
                debug!("Unknown relay message type: 0x{:02x}", msg_type);
            }
        }

        Ok(())
    }

    async fn handle_nucleus_signaling(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        if let Some(response) =
            signaling::handle_nucleus_message(self.nucleus_state, buf, src, self.secret)
        {
            if let Err(e) = self.socket.send_to(&response, src).await {
                warn!("Failed to send signaling response: {}", e);
            }
        }
        Ok(())
    }

    async fn handle_edge_signaling(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        let msg_type = signaling::get_signaling_type(buf);

        match msg_type {
            Some(signaling::SIGNALING_REGISTER_ACK) => self.process_register_ack(buf).await,
            Some(signaling::SIGNALING_HEARTBEAT_ACK) => self.process_heartbeat_ack(buf).await,
            Some(signaling::SIGNALING_PEER_INFO) => self.process_peer_info(buf).await,
            Some(signaling::SIGNALING_STUN_RESPONSE) => self.process_stun_response(buf).await,
            Some(signaling::SIGNALING_NAT_PUNCH) => {
                debug!("Received NAT punch from {}", src);
                Ok(())
            }
            Some(signaling::SIGNALING_DISCO_PING) => self.handle_disco_ping(buf, src).await,
            Some(signaling::SIGNALING_DISCO_PONG) => self.handle_disco_pong(buf, src).await,
            _ => {
                debug!("Unknown signaling message type");
                Ok(())
            }
        }
    }

    async fn process_register_ack(&mut self, buf: &[u8]) -> Result<()> {
        match signaling::parse_register_ack(buf, self.secret) {
            Ok(ack) => {
                info!(
                    "Registration confirmed, {} recent peers",
                    ack.recent_peers.len()
                );
                for peer_info in ack.recent_peers {
                    self.add_peer(peer_info).await;
                }
                Ok(())
            }
            Err(e) => {
                warn!("Failed to parse REGISTER_ACK: {}", e);
                Ok(())
            }
        }
    }

    async fn process_heartbeat_ack(&mut self, buf: &[u8]) -> Result<()> {
        match signaling::parse_heartbeat_ack(buf, self.secret) {
            Ok(ack) => {
                // Add new peers
                for peer_info in ack.new_peers {
                    self.add_peer(peer_info).await;
                }
                // Handle removed peers
                for vip in ack.removed_vips {
                    self.peer_table.remove_by_vip(&vip);
                    info!("Peer left: {}", vip);
                }
                Ok(())
            }
            Err(e) => {
                warn!("Failed to parse HEARTBEAT_ACK: {}", e);
                Ok(())
            }
        }
    }

    async fn process_peer_info(&mut self, buf: &[u8]) -> Result<()> {
        match signaling::parse_peer_info(buf, self.secret) {
            Ok(info) => {
                if info.found {
                    if let Some(peer_info) = info.peer {
                        self.add_peer(peer_info).await;
                    }
                } else {
                    debug!("Peer not found in nucleus");
                }
                Ok(())
            }
            Err(e) => {
                warn!("Failed to parse PEER_INFO: {}", e);
                Ok(())
            }
        }
    }

    async fn process_stun_response(&mut self, buf: &[u8]) -> Result<()> {
        match signaling::parse_stun_response(buf) {
            Ok(res) => {
                info!(
                    "Public endpoint discovered via Nucleus STUN: {}",
                    res.public_addr
                );
                // In a more complex implementation, we'd update our own endpoint state
                Ok(())
            }
            Err(e) => {
                warn!("Failed to parse STUN_RESPONSE: {}", e);
                Ok(())
            }
        }
    }

    async fn add_peer(&mut self, peer_info: signaling::PeerInfo) {
        if let Ok(endpoint) = peer_info.endpoint.parse::<std::net::SocketAddr>() {
            // Security: Validate VIP is in a reasonable range (e.g., 10.x.x.x or 172.16.x.x)
            // For now, we just log and ensure it's not a loopback or multicast address
            if peer_info.vip.is_loopback()
                || peer_info.vip.is_multicast()
                || peer_info.vip.is_unspecified()
            {
                warn!("Rejected peer with invalid VIP: {}", peer_info.vip);
                return;
            }

            if let Err(e) = self
                .peer_table
                .register(peer_info.public_key, endpoint, peer_info.vip)
            {
                warn!("Security alert for {}: {}", peer_info.vip, e);
                return;
            }
            info!("Discovered peer {} at {}", peer_info.vip, endpoint);

            // Configure WireGuard peer
            if let Some(wg_api) = self.wg_api.as_mut() {
                let pubkey_b64 = BASE64.encode(&peer_info.public_key);
                if let Err(e) = wg_api
                    .set_peer(
                        &pubkey_b64,
                        Some(endpoint),
                        &[peer_info.vip.to_string()],
                        Some(25),
                    )
                    .await
                {
                    warn!("Failed to configure WG peer {}: {}", peer_info.vip, e);
                } else {
                    info!(
                        "Successfully configured WG peer {} at {}",
                        peer_info.vip, peer_info.endpoint
                    );
                }
            }

            // Active UDP Hole Punching via Disco Ping:
            // Send a disco ping to the peer's endpoint from our signaling socket.
            // This helps open a mapping in our NAT for the peer's endpoint and
            // confirms bidirectional connectivity when we receive a pong.
            if let Err(e) = self.send_disco_ping(endpoint, peer_info.vip).await {
                debug!("Failed to send disco ping to {}: {}", endpoint, e);
                // Fall back to simple NAT punch
                let punch_packet = vec![signaling::SIGNALING_NAT_PUNCH];
                if let Err(e) = self.socket.send_to(&punch_packet, endpoint).await {
                    debug!("Failed to send NAT punch to {}: {}", endpoint, e);
                }
            } else {
                debug!("Disco ping sent to {} ({})", peer_info.vip, endpoint);
            }
        }
    }

    /// Handle incoming DISCO_PING message
    async fn handle_disco_ping(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        match signaling::parse_disco_ping(buf) {
            Ok(ping) => {
                info!(
                    "Received disco ping from {} (VIP: {}, tx: {:02x?})",
                    src,
                    ping.sender_vip,
                    &ping.tx_id[..4]
                );

                // Create pong response with the observed address
                let pong = signaling::DiscoPong {
                    tx_id: ping.tx_id,
                    observed_addr: src.to_string(),
                    responder_key: self.our_public_key.unwrap_or([0u8; 32]),
                };

                // Encode and send pong
                match signaling::encode_disco_pong(&pong) {
                    Ok(pong_data) => {
                        if let Err(e) = self.socket.send_to(&pong_data, src).await {
                            warn!("Failed to send disco pong to {}: {}", src, e);
                        } else {
                            debug!("Sent disco pong to {} (tx: {:02x?})", src, &pong.tx_id[..4]);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to encode disco pong: {}", e);
                    }
                }

                // Update peer endpoint if we know this peer by their public key
                // This handles endpoint migration (e.g., mobile device changing networks)
                if let Some(peer) = self.peer_table.find_by_public_key(&ping.sender_key) {
                    let current_endpoint = peer.endpoint;
                    if current_endpoint != src {
                        info!(
                            "Peer {} endpoint changed: {} -> {}",
                            ping.sender_vip, current_endpoint, src
                        );
                        // Update endpoint in peer table
                        if let Err(e) = self.peer_table.update_endpoint(&ping.sender_key, src) {
                            warn!("Failed to update peer endpoint: {}", e);
                        }

                        // Update WireGuard peer endpoint
                        if let Some(wg_api) = self.wg_api.as_mut() {
                            let pubkey_b64 = BASE64.encode(&ping.sender_key);
                            if let Err(e) = wg_api
                                .set_peer(
                                    &pubkey_b64,
                                    Some(src),
                                    &[ping.sender_vip.to_string()],
                                    Some(25),
                                )
                                .await
                            {
                                warn!("Failed to update WG peer endpoint: {}", e);
                            }
                        }
                    }
                }

                Ok(())
            }
            Err(e) => {
                warn!("Failed to parse DISCO_PING from {}: {}", src, e);
                Ok(())
            }
        }
    }

    /// Handle incoming DISCO_PONG message
    async fn handle_disco_pong(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        match signaling::parse_disco_pong(buf) {
            Ok(pong) => {
                // Look up the pending ping by transaction ID
                if let Some(pending) = self.pending_pings.remove(&pong.tx_id) {
                    let rtt = pending.sent_at.elapsed();
                    info!(
                        "Disco pong received from {} (VIP: {}, RTT: {:?}, observed: {})",
                        src, pending.target_vip, rtt, pong.observed_addr
                    );

                    // Parse our observed address for NAT hairpin detection
                    let observed_addr: Option<SocketAddr> = pong.observed_addr.parse().ok();

                    // Log the disco result
                    let result = DiscoResult {
                        vip: pending.target_vip,
                        endpoint: src,
                        rtt,
                        observed_addr,
                    };
                    debug!("Disco exchange successful: {:?}", result);

                    // Update peer endpoint if it changed (e.g., due to NAT rebinding)
                    if pending.target != src {
                        info!(
                            "Peer {} endpoint discovered via disco: {} -> {}",
                            pending.target_vip, pending.target, src
                        );

                        // Update endpoint in peer table
                        if let Err(e) = self.peer_table.update_endpoint(&pong.responder_key, src) {
                            debug!("Could not update peer endpoint: {}", e);
                        }

                        // Update WireGuard peer endpoint
                        if let Some(wg_api) = self.wg_api.as_mut() {
                            let pubkey_b64 = BASE64.encode(&pong.responder_key);
                            if let Err(e) = wg_api
                                .set_peer(
                                    &pubkey_b64,
                                    Some(src),
                                    &[pending.target_vip.to_string()],
                                    Some(25),
                                )
                                .await
                            {
                                warn!("Failed to update WG peer endpoint: {}", e);
                            }
                        }
                    }
                } else {
                    debug!(
                        "Received disco pong with unknown tx_id {:02x?} from {} (late/duplicate)",
                        &pong.tx_id[..4],
                        src
                    );
                }
                Ok(())
            }
            Err(e) => {
                warn!("Failed to parse DISCO_PONG from {}: {}", src, e);
                Ok(())
            }
        }
    }

    /// Send a DISCO_PING to a target endpoint
    pub async fn send_disco_ping(
        &mut self,
        target: SocketAddr,
        target_vip: Ipv4Addr,
    ) -> Result<()> {
        // Generate random transaction ID
        let tx_id: [u8; 12] = rand::random();

        // Create the ping message
        let ping = signaling::DiscoPing {
            tx_id,
            sender_key: self.our_public_key.unwrap_or([0u8; 32]),
            sender_vip: self.our_vip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        };

        // Encode and send
        let ping_data = signaling::encode_disco_ping(&ping)?;
        self.socket.send_to(&ping_data, target).await?;

        // Track the pending ping
        let pending = PendingPing {
            tx_id,
            target,
            target_vip,
            sent_at: Instant::now(),
            retries: 0,
        };
        self.pending_pings.insert(tx_id, pending);

        debug!(
            "Sent disco ping to {} ({}) tx: {:02x?}",
            target_vip,
            target,
            &tx_id[..4]
        );
        Ok(())
    }

    /// Clean up expired pending pings
    /// Returns list of VIPs that timed out (for potential retry or relay fallback)
    pub fn cleanup_expired_pings(&mut self) -> Vec<Ipv4Addr> {
        let timeout = self.disco_config.ping_timeout;
        let now = Instant::now();
        let mut timed_out = Vec::new();

        self.pending_pings.retain(|tx_id, pending| {
            if now.duration_since(pending.sent_at) > timeout {
                debug!(
                    "Disco ping to {} ({}) timed out (tx: {:02x?})",
                    pending.target_vip,
                    pending.target,
                    &tx_id[..4]
                );
                timed_out.push(pending.target_vip);
                false // Remove from map
            } else {
                true // Keep in map
            }
        });

        timed_out
    }

    /// Retry disco ping for a specific VIP (called after timeout)
    pub async fn retry_disco_ping(
        &mut self,
        target: SocketAddr,
        target_vip: Ipv4Addr,
    ) -> Result<bool> {
        // Check if we've exceeded max retries for this target
        let retry_count = self
            .pending_pings
            .values()
            .filter(|p| p.target_vip == target_vip)
            .map(|p| p.retries)
            .max()
            .unwrap_or(0);

        if retry_count >= self.disco_config.max_retries {
            info!(
                "Disco ping to {} exceeded max retries, connectivity failed",
                target_vip
            );
            return Ok(false);
        }

        // Send another ping
        self.send_disco_ping(target, target_vip).await?;

        // Update retry count for the new pending ping
        if let Some(pending) = self
            .pending_pings
            .values_mut()
            .find(|p| p.target_vip == target_vip)
        {
            pending.retries = retry_count + 1;
        }

        Ok(true)
    }

    /// Request relay allocation for a peer when direct connection fails
    pub async fn request_relay_for_peer(
        &mut self,
        target_key: [u8; 32],
        target_vip: Ipv4Addr,
    ) -> Result<bool> {
        let relay_client = match self.relay_client.as_mut() {
            Some(c) => c,
            None => {
                debug!("Relay not available, cannot fallback for {}", target_vip);
                return Ok(false);
            }
        };

        // Check if we already have an active relay for this peer
        if relay_client.is_relay_active(&target_key) {
            debug!("Relay already active for {}", target_vip);
            return Ok(true);
        }

        // Create and send bind request
        let request = relay_client.create_bind_request(target_key, target_vip);
        let bind_data = relay::encode_relay_bind(&request)?;
        let relay_endpoint = relay_client.relay_endpoint();

        self.socket.send_to(&bind_data, relay_endpoint).await?;

        info!(
            "Requested relay allocation for {} via {}",
            target_vip, relay_endpoint
        );

        Ok(true)
    }

    /// Check for peers that need relay fallback (disco timed out after max retries)
    pub async fn check_relay_fallback(&mut self) -> Result<Vec<Ipv4Addr>> {
        let timed_out = self.cleanup_expired_pings();
        let mut relay_requested = Vec::new();

        for vip in timed_out {
            // Find the peer info for this VIP
            if let Some(peer) = self.peer_table.lookup_by_vip(&vip) {
                if let Some(pubkey) = peer.public_key {
                    // Check retry count
                    let should_retry = self
                        .pending_pings
                        .values()
                        .filter(|p| p.target_vip == vip)
                        .map(|p| p.retries)
                        .max()
                        .map(|r| r < self.disco_config.max_retries)
                        .unwrap_or(true);

                    if should_retry {
                        // Retry disco ping
                        if let Err(e) = self.send_disco_ping(peer.endpoint, vip).await {
                            warn!("Failed to retry disco ping to {}: {}", vip, e);
                        }
                    } else {
                        // Max retries exceeded, request relay
                        if let Err(e) = self.request_relay_for_peer(pubkey, vip).await {
                            warn!("Failed to request relay for {}: {}", vip, e);
                        } else {
                            relay_requested.push(vip);
                        }
                    }
                }
            }
        }

        Ok(relay_requested)
    }
}
