use crate::happy_eyeballs::{ConnectionRace, RaceAction, RaceResult};
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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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
    /// Race ID if this ping is part of a Happy Eyeballs race
    pub race_id: Option<Ipv4Addr>,
}

/// Active Happy Eyeballs connection race
#[derive(Debug)]
pub struct ActiveRace {
    /// The connection race state
    pub race: ConnectionRace,
    /// Target VIP
    pub target_vip: Ipv4Addr,
    /// Transaction IDs associated with this race (for both IPv4 and IPv6 pings)
    pub tx_ids: Vec<[u8; 12]>,
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
    /// Happy Eyeballs delay in milliseconds before fallback to IPv4
    pub happy_eyeballs_delay_ms: u64,
}

impl Default for DiscoConfig {
    fn default() -> Self {
        Self {
            ping_timeout: Duration::from_secs(5),
            max_retries: 3,
            happy_eyeballs_delay_ms: crate::happy_eyeballs::HAPPY_EYEBALLS_DELAY_MS,
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
    /// Our IPv6 VIP (for disco messages, dual-stack support)
    pub our_vip_v6: Option<Ipv6Addr>,
    /// Pending disco pings awaiting responses
    pub pending_pings: HashMap<[u8; 12], PendingPing>,
    /// Active Happy Eyeballs connection races (keyed by target VIP)
    pub pending_races: HashMap<Ipv4Addr, ActiveRace>,
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
                if let Some(_relay_client) = self.relay_client.as_mut() {
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
                // Handle removed peers (IPv4)
                for vip in ack.removed_vips {
                    self.peer_table.remove_by_vip(&vip);
                    info!("Peer left: {}", vip);
                }
                // Handle removed peers (IPv6)
                for vip_v6 in ack.removed_vips_v6 {
                    self.peer_table.remove_by_vip_v6(&vip_v6);
                    info!("Peer left (via IPv6): {}", vip_v6);
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

            // Validate IPv6 VIP if provided (must be in ULA range fd00::/8)
            if let Some(vip_v6) = peer_info.vip_v6 {
                let octets = vip_v6.octets();
                if octets[0] != 0xfd {
                    warn!(
                        "Rejected peer with invalid IPv6 VIP {} (not in ULA range fd00::/8)",
                        vip_v6
                    );
                    return;
                }
            }

            if let Err(e) = self.peer_table.register_with_v6(
                peer_info.public_key,
                endpoint,
                peer_info.vip,
                peer_info.vip_v6,
            ) {
                warn!("Security alert for {}: {}", peer_info.vip, e);
                return;
            }
            info!(
                "Discovered peer {} (v6: {:?}) at {}",
                peer_info.vip, peer_info.vip_v6, endpoint
            );

            // Configure WireGuard peer with both IPv4 and IPv6 allowed IPs
            if let Some(wg_api) = self.wg_api.as_mut() {
                let pubkey_b64 = BASE64.encode(peer_info.public_key);

                // Build allowed IPs list (IPv4 /32 + optional IPv6 /128)
                let mut allowed_ips = vec![format!("{}/32", peer_info.vip)];
                if let Some(vip_v6) = peer_info.vip_v6 {
                    allowed_ips.push(format!("{}/128", vip_v6));
                }

                if let Err(e) = wg_api
                    .set_peer(&pubkey_b64, Some(endpoint), &allowed_ips, Some(25))
                    .await
                {
                    warn!("Failed to configure WG peer {}: {}", peer_info.vip, e);
                } else {
                    info!(
                        "Successfully configured WG peer {} at {} (allowed IPs: {:?})",
                        peer_info.vip, peer_info.endpoint, allowed_ips
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
                    responder_vip_v6: self.our_vip_v6,
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
                            let pubkey_b64 = BASE64.encode(ping.sender_key);
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

                    // Check if this ping was part of a Happy Eyeballs race
                    let race_result: Option<RaceResult> = if let Some(race_vip) = pending.race_id {
                        if let Some(active_race) = self.pending_races.get_mut(&race_vip) {
                            let result = active_race.race.record_response(src);
                            if let Some(ref res) = result {
                                info!(
                                    "Happy Eyeballs race for {} complete: {} won in {:?}",
                                    race_vip,
                                    if res.ipv6_won { "IPv6" } else { "IPv4" },
                                    res.race_duration
                                );
                            }
                            result
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // Clean up completed race and cancel other pending pings in the race
                    if let Some(ref result) = race_result {
                        if let Some(active_race) = self.pending_races.remove(&pending.target_vip) {
                            // Remove other pending pings from this race
                            for tx_id in active_race.tx_ids {
                                if tx_id != pong.tx_id {
                                    if self.pending_pings.remove(&tx_id).is_some() {
                                        debug!(
                                            "Cancelled racing ping {:02x?} (race won by {})",
                                            &tx_id[..4],
                                            if result.ipv6_won { "IPv6" } else { "IPv4" }
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Parse our observed address for NAT hairpin detection
                    let observed_addr: Option<SocketAddr> = pong.observed_addr.parse().ok();

                    // Log the disco result
                    let disco_result = DiscoResult {
                        vip: pending.target_vip,
                        endpoint: src,
                        rtt,
                        observed_addr,
                    };
                    debug!("Disco exchange successful: {:?}", disco_result);

                    // Update peer endpoint if it changed (e.g., due to NAT rebinding or race winner)
                    if pending.target != src || race_result.is_some() {
                        info!(
                            "Peer {} endpoint discovered via disco: {} -> {}{}",
                            pending.target_vip,
                            pending.target,
                            src,
                            if race_result.as_ref().map(|r| r.ipv6_won).unwrap_or(false) {
                                " (IPv6 won race)"
                            } else if race_result.is_some() {
                                " (IPv4 won race)"
                            } else {
                                ""
                            }
                        );

                        // Update endpoint in peer table
                        if let Err(e) = self.peer_table.update_endpoint(&pong.responder_key, src) {
                            debug!("Could not update peer endpoint: {}", e);
                        }

                        // Update WireGuard peer endpoint
                        if let Some(wg_api) = self.wg_api.as_mut() {
                            let pubkey_b64 = BASE64.encode(pong.responder_key);
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
        self.send_disco_ping_internal(target, target_vip, None)
            .await?;
        Ok(())
    }

    /// Internal function to send disco ping with optional race tracking
    async fn send_disco_ping_internal(
        &mut self,
        target: SocketAddr,
        target_vip: Ipv4Addr,
        race_id: Option<Ipv4Addr>,
    ) -> Result<[u8; 12]> {
        // Generate random transaction ID
        let tx_id: [u8; 12] = rand::random();

        // Create the ping message
        let ping = signaling::DiscoPing {
            tx_id,
            sender_key: self.our_public_key.unwrap_or([0u8; 32]),
            sender_vip: self.our_vip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            sender_vip_v6: self.our_vip_v6,
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
            race_id,
        };
        self.pending_pings.insert(tx_id, pending);

        debug!(
            "Sent disco ping to {} ({}) tx: {:02x?}{}",
            target_vip,
            target,
            &tx_id[..4],
            if race_id.is_some() { " [racing]" } else { "" }
        );
        Ok(tx_id)
    }

    /// Send DISCO_PINGs using Happy Eyeballs algorithm (RFC 8305)
    ///
    /// Races IPv4 and IPv6 endpoints, preferring IPv6 with a 250ms head start.
    /// The first endpoint to respond wins and becomes the active endpoint.
    ///
    /// # Arguments
    /// * `target_v4` - Optional IPv4 endpoint
    /// * `target_v6` - Optional IPv6 endpoint
    /// * `target_vip` - Target's virtual IP (used as race identifier)
    ///
    /// # Returns
    /// * `Ok(RaceAction)` - The initial action taken (ProbeV6/ProbeV4/NoAddresses)
    pub async fn send_disco_ping_with_race(
        &mut self,
        target_v4: Option<SocketAddr>,
        target_v6: Option<SocketAddr>,
        target_vip: Ipv4Addr,
    ) -> Result<RaceAction> {
        // Check if a race is already in progress for this peer
        if self.pending_races.contains_key(&target_vip) {
            debug!("Race already in progress for {}, skipping", target_vip);
            return Ok(RaceAction::RaceOver);
        }

        // Create new connection race with configured delay
        let mut race = ConnectionRace::with_delay(
            target_v4,
            target_v6,
            self.disco_config.happy_eyeballs_delay_ms,
        );
        let action = race.next_action();

        // Send probe based on race action
        let tx_id = match &action {
            RaceAction::ProbeV6(addr) => {
                info!(
                    "Happy Eyeballs: starting race for {} with IPv6 {}",
                    target_vip, addr
                );
                Some(
                    self.send_disco_ping_internal(*addr, target_vip, Some(target_vip))
                        .await?,
                )
            }
            RaceAction::ProbeV4(addr) => {
                info!(
                    "Happy Eyeballs: starting race for {} with IPv4 (no IPv6 available)",
                    target_vip
                );
                Some(
                    self.send_disco_ping_internal(*addr, target_vip, Some(target_vip))
                        .await?,
                )
            }
            RaceAction::NoAddresses => {
                warn!("Happy Eyeballs: no addresses for {}", target_vip);
                None
            }
            _ => None,
        };

        // Store the active race
        if let Some(tx_id) = tx_id {
            let active_race = ActiveRace {
                race,
                target_vip,
                tx_ids: vec![tx_id],
            };
            self.pending_races.insert(target_vip, active_race);
        }

        Ok(action)
    }

    /// Check and advance pending races (call periodically, e.g., every 50-100ms)
    ///
    /// This checks if any races have elapsed their IPv6 delay and need to start
    /// the IPv4 fallback probe.
    ///
    /// # Returns
    /// List of (VIP, SocketAddr) pairs for IPv4 fallback probes that were sent
    pub async fn advance_pending_races(&mut self) -> Vec<(Ipv4Addr, SocketAddr)> {
        let mut fallbacks_sent = Vec::new();

        // First pass: collect VIPs and addresses that need fallback, advance race state
        let mut fallback_targets: Vec<(Ipv4Addr, SocketAddr)> = Vec::new();
        for (vip, active_race) in self.pending_races.iter_mut() {
            if active_race.race.should_start_fallback() {
                let action = active_race.race.next_action();
                if let RaceAction::ProbeV4(addr) = action {
                    fallback_targets.push((*vip, addr));
                }
            }
        }

        // Second pass: send pings and update race tx_ids
        for (vip, addr) in fallback_targets {
            info!(
                "Happy Eyeballs: IPv6 delay elapsed for {}, starting IPv4 fallback to {}",
                vip, addr
            );

            // Generate transaction ID and send ping inline
            let tx_id: [u8; 12] = rand::random();
            let ping = signaling::DiscoPing {
                tx_id,
                sender_key: self.our_public_key.unwrap_or([0u8; 32]),
                sender_vip: self.our_vip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                sender_vip_v6: self.our_vip_v6,
            };

            match signaling::encode_disco_ping(&ping) {
                Ok(ping_data) => {
                    match self.socket.send_to(&ping_data, addr).await {
                        Ok(_) => {
                            // Track the pending ping
                            let pending = PendingPing {
                                tx_id,
                                target: addr,
                                target_vip: vip,
                                sent_at: Instant::now(),
                                retries: 0,
                                race_id: Some(vip),
                            };
                            self.pending_pings.insert(tx_id, pending);

                            // Update race with new tx_id
                            if let Some(race) = self.pending_races.get_mut(&vip) {
                                race.tx_ids.push(tx_id);
                            }

                            debug!(
                                "Sent disco ping to {} ({}) tx: {:02x?} [racing fallback]",
                                vip,
                                addr,
                                &tx_id[..4]
                            );
                            fallbacks_sent.push((vip, addr));
                        }
                        Err(e) => {
                            warn!("Failed to send IPv4 fallback ping for {}: {}", vip, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to encode IPv4 fallback ping for {}: {}", vip, e);
                }
            }
        }

        fallbacks_sent
    }

    /// Clean up expired races (races that took too long without any response)
    ///
    /// # Arguments
    /// * `timeout` - Maximum race duration before cleanup
    ///
    /// # Returns
    /// List of VIPs whose races timed out
    pub fn cleanup_expired_races(&mut self, timeout: Duration) -> Vec<Ipv4Addr> {
        let mut expired = Vec::new();

        self.pending_races.retain(|vip, race| {
            if race.race.elapsed() > timeout {
                debug!(
                    "Happy Eyeballs race for {} expired after {:?}",
                    vip,
                    race.race.elapsed()
                );
                race.race.mark_failed();
                expired.push(*vip);
                false
            } else {
                true
            }
        });

        // Also clean up pending pings that were part of expired races
        for vip in &expired {
            self.pending_pings
                .retain(|_, ping| ping.race_id.as_ref() != Some(vip));
        }

        expired
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
