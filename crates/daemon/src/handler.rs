use anyhow::Result;
use log::{info, warn, debug};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use crate::peers::PeerTable;
use crate::signaling::{self, NucleusState, NucleusClient};
use crate::wg::WgInterface;
use crate::metrics::Metrics;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

pub struct MessageHandler<'a> {
    pub socket: &'a UdpSocket,
    pub peer_table: &'a mut PeerTable,
    pub wg_api: Option<&'a mut dyn WgInterface>,
    pub metrics: &'a Metrics,
    pub nucleus_state: &'a mut NucleusState,
    pub nucleus_client: Option<&'a NucleusClient>,
    pub is_nucleus_mode: bool,
    pub secret: Option<&'a str>,
}

impl<'a> MessageHandler<'a> {
    pub async fn handle_packet(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        self.metrics.inc_packets_rx();
        
        // Signaling message types are 0x01-0x0F
        if !buf.is_empty() && buf[0] < 0x10 {
            if self.is_nucleus_mode {
                self.handle_nucleus_signaling(buf, src).await?;
            } else if signaling::is_signaling_message(buf) {
                self.handle_edge_signaling(buf, src).await?;
            }
        }
        
        Ok(())
    }

    async fn handle_nucleus_signaling(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        if let Some(response) = signaling::handle_nucleus_message(
            self.nucleus_state,
            buf,
            src,
            self.secret,
        ) {
            if let Err(e) = self.socket.send_to(&response, src).await {
                warn!("Failed to send signaling response: {}", e);
            }
        }
        Ok(())
    }

    async fn handle_edge_signaling(&mut self, buf: &[u8], src: SocketAddr) -> Result<()> {
        let msg_type = signaling::get_signaling_type(buf);
        
        match msg_type {
            Some(signaling::SIGNALING_REGISTER_ACK) => {
                self.process_register_ack(buf).await
            }
            Some(signaling::SIGNALING_HEARTBEAT_ACK) => {
                self.process_heartbeat_ack(buf).await
            }
            Some(signaling::SIGNALING_PEER_INFO) => {
                self.process_peer_info(buf).await
            }
            Some(signaling::SIGNALING_STUN_RESPONSE) => {
                self.process_stun_response(buf).await
            }
            Some(signaling::SIGNALING_NAT_PUNCH) => {
                debug!("Received NAT punch from {}", src);
                Ok(())
            }
            _ => {
                debug!("Unknown signaling message type");
                Ok(())
            }
        }
    }

    async fn process_register_ack(&mut self, buf: &[u8]) -> Result<()> {
        match signaling::parse_register_ack(buf, self.secret) {
            Ok(ack) => {
                info!("Registration confirmed, {} recent peers", ack.recent_peers.len());
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
                info!("Public endpoint discovered via Nucleus STUN: {}", res.public_addr);
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
            if peer_info.vip.is_loopback() || peer_info.vip.is_multicast() || peer_info.vip.is_unspecified() {
                warn!("Rejected peer with invalid VIP: {}", peer_info.vip);
                return;
            }

            if let Err(e) = self.peer_table.register(
                peer_info.public_key,
                endpoint,
                peer_info.vip,
            ) {
                warn!("Security alert for {}: {}", peer_info.vip, e);
                return;
            }
            info!("Discovered peer {} at {}", peer_info.vip, endpoint);

            // Configure WireGuard peer
            if let Some(wg_api) = self.wg_api.as_mut() {
                let pubkey_b64 = BASE64.encode(&peer_info.public_key);
                if let Err(e) = wg_api.set_peer(
                    &pubkey_b64,
                    Some(endpoint),
                    &[peer_info.vip.to_string()],
                    Some(25),
                ) {
                    warn!("Failed to configure WG peer {}: {}", peer_info.vip, e);
                } else {
                    info!("Successfully configured WG peer {} at {}", peer_info.vip, peer_info.endpoint);
                }
            }

            // Active UDP Hole Punching:
            // Send a minimal packet to the peer's endpoint from our signaling socket.
            // This helps open a mapping in our NAT for the peer's endpoint.
            let punch_packet = vec![signaling::SIGNALING_NAT_PUNCH];
            if let Err(e) = self.socket.send_to(&punch_packet, endpoint).await {
                debug!("Failed to send NAT punch to {}: {}", endpoint, e);
            } else {
                debug!("NAT punch sent to {}", endpoint);
            }
        }
    }
}
