use crate::config::L2Config;
use crate::metrics::Metrics;
use anyhow::{Context, Result};
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tun::Layer;

pub const L2_ENVELOPE: u8 = 0x05;
const L2_MSG_TYPE: u8 = 0x30;
const L2_VERSION: u8 = 1;
const HEADER_SIZE: usize = 1 + 1 + 32 + 32 + 8 + 2 + 2 + 2;
const MAX_UDP_PAYLOAD: usize = 1200;
const TAP_READ_BUFFER: usize = 4096;
const L2_MAX_MTU: u16 = 2000;
const L2_MIN_MTU: u16 = 576;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L2Header {
    pub version: u8,
    pub msg_type: u8,
    pub src_key: [u8; 32],
    pub dst_key: [u8; 32],
    pub frame_id: u64,
    pub frag_index: u16,
    pub frag_count: u16,
    pub payload_len: u16,
}

#[derive(Clone, Debug)]
pub struct L2Packet {
    pub header: L2Header,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L2FrameStats {
    pub frames_tx: u64,
    pub frames_rx: u64,
    pub fragments_tx: u64,
    pub fragments_rx: u64,
    pub reassembly_timeouts: u64,
    pub reassembly_drops: u64,
}

#[derive(Debug, Clone)]
pub struct L2ConfigSnapshot {
    pub mode: String,
    pub tap_name: String,
    pub mtu: u16,
    pub reassembly_timeout: Duration,
    pub max_frames_per_peer: usize,
    pub max_buffer_bytes: usize,
    pub max_total_buffer_bytes: usize,
}

impl From<&L2Config> for L2ConfigSnapshot {
    fn from(cfg: &L2Config) -> Self {
        Self {
            mode: cfg.mode.clone(),
            tap_name: cfg.tap_name.clone(),
            mtu: cfg.mtu,
            reassembly_timeout: Duration::from_millis(cfg.reassembly_timeout_ms),
            max_frames_per_peer: cfg.max_frames_per_peer,
            max_buffer_bytes: cfg.max_buffer_bytes,
            max_total_buffer_bytes: cfg.max_total_buffer_bytes,
        }
    }
}

struct ReassemblyBuffer {
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
    total_len: usize,
    created_at: Instant,
}

impl ReassemblyBuffer {
    fn new(frag_count: usize) -> Self {
        Self {
            fragments: vec![None; frag_count],
            received: 0,
            total_len: 0,
            created_at: Instant::now(),
        }
    }
}

pub struct L2FrameHandler {
    public_key: PublicKey,
    salsa_box: SalsaBox,
    frame_id: u64,
    reassembly: HashMap<[u8; 32], HashMap<u64, ReassemblyBuffer>>,
    per_peer_bytes: HashMap<[u8; 32], usize>,
    total_buffer_bytes: usize,
    stats: L2FrameStats,
    config: L2ConfigSnapshot,
    metrics: Arc<Metrics>,
}

impl L2FrameHandler {
    pub fn new(secret_key: [u8; 32], config: L2ConfigSnapshot, metrics: Arc<Metrics>) -> Self {
        let secret_key = SecretKey::from(secret_key);
        let public_key = secret_key.public_key();
        let salsa_box = SalsaBox::new(&public_key, &secret_key);
        Self {
            public_key,
            salsa_box,
            frame_id: 1,
            reassembly: HashMap::new(),
            per_peer_bytes: HashMap::new(),
            total_buffer_bytes: 0,
            stats: L2FrameStats::default(),
            config,
            metrics,
        }
    }

    pub fn encrypt_packet(&mut self, packet: &L2Packet) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + packet.payload.len());
        let header = &packet.header;
        buf.push(header.version);
        buf.push(header.msg_type);
        buf.extend_from_slice(&header.src_key);
        buf.extend_from_slice(&header.dst_key);
        buf.extend_from_slice(&header.frame_id.to_be_bytes());
        buf.extend_from_slice(&header.frag_index.to_be_bytes());
        buf.extend_from_slice(&header.frag_count.to_be_bytes());
        buf.extend_from_slice(&header.payload_len.to_be_bytes());
        buf.extend_from_slice(&packet.payload);

        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let ciphertext = self
            .salsa_box
            .encrypt(&nonce, buf.as_slice())
            .map_err(|e| anyhow::anyhow!("L2 encryption failed: {}", e))?;

        let mut out = Vec::with_capacity(1 + 1 + 32 + 24 + ciphertext.len());
        out.push(L2_ENVELOPE);
        out.push(L2_VERSION);
        out.extend_from_slice(self.public_key.as_bytes());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_packet(&mut self, data: &[u8]) -> Result<L2Packet> {
        if data.len() < 2 + 32 + 24 {
            anyhow::bail!("L2 ciphertext too small");
        }
        if data[0] != L2_ENVELOPE {
            anyhow::bail!("L2 envelope mismatch");
        }
        if data[1] != L2_VERSION {
            anyhow::bail!("L2 version mismatch");
        }
        let sender_key: [u8; 32] = data[2..34].try_into().context("sender_key")?;
        let nonce = crypto_box::Nonce::from_slice(&data[34..58]);
        let ciphertext = &data[58..];
        if sender_key == [0u8; 32] {
            anyhow::bail!("L2 sender key missing");
        }
        let plaintext = self
            .salsa_box
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("L2 decryption failed: {}", e))?;
        if plaintext.len() < HEADER_SIZE {
            anyhow::bail!("L2 packet too small");
        }
        let header = L2Header {
            version: plaintext[0],
            msg_type: plaintext[1],
            src_key: plaintext[2..34].try_into().context("src_key")?,
            dst_key: plaintext[34..66].try_into().context("dst_key")?,
            frame_id: u64::from_be_bytes(plaintext[66..74].try_into().context("frame_id")?),
            frag_index: u16::from_be_bytes(plaintext[74..76].try_into().context("frag_index")?),
            frag_count: u16::from_be_bytes(plaintext[76..78].try_into().context("frag_count")?),
            payload_len: u16::from_be_bytes(plaintext[78..80].try_into().context("payload_len")?),
        };
        if header.version != L2_VERSION || header.msg_type != L2_MSG_TYPE {
            anyhow::bail!("Invalid L2 header");
        }
        if header.src_key == [0u8; 32] || header.dst_key == [0u8; 32] {
            anyhow::bail!("L2 header keys missing");
        }
        let expected = header.payload_len as usize;
        let payload = plaintext[HEADER_SIZE..].to_vec();
        if payload.len() != expected {
            anyhow::bail!("L2 payload length mismatch");
        }
        Ok(L2Packet { header, payload })
    }

    pub fn fragment_frame(
        &mut self,
        src_key: [u8; 32],
        dst_key: [u8; 32],
        frame: &[u8],
    ) -> Vec<L2Packet> {
        let mtu = self.config.mtu as usize;
        let max_payload = mtu.saturating_sub(HEADER_SIZE).min(MAX_UDP_PAYLOAD);
        if max_payload == 0 {
            return Vec::new();
        }
        let mut packets = Vec::new();
        let total_len = frame.len();
        let frag_count = ((total_len + max_payload - 1) / max_payload).max(1) as u16;
        let frame_id = self.frame_id;
        self.frame_id = self.frame_id.wrapping_add(1);
        for (idx, chunk) in frame.chunks(max_payload).enumerate() {
            let packet = L2Packet {
                header: L2Header {
                    version: L2_VERSION,
                    msg_type: L2_MSG_TYPE,
                    src_key,
                    dst_key,
                    frame_id,
                    frag_index: idx as u16,
                    frag_count,
                    payload_len: chunk.len() as u16,
                },
                payload: chunk.to_vec(),
            };
            packets.push(packet);
        }
        packets
    }

    pub fn handle_fragment(&mut self, packet: L2Packet) -> Option<Vec<u8>> {
        let peer_key = packet.header.src_key;
        let frame_id = packet.header.frame_id;
        let frag_count = packet.header.frag_count as usize;
        let frag_index = packet.header.frag_index as usize;
        if frag_count == 0 || frag_index >= frag_count {
            self.stats.reassembly_drops += 1;
            self.metrics.add_l2_reassembly_drops(1);
            return None;
        }

        if frag_count > self.config.max_frames_per_peer {
            self.stats.reassembly_drops += 1;
            self.metrics.add_l2_reassembly_drops(1);
            return None;
        }

        let peer_buffers = self.reassembly.entry(peer_key).or_default();
        if !peer_buffers.contains_key(&frame_id)
            && peer_buffers.len() >= self.config.max_frames_per_peer
        {
            self.stats.reassembly_drops += 1;
            self.metrics.add_l2_reassembly_drops(1);
            return None;
        }
        let buffer = peer_buffers
            .entry(frame_id)
            .or_insert_with(|| ReassemblyBuffer::new(frag_count));

        if buffer.fragments.len() != frag_count {
            self.stats.reassembly_drops += 1;
            self.metrics.add_l2_reassembly_drops(1);
            peer_buffers.remove(&frame_id);
            return None;
        }

        if buffer.fragments[frag_index].is_none() {
            buffer.fragments[frag_index] = Some(packet.payload.clone());
            buffer.received += 1;
            buffer.total_len += packet.payload.len();
            self.stats.fragments_rx += 1;
            self.metrics.add_l2_fragments_rx(1);
            let peer_bytes = self.per_peer_bytes.entry(peer_key).or_insert(0);
            *peer_bytes += packet.payload.len();
            self.total_buffer_bytes += packet.payload.len();
            if self.total_buffer_bytes > self.config.max_total_buffer_bytes
                || *peer_bytes > self.config.max_buffer_bytes
            {
                self.stats.reassembly_drops += 1;
                self.metrics.add_l2_reassembly_drops(1);
                self.cleanup_frame(peer_key, frame_id, buffer.total_len);
                return None;
            }
            self.enforce_limits(peer_key);
        }

        if buffer.received == frag_count {
            let mut frame = Vec::with_capacity(buffer.total_len);
            for frag in buffer.fragments.iter_mut() {
                if let Some(data) = frag.take() {
                    frame.extend_from_slice(&data);
                }
            }
            self.cleanup_frame(peer_key, frame_id, buffer.total_len);
            self.stats.frames_rx += 1;
            self.metrics.add_l2_frames_rx(1);
            return Some(frame);
        }

        None
    }

    pub fn cleanup_expired(&mut self) {
        let timeout = self.config.reassembly_timeout;
        let now = Instant::now();
        let mut expired = Vec::new();
        for (peer, buffers) in self.reassembly.iter() {
            for (frame_id, buffer) in buffers.iter() {
                if now.duration_since(buffer.created_at) > timeout {
                    expired.push((*peer, *frame_id, buffer.total_len));
                }
            }
        }
        for (peer, frame_id, bytes) in expired {
            self.cleanup_frame(peer, frame_id, bytes);
            self.stats.reassembly_timeouts += 1;
            self.metrics.add_l2_reassembly_timeouts(1);
        }
    }

    fn cleanup_frame(&mut self, peer: [u8; 32], frame_id: u64, bytes: usize) {
        if let Some(buffers) = self.reassembly.get_mut(&peer) {
            buffers.remove(&frame_id);
            if buffers.is_empty() {
                self.reassembly.remove(&peer);
            }
        }
        if let Some(peer_bytes) = self.per_peer_bytes.get_mut(&peer) {
            *peer_bytes = peer_bytes.saturating_sub(bytes);
        }
        self.total_buffer_bytes = self.total_buffer_bytes.saturating_sub(bytes);
    }

    pub fn enforce_limits(&mut self, peer: [u8; 32]) {
        if let Some(peer_bytes) = self.per_peer_bytes.get(&peer) {
            if *peer_bytes > self.config.max_buffer_bytes {
                warn!("L2 buffer limit exceeded for peer {}", hex::encode(peer));
            }
        }
        if self.total_buffer_bytes > self.config.max_total_buffer_bytes {
            warn!("L2 total buffer limit exceeded");
        }
    }
}

pub struct L2Transport {
    device: tun::AsyncDevice,
    socket: std::sync::Arc<UdpSocket>,
    handler: std::sync::Arc<Mutex<L2FrameHandler>>,
    writer: Arc<Mutex<tun::AsyncDevice>>,
    local_key: [u8; 32],
}

impl L2Transport {
    pub async fn new(
        config: &L2Config,
        socket: std::sync::Arc<UdpSocket>,
        local_key: [u8; 32],
        secret_key: [u8; 32],
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let mut tun_config = tun::Configuration::default();
        tun_config.layer(Layer::L2);
        let mtu = config.mtu.clamp(L2_MIN_MTU, L2_MAX_MTU);
        tun_config.mtu(mtu as i32);
        if !config.tap_name.is_empty() {
            tun_config.name(&config.tap_name);
        }
        tun_config.up();

        let device = tun::create_as_async(&tun_config).context("Failed to create TAP device")?;

        info!("L2 TAP device '{}' created (mtu={})", config.tap_name, mtu);

        let writer = Arc::new(Mutex::new(device.clone()));

        Ok(Self {
            device,
            socket,
            handler: std::sync::Arc::new(Mutex::new(L2FrameHandler::new(
                secret_key,
                L2ConfigSnapshot::from(config),
                metrics,
            ))),
            writer,
            local_key,
        })
    }

    pub async fn start(&mut self, peer_table: Arc<Mutex<crate::peers::PeerTable>>) -> Result<()> {
        let mut reader = self.device.clone();
        let socket_tx = self.socket.clone();
        let handler_tx = self.handler.clone();
        let local_key = self.local_key;

        tokio::spawn(async move {
            let mut buf = vec![0u8; TAP_READ_BUFFER];
            loop {
                match reader.read(&mut buf).await {
                    Ok(len) => {
                        let frame = &buf[..len];
                        let peers = peer_table.lock().await;
                        for peer in peers.iter() {
                            if let Some(pubkey) = peer.public_key {
                                let packets = {
                                    let mut handler = handler_tx.lock().await;
                                    handler.fragment_frame(local_key, pubkey, frame)
                                };
                                if packets.is_empty() {
                                    continue;
                                }
                                let total_packets = packets.len();
                                for (idx, packet) in packets.iter().enumerate() {
                                    let encrypted = {
                                        let mut handler = handler_tx.lock().await;
                                        if idx == 0 {
                                            handler.stats.frames_tx += 1;
                                            handler.stats.fragments_tx += total_packets as u64;
                                            handler.metrics.add_l2_frames_tx(1);
                                            handler
                                                .metrics
                                                .add_l2_fragments_tx(total_packets as u64);
                                        }
                                        handler.encrypt_packet(packet)
                                    };
                                    if let Ok(data) = encrypted {
                                        if let Err(e) =
                                            socket_tx.send_to(&data, peer.endpoint).await
                                        {
                                            debug!("Failed to send L2 packet: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("L2 TAP read error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn handle_udp_packet(&self, buf: &[u8]) -> Result<()> {
        let mut handler = self.handler.lock().await;
        if let Ok(packet) = handler.decrypt_packet(buf) {
            if let Some(frame) = handler.handle_fragment(packet) {
                let mut writer = self.writer.lock().await;
                writer.write_all(&frame).await?;
            }
            handler.cleanup_expired();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::L2Config;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_fragment_and_reassemble() {
        let config = L2ConfigSnapshot::from(&L2Config::default());
        let metrics = Metrics::new();
        let mut handler = L2FrameHandler::new([1u8; 32], config, metrics.clone());
        let src_key = [2u8; 32];
        let dst_key = [3u8; 32];
        let frame = vec![0xAB; 3000];

        let packets = handler.fragment_frame(src_key, dst_key, &frame);
        assert!(packets.len() > 1);

        let mut reassembled = None;
        for packet in packets {
            let out = handler.handle_fragment(packet);
            if out.is_some() {
                reassembled = out;
            }
        }

        let reassembled = reassembled.expect("expected reassembled frame");
        assert_eq!(reassembled, frame);
        assert_eq!(metrics.l2_frames_rx_total.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.l2_fragments_rx_total.load(Ordering::Relaxed),
            handler.stats.fragments_rx
        );
    }

    #[test]
    fn test_reassembly_timeout_records_metric() {
        let mut config = L2ConfigSnapshot::from(&L2Config::default());
        config.reassembly_timeout = Duration::from_millis(0);
        let metrics = Metrics::new();
        let mut handler = L2FrameHandler::new([4u8; 32], config, metrics.clone());
        let src_key = [5u8; 32];
        let dst_key = [6u8; 32];
        let frame = vec![0xCD; 1024];

        let packets = handler.fragment_frame(src_key, dst_key, &frame);
        let first = packets.into_iter().next().expect("packet");
        handler.handle_fragment(first);
        handler.cleanup_expired();

        assert_eq!(
            metrics.l2_reassembly_timeouts_total.load(Ordering::Relaxed),
            1
        );
    }
}
