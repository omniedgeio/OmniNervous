#![no_std]

use bytemuck::{Pod, Zeroable};

/// Wire protocol header with 64-bit session ID and sequence number
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct PacketHeader {
    pub session_id: u64,
    pub sequence: u64,
    pub nonce: [u8; 8],
}

/// Session key for BPF HashMap compatibility (aya requires Pod trait)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct SessionKey {
    pub id_high: u32,
    pub id_low: u32,
}

impl SessionKey {
    pub const fn from_u64(id: u64) -> Self {
        SessionKey {
            id_high: (id >> 32) as u32,
            id_low: id as u32,
        }
    }

    pub const fn to_u64(self) -> u64 {
        ((self.id_high as u64) << 32) | (self.id_low as u64)
    }
}

impl From<u64> for SessionKey {
    fn from(id: u64) -> Self {
        Self::from_u64(id)
    }
}

/// Session entry stored in BPF map with replay protection
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct SessionEntry {
    pub key: [u8; 32],
    pub remote_addr: [u8; 16],
    pub remote_port: u16,
    pub _pad: [u8; 6],         // Explicit padding for Pod alignment
    pub last_seq: u64,
}

/// FDB entry for L2 MAC forwarding
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct FdbEntry {
    pub mac: [u8; 6],
    pub _pad: [u8; 2],         // Padding
    pub session_id: u64,
}

/// Handshake packet structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HandshakePacket {
    pub header: PacketHeader,
    pub payload: [u8; 128],
}

/// Transport packet structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TransportPacket {
    pub header: PacketHeader,
    pub payload: [u8; 1500],
}

unsafe impl Zeroable for HandshakePacket {}
unsafe impl Pod for HandshakePacket {}

unsafe impl Zeroable for TransportPacket {}
unsafe impl Pod for TransportPacket {}

