#![no_std]

/// Wire protocol header with 64-bit session ID and sequence number
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub session_id: u64,  // Changed from u32 to u64 for security
    pub sequence: u64,    // NEW: Replay protection
    pub nonce: [u8; 8],   // ChaCha20 nonce
}

/// Session key for BPF HashMap compatibility (aya requires Pod trait)
/// Wraps u64 as two u32 values for proper BPF map support
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionKey {
    pub id_high: u32,
    pub id_low: u32,
}

impl SessionKey {
    /// Create from u64 session ID
    pub const fn from_u64(id: u64) -> Self {
        SessionKey {
            id_high: (id >> 32) as u32,
            id_low: id as u32,
        }
    }

    /// Convert back to u64
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
#[derive(Clone, Copy, Debug)]
pub struct SessionEntry {
    pub key: [u8; 32],
    pub remote_addr: [u8; 16], // IPv6 compatible (IPv4 mapped as ::ffff:x.x.x.x)
    pub remote_port: u16,
    pub last_seq: u64,         // NEW: Track last seen sequence number for replay protection
}

/// FDB entry for L2 MAC forwarding
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FdbEntry {
    pub mac: [u8; 6],
    pub session_id: u64,  // Changed from u32 to u64
}

/// Handshake packet structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HandshakePacket {
    pub header: PacketHeader,
    pub payload: [u8; 128], // Standard Noise IK payload size
}

/// Transport packet structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TransportPacket {
    pub header: PacketHeader,
    pub payload: [u8; 1500], // Maximum L2 frame size
}
