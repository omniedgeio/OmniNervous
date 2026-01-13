#![no_std]

/// Wire protocol header with 64-bit session ID and sequence number
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub session_id: u64,  // Changed from u32 to u64 for security
    pub sequence: u64,    // NEW: Replay protection
    pub nonce: [u8; 8],   // ChaCha20 nonce
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
