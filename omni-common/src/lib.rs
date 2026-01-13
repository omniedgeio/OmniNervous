#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketHeader {
    pub session_id: u32,
    pub nonce: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SessionEntry {
    pub key: [u8; 32],
    pub remote_ip: u32, // Simplified for now
    pub remote_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FdbEntry {
    pub mac: [u8; 6],
    pub session_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HandshakePacket {
    pub header: PacketHeader,
    pub payload: [u8; 128], // Standard Noise IK payload size
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TransportPacket {
    pub header: PacketHeader,
    pub payload: [u8; 1500], // Maximum L2 frame size
}
