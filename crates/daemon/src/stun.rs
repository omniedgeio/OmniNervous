/// Reliable public STUN servers to use as ultimate fallback
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.voiparound.com:3478",
    "stun.schlund.de:3478",
    "stun.ekiga.net:3478",
];

/// Parse XOR-MAPPED-ADDRESS from STUN response
pub fn parse_xor_mapped_address(response: &[u8]) -> Option<std::net::SocketAddr> {
    let n = response.len();
    if n < 20 { return None; }
    
    let mut pos = 20;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([response[pos], response[pos+1]]);
        let attr_len = u16::from_be_bytes([response[pos+2], response[pos+3]]) as usize;
        pos += 4;
        
        if attr_type == 0x0020 { // XOR-MAPPED-ADDRESS
                if attr_len >= 8 && pos + attr_len <= n {
                let _family = response[pos + 1];
                let x_port = u16::from_be_bytes([response[pos+2], response[pos+3]]);
                let port = x_port ^ 0x2112; // XOR with magic cookie top 16 bits
                let x_ip = [response[pos+4], response[pos+5], response[pos+6], response[pos+7]];
                let cookie = [0x21, 0x12, 0xA4, 0x42];
                let ip = std::net::Ipv4Addr::new(
                    x_ip[0] ^ cookie[0],
                    x_ip[1] ^ cookie[1],
                    x_ip[2] ^ cookie[2],
                    x_ip[3] ^ cookie[3],
                );
                return Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port));
            }
        }
        
        pos += attr_len;
        if attr_len % 4 != 0 {
            pos += 4 - (attr_len % 4);
        }
    }
    None
}
