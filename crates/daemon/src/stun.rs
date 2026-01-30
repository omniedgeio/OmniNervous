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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let n = response.len();
    if n < 20 {
        return None;
    }

    // Extract transaction ID from header (bytes 8-20) for IPv6 XOR
    let transaction_id = &response[8..20];

    let mut pos = 20;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let attr_len = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;
        pos += 4;

        if attr_type == 0x0020 {
            // XOR-MAPPED-ADDRESS
            if pos + 4 > n {
                return None;
            }

            let family = response[pos + 1];
            let x_port = u16::from_be_bytes([response[pos + 2], response[pos + 3]]);
            let port = x_port ^ 0x2112; // XOR with magic cookie top 16 bits

            match family {
                0x01 => {
                    // IPv4: XOR with magic cookie (0x2112A442)
                    if attr_len >= 8 && pos + attr_len <= n {
                        let x_ip = [
                            response[pos + 4],
                            response[pos + 5],
                            response[pos + 6],
                            response[pos + 7],
                        ];
                        let cookie = [0x21, 0x12, 0xA4, 0x42];
                        let ip = Ipv4Addr::new(
                            x_ip[0] ^ cookie[0],
                            x_ip[1] ^ cookie[1],
                            x_ip[2] ^ cookie[2],
                            x_ip[3] ^ cookie[3],
                        );
                        return Some(std::net::SocketAddr::new(IpAddr::V4(ip), port));
                    }
                }
                0x02 => {
                    // IPv6: XOR with magic cookie (4 bytes) + transaction ID (12 bytes)
                    if attr_len >= 20 && pos + attr_len <= n {
                        let mut ip_bytes = [0u8; 16];
                        // First 4 bytes XOR with magic cookie
                        ip_bytes[0] = response[pos + 4] ^ 0x21;
                        ip_bytes[1] = response[pos + 5] ^ 0x12;
                        ip_bytes[2] = response[pos + 6] ^ 0xA4;
                        ip_bytes[3] = response[pos + 7] ^ 0x42;
                        // Remaining 12 bytes XOR with transaction ID
                        for i in 0..12 {
                            ip_bytes[4 + i] = response[pos + 8 + i] ^ transaction_id[i];
                        }
                        let ip = Ipv6Addr::from(ip_bytes);
                        return Some(std::net::SocketAddr::new(IpAddr::V6(ip), port));
                    }
                }
                _ => {}
            }
        }

        pos += attr_len;
        if attr_len % 4 != 0 {
            pos += 4 - (attr_len % 4);
        }
    }
    None
}
