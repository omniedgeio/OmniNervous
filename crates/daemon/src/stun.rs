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

/// STUN magic cookie (RFC 5389)
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// Address family constants (RFC 5389)
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// Parse XOR-MAPPED-ADDRESS from STUN response (supports both IPv4 and IPv6)
///
/// For IPv4: XOR with magic cookie (4 bytes)
/// For IPv6: XOR with magic cookie (4 bytes) || transaction ID (12 bytes)
///
/// The transaction ID is extracted from bytes 8-20 of the STUN header.
pub fn parse_xor_mapped_address(response: &[u8]) -> Option<std::net::SocketAddr> {
    let n = response.len();
    if n < 20 {
        return None;
    }

    // Extract transaction ID from STUN header (bytes 8-20)
    let transaction_id: [u8; 12] = response[8..20].try_into().ok()?;

    let mut pos = 20;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let attr_len = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;
        pos += 4;

        if attr_type == 0x0020 {
            // XOR-MAPPED-ADDRESS
            // Ensure we have at least the minimum bytes to read family and port
            if pos + 4 > n {
                break;
            }
            let family = response[pos + 1];
            let x_port = u16::from_be_bytes([response[pos + 2], response[pos + 3]]);
            let port = x_port ^ 0x2112; // XOR with magic cookie top 16 bits

            match family {
                FAMILY_IPV4 => {
                    // IPv4: need at least 8 bytes (1 reserved + 1 family + 2 port + 4 addr)
                    if attr_len >= 8 && pos + 8 <= n {
                        let x_ip = &response[pos + 4..pos + 8];
                        let ip = std::net::Ipv4Addr::new(
                            x_ip[0] ^ MAGIC_COOKIE[0],
                            x_ip[1] ^ MAGIC_COOKIE[1],
                            x_ip[2] ^ MAGIC_COOKIE[2],
                            x_ip[3] ^ MAGIC_COOKIE[3],
                        );
                        return Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port));
                    }
                }
                FAMILY_IPV6 => {
                    // IPv6: need at least 20 bytes (1 reserved + 1 family + 2 port + 16 addr)
                    if attr_len >= 20 && pos + 20 <= n {
                        let x_ip = &response[pos + 4..pos + 20];
                        // XOR with magic cookie (4 bytes) || transaction ID (12 bytes)
                        let mut ip_bytes = [0u8; 16];
                        for i in 0..4 {
                            ip_bytes[i] = x_ip[i] ^ MAGIC_COOKIE[i];
                        }
                        for i in 0..12 {
                            ip_bytes[4 + i] = x_ip[4 + i] ^ transaction_id[i];
                        }
                        let ip = std::net::Ipv6Addr::from(ip_bytes);
                        return Some(std::net::SocketAddr::new(std::net::IpAddr::V6(ip), port));
                    }
                }
                _ => {
                    // Unknown address family, skip this attribute
                }
            }
        }

        pos += attr_len;
        if !attr_len.is_multiple_of(4) {
            pos += 4 - (attr_len % 4);
        }
    }
    None
}

/// Parse XOR-MAPPED-ADDRESS and return both IPv4 and IPv6 addresses if present
///
/// Some STUN servers may return multiple XOR-MAPPED-ADDRESS attributes.
/// This function collects all of them.
pub fn parse_all_xor_mapped_addresses(
    response: &[u8],
) -> (
    Option<std::net::SocketAddrV4>,
    Option<std::net::SocketAddrV6>,
) {
    let n = response.len();
    if n < 20 {
        return (None, None);
    }

    // Extract transaction ID from STUN header (bytes 8-20)
    let transaction_id: [u8; 12] = match response[8..20].try_into() {
        Ok(tid) => tid,
        Err(_) => return (None, None),
    };

    let mut ipv4_addr: Option<std::net::SocketAddrV4> = None;
    let mut ipv6_addr: Option<std::net::SocketAddrV6> = None;

    let mut pos = 20;
    while pos + 4 <= n {
        let attr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let attr_len = u16::from_be_bytes([response[pos + 2], response[pos + 3]]) as usize;
        pos += 4;

        if attr_type == 0x0020 {
            // XOR-MAPPED-ADDRESS
            // Ensure we have at least the minimum bytes to read family and port
            if pos + 4 > n {
                break;
            }
            let family = response[pos + 1];
            let x_port = u16::from_be_bytes([response[pos + 2], response[pos + 3]]);
            let port = x_port ^ 0x2112;

            match family {
                FAMILY_IPV4 if attr_len >= 8 && pos + 8 <= n => {
                    let x_ip = &response[pos + 4..pos + 8];
                    let ip = std::net::Ipv4Addr::new(
                        x_ip[0] ^ MAGIC_COOKIE[0],
                        x_ip[1] ^ MAGIC_COOKIE[1],
                        x_ip[2] ^ MAGIC_COOKIE[2],
                        x_ip[3] ^ MAGIC_COOKIE[3],
                    );
                    ipv4_addr = Some(std::net::SocketAddrV4::new(ip, port));
                }
                FAMILY_IPV6 if attr_len >= 20 && pos + 20 <= n => {
                    let x_ip = &response[pos + 4..pos + 20];
                    let mut ip_bytes = [0u8; 16];
                    for i in 0..4 {
                        ip_bytes[i] = x_ip[i] ^ MAGIC_COOKIE[i];
                    }
                    for i in 0..12 {
                        ip_bytes[4 + i] = x_ip[4 + i] ^ transaction_id[i];
                    }
                    let ip = std::net::Ipv6Addr::from(ip_bytes);
                    ipv6_addr = Some(std::net::SocketAddrV6::new(ip, port, 0, 0));
                }
                _ => {}
            }
        }

        pos += attr_len;
        if !attr_len.is_multiple_of(4) {
            pos += 4 - (attr_len % 4);
        }
    }

    (ipv4_addr, ipv6_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Helper to build a minimal STUN Binding Response with XOR-MAPPED-ADDRESS
    fn build_stun_response(transaction_id: [u8; 12], xor_mapped_attr: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        // STUN header (20 bytes)
        // Message Type: Binding Success Response (0x0101)
        response.extend_from_slice(&[0x01, 0x01]);
        // Message Length (attribute length)
        let msg_len = xor_mapped_attr.len() as u16;
        response.extend_from_slice(&msg_len.to_be_bytes());
        // Magic Cookie
        response.extend_from_slice(&MAGIC_COOKIE);
        // Transaction ID (12 bytes)
        response.extend_from_slice(&transaction_id);
        // Attributes
        response.extend_from_slice(xor_mapped_attr);
        response
    }

    /// Build XOR-MAPPED-ADDRESS attribute for IPv4
    fn build_xor_mapped_address_v4(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut attr = Vec::new();
        // Attribute Type: XOR-MAPPED-ADDRESS (0x0020)
        attr.extend_from_slice(&[0x00, 0x20]);
        // Attribute Length: 8 bytes
        attr.extend_from_slice(&[0x00, 0x08]);
        // Reserved + Family (IPv4 = 0x01)
        attr.extend_from_slice(&[0x00, FAMILY_IPV4]);
        // XOR'd Port
        let x_port = port ^ 0x2112;
        attr.extend_from_slice(&x_port.to_be_bytes());
        // XOR'd IP
        let ip_octets = ip.octets();
        attr.push(ip_octets[0] ^ MAGIC_COOKIE[0]);
        attr.push(ip_octets[1] ^ MAGIC_COOKIE[1]);
        attr.push(ip_octets[2] ^ MAGIC_COOKIE[2]);
        attr.push(ip_octets[3] ^ MAGIC_COOKIE[3]);
        attr
    }

    /// Build XOR-MAPPED-ADDRESS attribute for IPv6
    fn build_xor_mapped_address_v6(ip: Ipv6Addr, port: u16, transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut attr = Vec::new();
        // Attribute Type: XOR-MAPPED-ADDRESS (0x0020)
        attr.extend_from_slice(&[0x00, 0x20]);
        // Attribute Length: 20 bytes
        attr.extend_from_slice(&[0x00, 0x14]);
        // Reserved + Family (IPv6 = 0x02)
        attr.extend_from_slice(&[0x00, FAMILY_IPV6]);
        // XOR'd Port
        let x_port = port ^ 0x2112;
        attr.extend_from_slice(&x_port.to_be_bytes());
        // XOR'd IP (magic cookie || transaction_id)
        let ip_octets = ip.octets();
        for i in 0..4 {
            attr.push(ip_octets[i] ^ MAGIC_COOKIE[i]);
        }
        for i in 0..12 {
            attr.push(ip_octets[4 + i] ^ transaction_id[i]);
        }
        attr
    }

    #[test]
    fn test_parse_ipv4_xor_mapped_address() {
        let transaction_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let port = 12345;

        let attr = build_xor_mapped_address_v4(ip, port);
        let response = build_stun_response(transaction_id, &attr);

        let result = parse_xor_mapped_address(&response);
        assert!(result.is_some());
        let addr = result.unwrap();
        assert_eq!(addr, SocketAddr::new(ip.into(), port));
    }

    #[test]
    fn test_parse_ipv6_xor_mapped_address() {
        let transaction_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let ip = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        );
        let port = 54321;

        let attr = build_xor_mapped_address_v6(ip, port, &transaction_id);
        let response = build_stun_response(transaction_id, &attr);

        let result = parse_xor_mapped_address(&response);
        assert!(result.is_some());
        let addr = result.unwrap();
        assert_eq!(addr, SocketAddr::new(ip.into(), port));
    }

    #[test]
    fn test_parse_ipv6_ula_address() {
        // Test with ULA address (fd00::/8) which OmniEdge uses for virtual IPs
        let transaction_id = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ];
        let ip = Ipv6Addr::new(
            0xfd00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
        );
        let port = 8080;

        let attr = build_xor_mapped_address_v6(ip, port, &transaction_id);
        let response = build_stun_response(transaction_id, &attr);

        let result = parse_xor_mapped_address(&response);
        assert!(result.is_some());
        let addr = result.unwrap();
        assert_eq!(addr, SocketAddr::new(ip.into(), port));
    }

    #[test]
    fn test_parse_all_xor_mapped_addresses_v4_only() {
        let transaction_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let port = 443;

        let attr = build_xor_mapped_address_v4(ip, port);
        let response = build_stun_response(transaction_id, &attr);

        let (v4, v6) = parse_all_xor_mapped_addresses(&response);
        assert!(v4.is_some());
        assert!(v6.is_none());
        assert_eq!(v4.unwrap().ip(), &ip);
        assert_eq!(v4.unwrap().port(), port);
    }

    #[test]
    fn test_parse_all_xor_mapped_addresses_v6_only() {
        let transaction_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let ip = Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4004, 0x0800, 0x0000, 0x0000, 0x0000, 0x200e,
        );
        let port = 80;

        let attr = build_xor_mapped_address_v6(ip, port, &transaction_id);
        let response = build_stun_response(transaction_id, &attr);

        let (v4, v6) = parse_all_xor_mapped_addresses(&response);
        assert!(v4.is_none());
        assert!(v6.is_some());
        assert_eq!(v6.unwrap().ip(), &ip);
        assert_eq!(v6.unwrap().port(), port);
    }

    #[test]
    fn test_parse_empty_response() {
        let result = parse_xor_mapped_address(&[]);
        assert!(result.is_none());

        let (v4, v6) = parse_all_xor_mapped_addresses(&[]);
        assert!(v4.is_none());
        assert!(v6.is_none());
    }

    #[test]
    fn test_parse_short_response() {
        // Only 10 bytes, less than minimum header size
        let result = parse_xor_mapped_address(&[0u8; 10]);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_response_without_xor_mapped_address() {
        let transaction_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        // Build response with SOFTWARE attribute (0x8022) instead
        let mut attr = Vec::new();
        attr.extend_from_slice(&[0x80, 0x22]); // SOFTWARE
        attr.extend_from_slice(&[0x00, 0x04]); // Length: 4
        attr.extend_from_slice(b"test");
        let response = build_stun_response(transaction_id, &attr);

        let result = parse_xor_mapped_address(&response);
        assert!(result.is_none());
    }
}
