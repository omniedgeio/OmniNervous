//! IPv6 utility functions for OmniNervous
//!
//! This module provides shared IPv6 validation and utility functions used
//! across the codebase, particularly for ULA (Unique Local Address) validation.

use std::net::Ipv6Addr;

/// ULA prefix byte (fd00::/8)
pub const ULA_PREFIX: u8 = 0xfd;

/// Link-local prefix byte (fe80::/10 - first byte is 0xfe)
pub const LINK_LOCAL_PREFIX: u8 = 0xfe;

/// Link-local mask for second byte (::80 to ::bf)
pub const LINK_LOCAL_MASK: u8 = 0xc0;

/// Link-local expected second byte value
pub const LINK_LOCAL_EXPECTED: u8 = 0x80;

/// Validates that an IPv6 address is in the Unique Local Address (ULA) range.
///
/// ULA addresses are in the fd00::/8 range. Technically, ULA is defined as fc00::/7
/// with the L bit set, meaning fd00::/8 is the locally-assigned subset.
/// fc00::/8 is reserved for future use.
///
/// # Arguments
/// * `ip` - The IPv6 address to validate
///
/// # Returns
/// `true` if the address is a valid ULA, `false` otherwise
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// use omninervous::ipv6_utils::is_valid_ula;
///
/// assert!(is_valid_ula(&"fd00::1".parse().unwrap()));
/// assert!(is_valid_ula(&"fd12:3456:789a:bcde::1".parse().unwrap()));
/// assert!(!is_valid_ula(&"2001:db8::1".parse().unwrap()));
/// assert!(!is_valid_ula(&"fe80::1".parse().unwrap()));
/// ```
pub fn is_valid_ula(ip: &Ipv6Addr) -> bool {
    ip.octets()[0] == ULA_PREFIX
}

/// Validates that an IPv6 address is a link-local address (fe80::/10).
///
/// Link-local addresses are used for communication within a single network
/// segment and are not routable beyond that.
///
/// # Arguments
/// * `ip` - The IPv6 address to validate
///
/// # Returns
/// `true` if the address is link-local, `false` otherwise
///
/// # Examples
/// ```
/// use std::net::Ipv6Addr;
/// use omninervous::ipv6_utils::is_link_local;
///
/// assert!(is_link_local(&"fe80::1".parse().unwrap()));
/// assert!(is_link_local(&"fe80::1234:5678:abcd:ef01".parse().unwrap()));
/// assert!(!is_link_local(&"fd00::1".parse().unwrap()));
/// assert!(!is_link_local(&"2001:db8::1".parse().unwrap()));
/// ```
pub fn is_link_local(ip: &Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == LINK_LOCAL_PREFIX && (octets[1] & LINK_LOCAL_MASK) == LINK_LOCAL_EXPECTED
}

/// Checks if an IPv6 address is a global unicast address.
///
/// Global unicast addresses are routable on the public internet.
/// This includes 2000::/3 (first three bits are 001).
///
/// # Arguments
/// * `ip` - The IPv6 address to validate
///
/// # Returns
/// `true` if the address is a global unicast address, `false` otherwise
pub fn is_global_unicast(ip: &Ipv6Addr) -> bool {
    let first_byte = ip.octets()[0];
    // 2000::/3 means first 3 bits are 001
    // In binary: 0010 0000 to 0011 1111 (0x20 to 0x3f)
    (0x20..=0x3f).contains(&first_byte)
}

/// Checks if an IPv6 address is a loopback address (::1).
pub fn is_loopback(ip: &Ipv6Addr) -> bool {
    *ip == Ipv6Addr::LOCALHOST
}

/// Checks if an IPv6 address is the unspecified address (::).
pub fn is_unspecified(ip: &Ipv6Addr) -> bool {
    *ip == Ipv6Addr::UNSPECIFIED
}

/// Checks if an IPv6 address is in the documentation range (2001:db8::/32).
///
/// These addresses are reserved for documentation and examples.
pub fn is_documentation(ip: &Ipv6Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8
}

/// Determines if an IPv6 address is suitable for VPN virtual IPs.
///
/// Only ULA addresses (fd00::/8) are valid for OmniEdge virtual IPs.
/// This ensures addresses don't conflict with global routable addresses.
///
/// # Arguments
/// * `ip` - The IPv6 address to validate
///
/// # Returns
/// `true` if the address is valid for use as a virtual IP, `false` otherwise
pub fn is_valid_virtual_ip(ip: &Ipv6Addr) -> bool {
    is_valid_ula(ip)
}

/// Formats an IPv6 address for display with optional zone ID.
///
/// This is useful for link-local addresses which may require a zone/scope ID.
pub fn format_with_zone(ip: &Ipv6Addr, zone: Option<&str>) -> String {
    match zone {
        Some(z) => format!("{}%{}", ip, z),
        None => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ula() {
        // Valid ULA addresses (fd00::/8)
        assert!(is_valid_ula(&"fd00::1".parse().unwrap()));
        assert!(is_valid_ula(&"fd12:3456:789a:bcde::1".parse().unwrap()));
        assert!(is_valid_ula(
            &"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));

        // Invalid: global unicast
        assert!(!is_valid_ula(&"2001:db8::1".parse().unwrap()));
        assert!(!is_valid_ula(&"2607:f8b0:4004:800::200e".parse().unwrap()));

        // Invalid: link-local
        assert!(!is_valid_ula(&"fe80::1".parse().unwrap()));

        // Invalid: loopback
        assert!(!is_valid_ula(&"::1".parse().unwrap()));

        // Invalid: fc00::/8 (reserved, not ULA)
        assert!(!is_valid_ula(&"fc00::1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local() {
        // Valid link-local addresses (fe80::/10)
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_link_local(&"fe80::1234:5678:abcd:ef01".parse().unwrap()));
        assert!(is_link_local(&"fe80:1234:5678::1".parse().unwrap()));
        assert!(is_link_local(&"feb0::1".parse().unwrap())); // febf::/16 is still in fe80::/10

        // Invalid: ULA
        assert!(!is_link_local(&"fd00::1".parse().unwrap()));

        // Invalid: global
        assert!(!is_link_local(&"2001:db8::1".parse().unwrap()));

        // Invalid: fec0::/10 (site-local, deprecated)
        assert!(!is_link_local(&"fec0::1".parse().unwrap()));
    }

    #[test]
    fn test_is_global_unicast() {
        // Valid global unicast (2000::/3)
        assert!(is_global_unicast(&"2001:db8::1".parse().unwrap()));
        assert!(is_global_unicast(
            &"2607:f8b0:4004:800::200e".parse().unwrap()
        ));
        assert!(is_global_unicast(&"2000::1".parse().unwrap()));
        assert!(is_global_unicast(&"3fff::1".parse().unwrap()));

        // Invalid: ULA
        assert!(!is_global_unicast(&"fd00::1".parse().unwrap()));

        // Invalid: link-local
        assert!(!is_global_unicast(&"fe80::1".parse().unwrap()));

        // Invalid: loopback
        assert!(!is_global_unicast(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_is_loopback() {
        assert!(is_loopback(&"::1".parse().unwrap()));
        assert!(!is_loopback(&"::2".parse().unwrap()));
        assert!(!is_loopback(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn test_is_unspecified() {
        assert!(is_unspecified(&"::".parse().unwrap()));
        assert!(!is_unspecified(&"::1".parse().unwrap()));
        assert!(!is_unspecified(&"fd00::".parse().unwrap()));
    }

    #[test]
    fn test_is_documentation() {
        assert!(is_documentation(&"2001:db8::1".parse().unwrap()));
        assert!(is_documentation(&"2001:db8:1234:5678::1".parse().unwrap()));
        assert!(!is_documentation(&"2001:db9::1".parse().unwrap()));
        assert!(!is_documentation(&"2001::1".parse().unwrap()));
    }

    #[test]
    fn test_is_valid_virtual_ip() {
        assert!(is_valid_virtual_ip(&"fd00::1".parse().unwrap()));
        assert!(!is_valid_virtual_ip(&"2001:db8::1".parse().unwrap()));
        assert!(!is_valid_virtual_ip(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_format_with_zone() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(format_with_zone(&ip, None), "fe80::1");
        assert_eq!(format_with_zone(&ip, Some("eth0")), "fe80::1%eth0");
    }
}
