//! Happy Eyeballs (RFC 8305) - Connection Racing for IPv4/IPv6
//!
//! Implements the Happy Eyeballs algorithm to minimize connection latency
//! when both IPv4 and IPv6 addresses are available for a peer.
//!
//! ## Algorithm Overview
//! 1. Sort addresses by preference (IPv6 first, then IPv4)
//! 2. Start connection to first (IPv6) address
//! 3. After 250ms delay, start connection to second (IPv4) address if first hasn't succeeded
//! 4. Return first successful connection, cancel others
//!
//! ## Adaptations for UDP/WireGuard
//! Since WireGuard uses UDP and doesn't have TCP-style connections, we adapt:
//! - "Connection" = successful disco ping/pong exchange
//! - Race discovery probes to both addresses
//! - First to respond wins and becomes the active endpoint

use log::debug;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Default delay before starting fallback connection (RFC 8305 recommends 250ms)
pub const HAPPY_EYEBALLS_DELAY_MS: u64 = 250;

/// Minimum delay (for local networks)
pub const HAPPY_EYEBALLS_MIN_DELAY_MS: u64 = 50;

/// Maximum delay (for high-latency networks)
pub const HAPPY_EYEBALLS_MAX_DELAY_MS: u64 = 2000;

/// Result of a connection race
#[derive(Debug, Clone)]
pub struct RaceResult {
    /// The winning address
    pub winner: SocketAddr,
    /// Round-trip time to the winner in microseconds
    pub rtt_us: u64,
    /// Whether IPv6 won the race
    pub ipv6_won: bool,
    /// Total race duration
    pub race_duration: Duration,
}

/// State for tracking an ongoing connection race
#[derive(Debug)]
pub struct ConnectionRace {
    /// IPv4 endpoint (if available)
    addr_v4: Option<SocketAddr>,
    /// IPv6 endpoint (if available)
    addr_v6: Option<SocketAddr>,
    /// When the race started
    started: Instant,
    /// When IPv6 probe was sent
    v6_sent: Option<Instant>,
    /// When IPv4 probe was sent
    v4_sent: Option<Instant>,
    /// Delay before starting fallback
    delay: Duration,
    /// Current phase
    phase: RacePhase,
}

/// Phase of the connection race
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RacePhase {
    /// Haven't started yet
    NotStarted,
    /// Waiting for IPv6 response (IPv4 not yet started)
    WaitingV6Only,
    /// Both IPv4 and IPv6 probes sent, waiting for either
    WaitingBoth,
    /// Race complete, have a winner
    Complete,
    /// Race failed, no responses
    Failed,
}

impl ConnectionRace {
    /// Create a new connection race with the given endpoints
    pub fn new(addr_v4: Option<SocketAddr>, addr_v6: Option<SocketAddr>) -> Self {
        Self {
            addr_v4,
            addr_v6,
            started: Instant::now(),
            v6_sent: None,
            v4_sent: None,
            delay: Duration::from_millis(HAPPY_EYEBALLS_DELAY_MS),
            phase: RacePhase::NotStarted,
        }
    }

    /// Create with a custom delay
    pub fn with_delay(
        addr_v4: Option<SocketAddr>,
        addr_v6: Option<SocketAddr>,
        delay_ms: u64,
    ) -> Self {
        let delay_ms = delay_ms.clamp(HAPPY_EYEBALLS_MIN_DELAY_MS, HAPPY_EYEBALLS_MAX_DELAY_MS);
        Self {
            delay: Duration::from_millis(delay_ms),
            ..Self::new(addr_v4, addr_v6)
        }
    }

    /// Get the current phase
    pub fn phase(&self) -> RacePhase {
        self.phase
    }

    /// Check if the race is complete
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, RacePhase::Complete | RacePhase::Failed)
    }

    /// Get the next address to probe, following Happy Eyeballs algorithm
    ///
    /// Returns the address to probe and whether this is the first probe.
    /// Call this to get the next action to take.
    pub fn next_action(&mut self) -> RaceAction {
        match self.phase {
            RacePhase::NotStarted => {
                // Start with IPv6 if available, otherwise IPv4
                if let Some(addr_v6) = self.addr_v6 {
                    self.phase = RacePhase::WaitingV6Only;
                    self.v6_sent = Some(Instant::now());
                    debug!("Happy Eyeballs: starting with IPv6 {}", addr_v6);
                    RaceAction::ProbeV6(addr_v6)
                } else if let Some(addr_v4) = self.addr_v4 {
                    self.phase = RacePhase::WaitingBoth; // No IPv6, go straight to "both" (just v4)
                    self.v4_sent = Some(Instant::now());
                    debug!("Happy Eyeballs: no IPv6, using IPv4 {}", addr_v4);
                    RaceAction::ProbeV4(addr_v4)
                } else {
                    self.phase = RacePhase::Failed;
                    RaceAction::NoAddresses
                }
            }
            RacePhase::WaitingV6Only => {
                // Check if delay has elapsed
                let elapsed = self.started.elapsed();
                if elapsed >= self.delay {
                    if let Some(addr_v4) = self.addr_v4 {
                        self.phase = RacePhase::WaitingBoth;
                        self.v4_sent = Some(Instant::now());
                        debug!(
                            "Happy Eyeballs: IPv6 delay elapsed, starting IPv4 {}",
                            addr_v4
                        );
                        RaceAction::ProbeV4(addr_v4)
                    } else {
                        // No IPv4 fallback available
                        RaceAction::WaitForResponse
                    }
                } else {
                    // Still waiting for IPv6
                    let remaining = self.delay - elapsed;
                    RaceAction::WaitWithTimeout(remaining)
                }
            }
            RacePhase::WaitingBoth => RaceAction::WaitForResponse,
            RacePhase::Complete | RacePhase::Failed => RaceAction::RaceOver,
        }
    }

    /// Record a successful response from an address
    ///
    /// Returns the race result if this response wins the race.
    pub fn record_response(&mut self, from: SocketAddr) -> Option<RaceResult> {
        if self.is_complete() {
            return None;
        }

        let is_ipv6 = from.is_ipv6();
        let sent_time = if is_ipv6 { self.v6_sent } else { self.v4_sent };

        // Use saturating conversion to prevent truncation on extremely long RTTs
        let rtt_us = sent_time
            .map(|t| t.elapsed().as_micros().min(u64::MAX as u128) as u64)
            .unwrap_or(0);

        self.phase = RacePhase::Complete;

        let result = RaceResult {
            winner: from,
            rtt_us,
            ipv6_won: is_ipv6,
            race_duration: self.started.elapsed(),
        };

        debug!(
            "Happy Eyeballs: {} won in {:?} (RTT: {}us)",
            if is_ipv6 { "IPv6" } else { "IPv4" },
            result.race_duration,
            rtt_us
        );

        Some(result)
    }

    /// Mark the race as failed (timeout with no responses)
    pub fn mark_failed(&mut self) {
        self.phase = RacePhase::Failed;
    }

    /// Get time elapsed since race started
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Check if we should start the fallback (IPv4) probe
    pub fn should_start_fallback(&self) -> bool {
        self.phase == RacePhase::WaitingV6Only && self.started.elapsed() >= self.delay
    }
}

/// Action to take in the connection race
#[derive(Debug, Clone)]
pub enum RaceAction {
    /// Send a probe to this IPv6 address
    ProbeV6(SocketAddr),
    /// Send a probe to this IPv4 address
    ProbeV4(SocketAddr),
    /// Wait for responses (probes already sent)
    WaitForResponse,
    /// Wait for this duration before checking again
    WaitWithTimeout(Duration),
    /// No addresses available to probe
    NoAddresses,
    /// Race is over (complete or failed)
    RaceOver,
}

impl RaceAction {
    /// Check if this action requires sending a probe
    pub fn is_probe(&self) -> bool {
        matches!(self, RaceAction::ProbeV6(_) | RaceAction::ProbeV4(_))
    }

    /// Get the address to probe (if this is a probe action)
    pub fn probe_addr(&self) -> Option<SocketAddr> {
        match self {
            RaceAction::ProbeV6(addr) | RaceAction::ProbeV4(addr) => Some(*addr),
            _ => None,
        }
    }
}

/// Sort addresses for Happy Eyeballs (IPv6 first, then IPv4)
pub fn sort_addresses_for_racing(addrs: &mut [SocketAddr]) {
    addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
}

/// Interleave IPv4 and IPv6 addresses for connection attempts
/// Returns addresses in order: v6, v4, v6, v4, ...
pub fn interleave_addresses(v4_addrs: &[SocketAddr], v6_addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut result = Vec::with_capacity(v4_addrs.len() + v6_addrs.len());
    let mut v4_iter = v4_addrs.iter();
    let mut v6_iter = v6_addrs.iter();

    loop {
        let v6 = v6_iter.next();
        let v4 = v4_iter.next();

        if v6.is_none() && v4.is_none() {
            break;
        }

        if let Some(addr) = v6 {
            result.push(*addr);
        }
        if let Some(addr) = v4 {
            result.push(*addr);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
    }

    fn v6_addr(port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port,
        )
    }

    #[test]
    fn test_race_ipv6_first() {
        let mut race = ConnectionRace::new(Some(v4_addr(1234)), Some(v6_addr(1234)));

        // First action should be to probe IPv6
        let action = race.next_action();
        assert!(matches!(action, RaceAction::ProbeV6(_)));
        assert_eq!(race.phase(), RacePhase::WaitingV6Only);
    }

    #[test]
    fn test_race_v4_only() {
        let mut race = ConnectionRace::new(Some(v4_addr(1234)), None);

        // Should go straight to IPv4
        let action = race.next_action();
        assert!(matches!(action, RaceAction::ProbeV4(_)));
    }

    #[test]
    fn test_race_no_addresses() {
        let mut race = ConnectionRace::new(None, None);

        let action = race.next_action();
        assert!(matches!(action, RaceAction::NoAddresses));
        assert_eq!(race.phase(), RacePhase::Failed);
    }

    #[test]
    fn test_race_response_wins() {
        let mut race = ConnectionRace::new(Some(v4_addr(1234)), Some(v6_addr(1234)));

        // Start the race
        let _ = race.next_action();

        // Simulate IPv6 response
        let result = race.record_response(v6_addr(1234));
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.ipv6_won);
        assert_eq!(race.phase(), RacePhase::Complete);
    }

    #[test]
    fn test_sort_addresses() {
        let mut addrs = vec![v4_addr(1), v6_addr(2), v4_addr(3), v6_addr(4)];

        sort_addresses_for_racing(&mut addrs);

        // IPv6 should come first
        assert!(addrs[0].is_ipv6());
        assert!(addrs[1].is_ipv6());
        assert!(addrs[2].is_ipv4());
        assert!(addrs[3].is_ipv4());
    }

    #[test]
    fn test_interleave_addresses() {
        let v4_addrs = vec![v4_addr(1), v4_addr(2)];
        let v6_addrs = vec![v6_addr(3), v6_addr(4), v6_addr(5)];

        let result = interleave_addresses(&v4_addrs, &v6_addrs);

        // Should be: v6, v4, v6, v4, v6
        assert_eq!(result.len(), 5);
        assert!(result[0].is_ipv6());
        assert!(result[1].is_ipv4());
        assert!(result[2].is_ipv6());
        assert!(result[3].is_ipv4());
        assert!(result[4].is_ipv6());
    }

    #[test]
    fn test_race_with_custom_delay() {
        let race = ConnectionRace::with_delay(Some(v4_addr(1234)), Some(v6_addr(1234)), 100);
        assert_eq!(race.delay, Duration::from_millis(100));
    }

    #[test]
    fn test_race_action_helpers() {
        let probe = RaceAction::ProbeV6(v6_addr(1234));
        assert!(probe.is_probe());
        assert_eq!(probe.probe_addr(), Some(v6_addr(1234)));

        let wait = RaceAction::WaitForResponse;
        assert!(!wait.is_probe());
        assert_eq!(wait.probe_addr(), None);
    }
}
