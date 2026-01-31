use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use crate::netcheck::NatType;

/// Prometheus-compatible metrics for OmniNervous.
///
/// Phase 6: Enhanced with NAT traversal specific metrics:
/// - NAT type detection results
/// - STUN query success/failure rates
/// - Disco ping/pong statistics
/// - Relay session tracking
/// - Port mapping attempts
pub struct Metrics {
    // === Existing Session Metrics ===
    pub sessions_active: AtomicU64,
    pub packets_rx_total: AtomicU64,
    pub packets_tx_total: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub sessions_dropped_ratelimit: AtomicU64,
    pub fdb_entries: AtomicU64,

    // === NAT Type Detection (Phase 6) ===
    /// Current NAT type (0=Unknown, 1=Open, 2=FullCone, 3=RestrictedCone, 4=PortRestrictedCone, 5=Symmetric)
    pub nat_type: AtomicU8,

    // === STUN Metrics (Phase 6) ===
    /// Total STUN queries sent
    pub stun_queries_total: AtomicU64,
    /// Successful STUN responses received
    pub stun_responses_total: AtomicU64,
    /// STUN query failures (timeout, error)
    pub stun_failures_total: AtomicU64,

    // === Disco Ping/Pong Metrics (Phase 6) ===
    /// Total disco pings sent
    pub disco_pings_sent: AtomicU64,
    /// Total disco pongs received
    pub disco_pongs_received: AtomicU64,
    /// Disco ping timeouts
    pub disco_timeouts: AtomicU64,
    /// Successful hole punches (ping→pong within timeout)
    pub holepunch_success: AtomicU64,

    // === Relay Metrics (Phase 6) ===
    /// Current active relay sessions
    pub relay_sessions_active: AtomicU64,
    /// Total relay sessions created
    pub relay_sessions_total: AtomicU64,
    /// Total bytes relayed
    pub relay_bytes_total: AtomicU64,
    /// Relay fallback events (direct connection failed)
    pub relay_fallbacks: AtomicU64,

    // === Port Mapping Metrics (Phase 6) ===
    /// Total port mapping attempts
    pub portmap_attempts_total: AtomicU64,
    /// Successful port mappings
    pub portmap_success_total: AtomicU64,
    /// Port mapping failures
    pub portmap_failures_total: AtomicU64,
    /// Current active port mappings
    pub portmap_active: AtomicU64,

    // === Connection Path Metrics (Phase 6) ===
    /// Peers connected via direct path
    pub peers_direct: AtomicU64,
    /// Peers connected via relay path
    pub peers_relayed: AtomicU64,
    /// Average latency to peers in microseconds
    pub avg_latency_us: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new_inner()
    }
}

impl Metrics {
    fn new_inner() -> Self {
        Self {
            sessions_active: AtomicU64::new(0),
            packets_rx_total: AtomicU64::new(0),
            packets_tx_total: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            sessions_dropped_ratelimit: AtomicU64::new(0),
            fdb_entries: AtomicU64::new(0),
            // NAT type
            nat_type: AtomicU8::new(0),
            // STUN
            stun_queries_total: AtomicU64::new(0),
            stun_responses_total: AtomicU64::new(0),
            stun_failures_total: AtomicU64::new(0),
            // Disco
            disco_pings_sent: AtomicU64::new(0),
            disco_pongs_received: AtomicU64::new(0),
            disco_timeouts: AtomicU64::new(0),
            holepunch_success: AtomicU64::new(0),
            // Relay
            relay_sessions_active: AtomicU64::new(0),
            relay_sessions_total: AtomicU64::new(0),
            relay_bytes_total: AtomicU64::new(0),
            relay_fallbacks: AtomicU64::new(0),
            // Port mapping
            portmap_attempts_total: AtomicU64::new(0),
            portmap_success_total: AtomicU64::new(0),
            portmap_failures_total: AtomicU64::new(0),
            portmap_active: AtomicU64::new(0),
            // Connection paths
            peers_direct: AtomicU64::new(0),
            peers_relayed: AtomicU64::new(0),
            avg_latency_us: AtomicU64::new(0),
        }
    }

    pub fn new() -> Arc<Self> {
        Arc::new(Self::new_inner())
    }

    // === Existing Session Methods ===

    pub fn inc_sessions(&self) {
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_sessions(&self) {
        self.sessions_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_packets_rx(&self) {
        self.packets_rx_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_packets_tx(&self) {
        self.packets_tx_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_handshakes_completed(&self) {
        self.handshakes_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_handshakes_failed(&self) {
        self.handshakes_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ratelimit_drops(&self) {
        self.sessions_dropped_ratelimit
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_fdb_entries(&self, count: u64) {
        self.fdb_entries.store(count, Ordering::Relaxed);
    }

    // === NAT Type Methods (Phase 6) ===

    /// Set the detected NAT type
    pub fn set_nat_type(&self, nat_type: NatType) {
        let value = match nat_type {
            NatType::Unknown => 0,
            NatType::Open => 1,
            NatType::FullCone => 2,
            NatType::RestrictedCone => 3,
            NatType::PortRestrictedCone => 4,
            NatType::Symmetric => 5,
        };
        self.nat_type.store(value, Ordering::Relaxed);
    }

    /// Get the NAT type as a string for Prometheus labels
    pub fn nat_type_label(&self) -> &'static str {
        match self.nat_type.load(Ordering::Relaxed) {
            0 => "unknown",
            1 => "open",
            2 => "full_cone",
            3 => "restricted_cone",
            4 => "port_restricted_cone",
            5 => "symmetric",
            _ => "unknown",
        }
    }

    // === STUN Methods (Phase 6) ===

    pub fn inc_stun_queries(&self) {
        self.stun_queries_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_stun_responses(&self) {
        self.stun_responses_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_stun_failures(&self) {
        self.stun_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    // === Disco Methods (Phase 6) ===

    pub fn inc_disco_pings(&self) {
        self.disco_pings_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_disco_pongs(&self) {
        self.disco_pongs_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_disco_timeouts(&self) {
        self.disco_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_holepunch_success(&self) {
        self.holepunch_success.fetch_add(1, Ordering::Relaxed);
    }

    // === Relay Methods (Phase 6) ===

    pub fn inc_relay_sessions(&self) {
        self.relay_sessions_active.fetch_add(1, Ordering::Relaxed);
        self.relay_sessions_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_relay_sessions(&self) {
        self.relay_sessions_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_relay_bytes(&self, bytes: u64) {
        self.relay_bytes_total.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn inc_relay_fallbacks(&self) {
        self.relay_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    // === Port Mapping Methods (Phase 6) ===

    pub fn inc_portmap_attempts(&self) {
        self.portmap_attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_portmap_success(&self) {
        self.portmap_success_total.fetch_add(1, Ordering::Relaxed);
        self.portmap_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_portmap_failures(&self) {
        self.portmap_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_portmap_active(&self) {
        self.portmap_active.fetch_sub(1, Ordering::Relaxed);
    }

    // === Connection Path Methods (Phase 6) ===

    pub fn set_peers_direct(&self, count: u64) {
        self.peers_direct.store(count, Ordering::Relaxed);
    }

    pub fn set_peers_relayed(&self, count: u64) {
        self.peers_relayed.store(count, Ordering::Relaxed);
    }

    pub fn set_avg_latency_us(&self, latency: u64) {
        self.avg_latency_us.store(latency, Ordering::Relaxed);
    }

    /// Format metrics in Prometheus exposition format.
    pub fn to_prometheus(&self) -> String {
        let nat_label = self.nat_type_label();

        format!(
            "# HELP omni_sessions_active Current number of active sessions\n\
             # TYPE omni_sessions_active gauge\n\
             omni_sessions_active {}\n\
             # HELP omni_packets_rx_total Total packets received\n\
             # TYPE omni_packets_rx_total counter\n\
             omni_packets_rx_total {}\n\
             # HELP omni_packets_tx_total Total packets transmitted\n\
             # TYPE omni_packets_tx_total counter\n\
             omni_packets_tx_total {}\n\
             # HELP omni_handshakes_completed_total Successful handshakes\n\
             # TYPE omni_handshakes_completed_total counter\n\
             omni_handshakes_completed_total {}\n\
             # HELP omni_handshakes_failed_total Failed handshakes\n\
             # TYPE omni_handshakes_failed_total counter\n\
             omni_handshakes_failed_total {}\n\
             # HELP omni_sessions_dropped_ratelimit_total Sessions dropped by rate limiter\n\
             # TYPE omni_sessions_dropped_ratelimit_total counter\n\
             omni_sessions_dropped_ratelimit_total {}\n\
             # HELP omni_fdb_entries Current FDB entries\n\
             # TYPE omni_fdb_entries gauge\n\
             omni_fdb_entries {}\n\
             # HELP omni_nat_type Detected NAT type (0=unknown,1=open,2=full_cone,3=restricted,4=port_restricted,5=symmetric)\n\
             # TYPE omni_nat_type gauge\n\
             omni_nat_type{{type=\"{}\"}} {}\n\
             # HELP omni_stun_queries_total Total STUN queries sent\n\
             # TYPE omni_stun_queries_total counter\n\
             omni_stun_queries_total {}\n\
             # HELP omni_stun_responses_total Successful STUN responses\n\
             # TYPE omni_stun_responses_total counter\n\
             omni_stun_responses_total {}\n\
             # HELP omni_stun_failures_total STUN query failures\n\
             # TYPE omni_stun_failures_total counter\n\
             omni_stun_failures_total {}\n\
             # HELP omni_disco_pings_sent_total Total disco pings sent\n\
             # TYPE omni_disco_pings_sent_total counter\n\
             omni_disco_pings_sent_total {}\n\
             # HELP omni_disco_pongs_received_total Total disco pongs received\n\
             # TYPE omni_disco_pongs_received_total counter\n\
             omni_disco_pongs_received_total {}\n\
             # HELP omni_disco_timeouts_total Disco ping timeouts\n\
             # TYPE omni_disco_timeouts_total counter\n\
             omni_disco_timeouts_total {}\n\
             # HELP omni_holepunch_success_total Successful hole punches\n\
             # TYPE omni_holepunch_success_total counter\n\
             omni_holepunch_success_total {}\n\
             # HELP omni_relay_sessions_active Current active relay sessions\n\
             # TYPE omni_relay_sessions_active gauge\n\
             omni_relay_sessions_active {}\n\
             # HELP omni_relay_sessions_total Total relay sessions created\n\
             # TYPE omni_relay_sessions_total counter\n\
             omni_relay_sessions_total {}\n\
             # HELP omni_relay_bytes_total Total bytes relayed\n\
             # TYPE omni_relay_bytes_total counter\n\
             omni_relay_bytes_total {}\n\
             # HELP omni_relay_fallbacks_total Relay fallback events\n\
             # TYPE omni_relay_fallbacks_total counter\n\
             omni_relay_fallbacks_total {}\n\
             # HELP omni_portmap_attempts_total Total port mapping attempts\n\
             # TYPE omni_portmap_attempts_total counter\n\
             omni_portmap_attempts_total {}\n\
             # HELP omni_portmap_success_total Successful port mappings\n\
             # TYPE omni_portmap_success_total counter\n\
             omni_portmap_success_total {}\n\
             # HELP omni_portmap_failures_total Port mapping failures\n\
             # TYPE omni_portmap_failures_total counter\n\
             omni_portmap_failures_total {}\n\
             # HELP omni_portmap_active Current active port mappings\n\
             # TYPE omni_portmap_active gauge\n\
             omni_portmap_active {}\n\
             # HELP omni_peers_direct Peers connected via direct path\n\
             # TYPE omni_peers_direct gauge\n\
             omni_peers_direct {}\n\
             # HELP omni_peers_relayed Peers connected via relay\n\
             # TYPE omni_peers_relayed gauge\n\
             omni_peers_relayed {}\n\
             # HELP omni_avg_latency_us Average peer latency in microseconds\n\
             # TYPE omni_avg_latency_us gauge\n\
             omni_avg_latency_us {}\n",
            self.sessions_active.load(Ordering::Relaxed),
            self.packets_rx_total.load(Ordering::Relaxed),
            self.packets_tx_total.load(Ordering::Relaxed),
            self.handshakes_completed.load(Ordering::Relaxed),
            self.handshakes_failed.load(Ordering::Relaxed),
            self.sessions_dropped_ratelimit.load(Ordering::Relaxed),
            self.fdb_entries.load(Ordering::Relaxed),
            nat_label,
            self.nat_type.load(Ordering::Relaxed),
            self.stun_queries_total.load(Ordering::Relaxed),
            self.stun_responses_total.load(Ordering::Relaxed),
            self.stun_failures_total.load(Ordering::Relaxed),
            self.disco_pings_sent.load(Ordering::Relaxed),
            self.disco_pongs_received.load(Ordering::Relaxed),
            self.disco_timeouts.load(Ordering::Relaxed),
            self.holepunch_success.load(Ordering::Relaxed),
            self.relay_sessions_active.load(Ordering::Relaxed),
            self.relay_sessions_total.load(Ordering::Relaxed),
            self.relay_bytes_total.load(Ordering::Relaxed),
            self.relay_fallbacks.load(Ordering::Relaxed),
            self.portmap_attempts_total.load(Ordering::Relaxed),
            self.portmap_success_total.load(Ordering::Relaxed),
            self.portmap_failures_total.load(Ordering::Relaxed),
            self.portmap_active.load(Ordering::Relaxed),
            self.peers_direct.load(Ordering::Relaxed),
            self.peers_relayed.load(Ordering::Relaxed),
            self.avg_latency_us.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new();
        assert_eq!(metrics.sessions_active.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.nat_type.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_nat_type_metrics() {
        let metrics = Metrics::new();

        metrics.set_nat_type(NatType::FullCone);
        assert_eq!(metrics.nat_type.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.nat_type_label(), "full_cone");

        metrics.set_nat_type(NatType::Symmetric);
        assert_eq!(metrics.nat_type.load(Ordering::Relaxed), 5);
        assert_eq!(metrics.nat_type_label(), "symmetric");
    }

    #[test]
    fn test_stun_metrics() {
        let metrics = Metrics::new();

        metrics.inc_stun_queries();
        metrics.inc_stun_queries();
        metrics.inc_stun_responses();
        metrics.inc_stun_failures();

        assert_eq!(metrics.stun_queries_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.stun_responses_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.stun_failures_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_disco_metrics() {
        let metrics = Metrics::new();

        metrics.inc_disco_pings();
        metrics.inc_disco_pings();
        metrics.inc_disco_pongs();
        metrics.inc_disco_timeouts();
        metrics.inc_holepunch_success();

        assert_eq!(metrics.disco_pings_sent.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.disco_pongs_received.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.disco_timeouts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.holepunch_success.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_relay_metrics() {
        let metrics = Metrics::new();

        metrics.inc_relay_sessions();
        metrics.inc_relay_sessions();
        metrics.dec_relay_sessions();
        metrics.add_relay_bytes(1024);
        metrics.add_relay_bytes(2048);
        metrics.inc_relay_fallbacks();

        assert_eq!(metrics.relay_sessions_active.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.relay_sessions_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.relay_bytes_total.load(Ordering::Relaxed), 3072);
        assert_eq!(metrics.relay_fallbacks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_portmap_metrics() {
        let metrics = Metrics::new();

        metrics.inc_portmap_attempts();
        metrics.inc_portmap_attempts();
        metrics.inc_portmap_success();
        metrics.inc_portmap_failures();
        metrics.dec_portmap_active();

        assert_eq!(metrics.portmap_attempts_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.portmap_success_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.portmap_failures_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.portmap_active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_prometheus_output() {
        let metrics = Metrics::new();
        metrics.set_nat_type(NatType::PortRestrictedCone);
        metrics.inc_stun_queries();
        metrics.inc_disco_pings();

        let output = metrics.to_prometheus();
        assert!(output.contains("omni_nat_type{type=\"port_restricted_cone\"}"));
        assert!(output.contains("omni_stun_queries_total 1"));
        assert!(output.contains("omni_disco_pings_sent_total 1"));
    }
}
