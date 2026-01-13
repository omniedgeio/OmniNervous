use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Prometheus-compatible metrics for OmniNervous.
pub struct Metrics {
    pub sessions_active: AtomicU64,
    pub packets_rx_total: AtomicU64,
    pub packets_tx_total: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub handshakes_failed: AtomicU64,
    pub sessions_dropped_ratelimit: AtomicU64,
    pub fdb_entries: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions_active: AtomicU64::new(0),
            packets_rx_total: AtomicU64::new(0),
            packets_tx_total: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshakes_failed: AtomicU64::new(0),
            sessions_dropped_ratelimit: AtomicU64::new(0),
            fdb_entries: AtomicU64::new(0),
        })
    }

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
        self.sessions_dropped_ratelimit.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_fdb_entries(&self, count: u64) {
        self.fdb_entries.store(count, Ordering::Relaxed);
    }

    /// Format metrics in Prometheus exposition format.
    pub fn to_prometheus(&self) -> String {
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
             omni_fdb_entries {}\n",
            self.sessions_active.load(Ordering::Relaxed),
            self.packets_rx_total.load(Ordering::Relaxed),
            self.packets_tx_total.load(Ordering::Relaxed),
            self.handshakes_completed.load(Ordering::Relaxed),
            self.handshakes_failed.load(Ordering::Relaxed),
            self.sessions_dropped_ratelimit.load(Ordering::Relaxed),
            self.fdb_entries.load(Ordering::Relaxed),
        )
    }
}
