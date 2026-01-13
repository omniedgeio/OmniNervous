use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use log::warn;

/// Configuration for rate limiting.
pub struct RateLimitConfig {
    pub max_sessions_per_ip: u32,
    pub window_duration: Duration,
    pub handshake_timeout: Duration,
    pub session_max_age: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_sessions_per_ip: 10,
            window_duration: Duration::from_secs(1),
            handshake_timeout: Duration::from_secs(5),
            session_max_age: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Tracks rate limiting state per source IP.
struct IpRateState {
    count: u32,
    window_start: Instant,
}

/// Rate limiter for DoS protection.
pub struct RateLimiter {
    config: RateLimitConfig,
    ip_states: HashMap<IpAddr, IpRateState>,
    session_creation_times: HashMap<u32, Instant>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_states: HashMap::new(),
            session_creation_times: HashMap::new(),
        }
    }

    /// Check if a new session from this IP should be allowed.
    pub fn allow_new_session(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        
        let state = self.ip_states.entry(ip).or_insert_with(|| IpRateState {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(state.window_start) >= self.config.window_duration {
            state.count = 0;
            state.window_start = now;
        }

        // Check rate limit
        if state.count >= self.config.max_sessions_per_ip {
            warn!("Rate limit exceeded for IP: {}", ip);
            return false;
        }

        state.count += 1;
        true
    }

    /// Record when a session was created (for timeout tracking).
    pub fn record_session_start(&mut self, session_id: u32) {
        self.session_creation_times.insert(session_id, Instant::now());
    }

    /// Check if a handshake has timed out.
    pub fn is_handshake_timeout(&self, session_id: u32) -> bool {
        if let Some(start_time) = self.session_creation_times.get(&session_id) {
            Instant::now().duration_since(*start_time) > self.config.handshake_timeout
        } else {
            false
        }
    }

    /// Get list of expired sessions.
    pub fn expired_sessions(&self) -> Vec<u32> {
        let now = Instant::now();
        self.session_creation_times
            .iter()
            .filter(|(_, start)| now.duration_since(**start) > self.config.session_max_age)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Remove a session from tracking.
    pub fn remove_session(&mut self, session_id: u32) {
        self.session_creation_times.remove(&session_id);
    }

    /// Clean up stale IP tracking entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = self.config.window_duration * 2;
        self.ip_states.retain(|_, state| {
            now.duration_since(state.window_start) < window
        });
    }
}
