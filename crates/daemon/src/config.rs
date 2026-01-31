use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Top-level configuration for OmniNervous daemon.
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub timing: TimingConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

/// Daemon runtime settings.
#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_iface")]
    pub interface: String,
    #[serde(default)]
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            interface: default_iface(),
            log_level: "info".to_string(),
        }
    }
}

/// Network configuration.
#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub nucleus: Option<String>,
    pub cluster: Option<String>,
    /// IPv4 STUN servers
    #[serde(default = "default_stuns")]
    pub stun_servers: Vec<String>,
    /// IPv6 STUN servers (Phase 7)
    #[serde(default = "default_stuns_v6")]
    pub stun_servers_v6: Vec<String>,
    #[serde(default = "default_true")]
    pub use_builtin_stun: bool,
    /// Enable IPv6 support (Phase 7)
    #[serde(default = "default_true")]
    pub enable_ipv6: bool,
    /// Prefer IPv6 connections when available (Phase 7)
    #[serde(default = "default_true")]
    pub prefer_ipv6: bool,
    /// Happy Eyeballs delay in milliseconds (Phase 7)
    #[serde(default = "default_happy_eyeballs_delay")]
    pub happy_eyeballs_delay_ms: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            nucleus: None,
            cluster: None,
            stun_servers: default_stuns(),
            stun_servers_v6: default_stuns_v6(),
            use_builtin_stun: true,
            enable_ipv6: true,
            prefer_ipv6: true,
            happy_eyeballs_delay_ms: default_happy_eyeballs_delay(),
        }
    }
}

/// Security settings.
#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    pub identity_path: Option<String>,
    #[serde(default = "default_rate_limit")]
    pub max_sessions_per_ip: u32,
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    /// Enable encryption for signaling messages (nacl box)
    #[serde(default)]
    pub encrypt_signaling: bool,
    /// Path to encryption keypair file (auto-generated if not exists)
    pub encryption_key_path: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            identity_path: None,
            max_sessions_per_ip: default_rate_limit(),
            handshake_timeout_secs: default_handshake_timeout(),
            encrypt_signaling: false,
            encryption_key_path: None,
        }
    }
}

/// Timing configuration for NAT traversal and keepalives.
///
/// These values are tuned for optimal NAT traversal performance:
/// - WireGuard keepalive: 20s (within typical 30-60s NAT timeout)
/// - Heartbeat: 25s (slightly longer, includes peer state)
/// - STUN refresh: 120s (detect endpoint changes from NAT rebinding)
/// - Disco ping timeout: 5s (reasonable for global RTT)
/// - Disco retries: 3 (total 15s before fallback)
#[derive(Debug, Deserialize, Clone)]
pub struct TimingConfig {
    /// WireGuard persistent keepalive interval in seconds
    /// Default: 20 (reduced from WG default of 25 for better NAT traversal)
    #[serde(default = "default_wg_keepalive")]
    pub wg_keepalive_secs: u64,

    /// Heartbeat interval to Nucleus in seconds
    /// Default: 25 (reduced from 30 for faster peer discovery)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// STUN refresh interval in seconds
    /// Default: 120 (reduced from 300 for faster endpoint change detection)
    #[serde(default = "default_stun_refresh")]
    pub stun_refresh_secs: u64,

    /// Disco ping timeout in seconds
    /// Default: 5
    #[serde(default = "default_ping_timeout")]
    pub ping_timeout_secs: u64,

    /// Number of disco ping retries before fallback
    /// Default: 3
    #[serde(default = "default_ping_retries")]
    pub ping_retries: u32,

    /// Cleanup interval for expired entries in seconds
    /// Default: 60
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,

    /// Peer timeout before removal in seconds
    /// Default: 120
    #[serde(default = "default_peer_timeout")]
    pub peer_timeout_secs: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            wg_keepalive_secs: default_wg_keepalive(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            stun_refresh_secs: default_stun_refresh(),
            ping_timeout_secs: default_ping_timeout(),
            ping_retries: default_ping_retries(),
            cleanup_interval_secs: default_cleanup_interval(),
            peer_timeout_secs: default_peer_timeout(),
        }
    }
}

impl TimingConfig {
    /// Get WireGuard keepalive as Duration
    pub fn wg_keepalive(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.wg_keepalive_secs)
    }

    /// Get heartbeat interval as Duration
    pub fn heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.heartbeat_interval_secs)
    }

    /// Get STUN refresh interval as Duration
    pub fn stun_refresh(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.stun_refresh_secs)
    }

    /// Get disco ping timeout as Duration
    pub fn ping_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.ping_timeout_secs)
    }

    /// Get cleanup interval as Duration
    pub fn cleanup_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.cleanup_interval_secs)
    }

    /// Get peer timeout as Duration
    pub fn peer_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.peer_timeout_secs)
    }
}

/// Peer configuration.
#[derive(Debug, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
}

fn default_port() -> u16 {
    51820
}
fn default_iface() -> String {
    "eth0".to_string()
}
fn default_stuns() -> Vec<String> {
    vec![]
}
fn default_stuns_v6() -> Vec<String> {
    // Default IPv6 STUN servers
    // Google and Cloudflare provide reliable dual-stack STUN
    vec![
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
    ]
}
fn default_happy_eyeballs_delay() -> u64 {
    250 // RFC 8305 recommended delay in milliseconds
}
fn default_true() -> bool {
    true
}
fn default_rate_limit() -> u32 {
    10
}
fn default_handshake_timeout() -> u64 {
    5
}

// Timing defaults - tuned for optimal NAT traversal
fn default_wg_keepalive() -> u64 {
    20 // Reduced from 25 for better NAT traversal
}
fn default_heartbeat_interval() -> u64 {
    25 // Reduced from 30 for faster peer discovery
}
fn default_stun_refresh() -> u64 {
    120 // Reduced from 300 for faster endpoint change detection
}
fn default_ping_timeout() -> u64 {
    5 // 5 seconds per ping attempt
}
fn default_ping_retries() -> u32 {
    3 // 3 retries = 15 seconds total before fallback
}
fn default_cleanup_interval() -> u64 {
    60 // Cleanup expired entries every minute
}
fn default_peer_timeout() -> u64 {
    120 // Remove peers after 2 minutes of inactivity
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .context(format!("Failed to read config file: {:?}", path.as_ref()))?;
        let config: Config = toml::from_str(&content).context("Failed to parse TOML config")?;
        Ok(config)
    }

    /// Load from default paths or return default config.
    pub fn load_or_default() -> Self {
        let paths = [
            "/etc/omni/config.toml",
            "~/.omni/config.toml",
            "./config.toml",
        ];

        for path in &paths {
            let expanded = shellexpand::tilde(path).to_string();
            if Path::new(&expanded).exists() {
                if let Ok(config) = Self::load(&expanded) {
                    return config;
                }
            }
        }

        Self::default()
    }
}
