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
    #[serde(default = "default_stun")]
    pub stun_server: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            nucleus: None,
            cluster: None,
            stun_server: default_stun(),
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
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            identity_path: None,
            max_sessions_per_ip: default_rate_limit(),
            handshake_timeout_secs: default_handshake_timeout(),
        }
    }
}

/// Peer configuration.
#[derive(Debug, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<Vec<String>>,
}

fn default_port() -> u16 { 51820 }
fn default_iface() -> String { "eth0".to_string() }
fn default_stun() -> String { "stun.l.google.com:19302".to_string() }
fn default_rate_limit() -> u32 { 10 }
fn default_handshake_timeout() -> u64 { 5 }

impl Config {
    /// Load configuration from a TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .context(format!("Failed to read config file: {:?}", path.as_ref()))?;
        let config: Config = toml::from_str(&content)
            .context("Failed to parse TOML config")?;
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
