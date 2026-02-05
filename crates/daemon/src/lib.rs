//! # OmniNervous Daemon
//!
//! Core networking daemon for OmniEdge mesh VPN, providing NAT traversal,
//! peer discovery, and secure communication primitives.
//!
//! ## Key Components
//!
//! ### NAT Traversal
//! - [`NatChecker`] - Detect NAT type using STUN servers
//! - [`PortMapper`] - NAT-PMP/UPnP port mapping
//! - [`RelayServer`] / [`RelayClient`] - Relay fallback for symmetric NAT
//!
//! ### Peer Communication
//! - [`NucleusClient`] - Connection to signaling server
//! - [`SignalingEncryption`] - End-to-end encrypted signaling
//! - [`MessageHandler`] - Disco ping/pong handling
//!
//! ### Connectivity
//! - [`DualStackSocket`] - IPv4/IPv6 dual-stack support
//! - [`ConnectionRace`] - Happy Eyeballs (RFC 8305) implementation
//! - [`EndpointSet`] - Multi-path endpoint management
//!
//! ## Example
//!
//! ```rust,ignore
//! use omninervous::{Config, NatChecker, NucleusClient, Identity};
//!
//! // Load configuration
//! let config = Config::load("config.toml")?;
//!
//! // Create identity
//! let identity = Identity::generate();
//!
//! // Check NAT type
//! let checker = NatChecker::new(&config.network.stun_servers);
//! let report = checker.check().await?;
//! println!("NAT Type: {:?}", report.nat_type);
//! ```

pub mod config;
pub mod endpoint;
pub mod handler;
pub mod happy_eyeballs;
pub mod http;
pub mod identity;
pub mod ipv6_utils;
pub mod metrics;
pub mod netcheck;
pub mod peers;
pub mod portmap;
pub mod relay;
pub mod signaling;
pub mod socket;
pub mod stun;
pub mod wg;
#[cfg(all(feature = "l2-vpn", target_os = "linux"))]
pub mod l2;


// ============================================================================
// Configuration
// ============================================================================

pub use config::{Config, DaemonConfig, NetworkConfig, PeerConfig, SecurityConfig, TimingConfig};

// ============================================================================
// Endpoint Management
// ============================================================================

pub use endpoint::{
    ConnectionState, EndpointInfo, EndpointSet, EndpointSource, EndpointState, PathType,
    PeerConnection,
};

// ============================================================================
// Message Handling
// ============================================================================

pub use handler::{DiscoConfig, DiscoResult, MessageHandler, PendingPing};

// ============================================================================
// Happy Eyeballs (RFC 8305)
// ============================================================================

pub use happy_eyeballs::{ConnectionRace, RaceAction, RacePhase, RaceResult};

// ============================================================================
// Identity
// ============================================================================

pub use identity::Identity;

// ============================================================================
// Metrics
// ============================================================================

pub use metrics::Metrics;

// ============================================================================
// NAT Checking
// ============================================================================

pub use netcheck::{NatChecker, NatReport, NatType};

// ============================================================================
// Peer Management
// ============================================================================

pub use peers::{PeerEntry, PeerTable};

// ============================================================================
// Port Mapping
// ============================================================================

pub use portmap::{PortMapCapabilities, PortMapProtocol, PortMapper, PortMapping};

// ============================================================================
// Relay
// ============================================================================

pub use relay::{
    RelayClient, RelayClientState, RelayConfig, RelayServer, RelaySession, RelayStats, SessionId,
};

// ============================================================================
// Signaling
// ============================================================================

pub use signaling::{
    EncryptedEnvelope, NucleusClient, NucleusState, RuntimeState, SignalingEncryption,
};
#[cfg(all(feature = "l2-vpn", target_os = "linux"))]
pub use l2::{L2ConfigSnapshot, L2FrameHandler, L2FrameStats, L2Transport};

// ============================================================================
// Socket Utilities
// ============================================================================

pub use socket::{DualStackAddr, DualStackSocket, RecvResult};


// ============================================================================
// IPv6 Utilities
// ============================================================================

pub use ipv6_utils::{
    is_documentation, is_global_unicast, is_link_local, is_loopback, is_unspecified, is_valid_ula,
    is_valid_virtual_ip,
};

// ============================================================================
// WireGuard
// ============================================================================

pub use wg::{CliWgControl, PeerStats, UserspaceWgControl, WgInterface};

// ============================================================================
// Message Type Detection Utilities
// ============================================================================

pub use relay::is_relay_message;
pub use signaling::{get_signaling_type, is_signaling_message};
