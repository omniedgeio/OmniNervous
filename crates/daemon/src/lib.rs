pub mod config;
pub mod endpoint;
pub mod handler;
pub mod happy_eyeballs;
pub mod http;
pub mod identity;
pub mod metrics;
pub mod netcheck;
pub mod peers;
pub mod portmap;
pub mod relay;
pub mod signaling;
pub mod socket;
pub mod stun;
pub mod wg;

// Re-export key types for easier access by consumers
pub use config::{Config, TimingConfig};
pub use endpoint::{
    ConnectionState, EndpointInfo, EndpointSet, EndpointSource, PathType, PeerConnection,
};
pub use handler::{DiscoConfig, DiscoResult, MessageHandler, PendingPing};
pub use happy_eyeballs::{ConnectionRace, RaceAction, RacePhase, RaceResult};
pub use identity::Identity;
pub use metrics::Metrics;
pub use netcheck::{NatChecker, NatReport, NatType};
pub use portmap::{PortMapCapabilities, PortMapper, PortMapping};
pub use relay::{RelayClient, RelayConfig, RelayServer, RelaySession};
pub use signaling::{EncryptedEnvelope, NucleusClient, NucleusState, SignalingEncryption};
pub use socket::{DualStackAddr, DualStackSocket, RecvResult};
pub use wg::{CliWgControl, UserspaceWgControl, WgInterface};
