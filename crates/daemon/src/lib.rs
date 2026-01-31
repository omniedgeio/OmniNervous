pub mod config;
pub mod handler;
pub mod http;
pub mod identity;
pub mod metrics;
pub mod netcheck;
pub mod peers;
pub mod relay;
pub mod signaling;
pub mod stun;
pub mod wg;

// Re-export key types for easier access by consumers
pub use config::{Config, TimingConfig};
pub use handler::{DiscoConfig, DiscoResult, MessageHandler, PendingPing};
pub use identity::Identity;
pub use metrics::Metrics;
pub use netcheck::{NatChecker, NatReport, NatType};
pub use relay::{RelayClient, RelayConfig, RelayServer, RelaySession};
pub use signaling::{NucleusClient, NucleusState};
pub use wg::{CliWgControl, UserspaceWgControl, WgInterface};
