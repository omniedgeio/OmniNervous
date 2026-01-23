pub mod identity;
pub mod metrics;
pub mod config;
pub mod http;
pub mod peers;
pub mod signaling;
pub mod handler;
pub mod wg;
pub mod stun;

// Re-export key types for easier access by consumers
pub use identity::Identity;
pub use config::Config;
pub use signaling::{NucleusState, NucleusClient};
pub use wg::{WgInterface, CliWgControl, UserspaceWgControl};
pub use handler::MessageHandler;
pub use metrics::Metrics;
