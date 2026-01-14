use anyhow::Result;
use log::info;
use omni_common::{SessionEntry, SessionKey};
use std::net::IpAddr;
use std::collections::HashMap;

/// Manages synchronization between userspace sessions and BPF maps.
/// 
/// NOTE: Full BPF map sync requires aya Pod trait implementations.
/// Currently stores sessions locally; XDP processing uses direct map access.
/// Production deployment will use shared memory or netlink for sync.
pub struct BpfSync {
    // Local session storage (for non-BPF fallback and session management)
    sessions: HashMap<u64, SessionEntry>,
}

impl BpfSync {
    /// Create a new BpfSync instance.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Initialize with the BPF map from the loaded program.
    /// NOTE: Currently a no-op - BPF map sync pending Pod trait implementation.
    #[cfg(target_os = "linux")]
    pub fn init_from_bpf(&mut self, _bpf: &mut aya::Bpf) -> Result<()> {
        // TODO: Implement full BPF map sync when aya Pod support is added
        // This requires either:
        // 1. Adding aya dependency to omni-common (breaks no_std)
        // 2. Using a shim crate with Pod impl for SessionKey
        // 3. Using raw BPF map operations instead of typed HashMap
        info!("BPF SESSIONS map: Using local session storage (BPF sync pending)");
        Ok(())
    }

    /// Add a session to the session manager.
    pub fn insert_session(
        &mut self, 
        session_id: u64,
        key: [u8; 32], 
        remote_addr: IpAddr,
        remote_port: u16
    ) -> Result<()> {
        let addr_bytes = match remote_addr {
            IpAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                bytes[10] = 0xff;
                bytes[11] = 0xff;
                bytes[12..16].copy_from_slice(&v4.octets());
                bytes
            }
            IpAddr::V6(v6) => v6.octets(),
        };

        let entry = SessionEntry {
            key,
            remote_addr: addr_bytes,
            remote_port,
            last_seq: 0,
        };

        self.sessions.insert(session_id, entry);
        info!("Session inserted: {:016x} -> {:?}", session_id, remote_addr);

        // TODO: Sync to BPF map when Pod trait is implemented
        // For now, XDP program will need to be preloaded with session data
        // via alternative mechanism (bpftool, etc.)

        Ok(())
    }

    /// Remove a session from the session manager.
    pub fn remove_session(&mut self, session_id: u64) -> Result<()> {
        self.sessions.remove(&session_id);
        info!("Session removed: {:016x}", session_id);
        Ok(())
    }

    /// Get a session entry by ID.
    pub fn get_session(&self, session_id: u64) -> Option<&SessionEntry> {
        self.sessions.get(&session_id)
    }

    /// Get the SessionKey representation for a session ID.
    pub fn session_key(session_id: u64) -> SessionKey {
        SessionKey::from_u64(session_id)
    }
}
