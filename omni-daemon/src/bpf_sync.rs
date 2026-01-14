use anyhow::{Result};
use log::info;
use omni_common::{SessionEntry};
use std::collections::HashMap;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use aya::maps::HashMap as BpfHashMap;

/// Manages synchronization between userspace sessions and BPF maps.
/// 
/// On Linux with eBPF enabled, sessions are synced to BPF maps for XDP processing.
/// On other platforms, sessions are stored locally for userspace processing.
pub struct BpfSync {
    // Local session storage for fallback/lookup
    sessions: HashMap<u64, SessionEntry>,
    
    // BPF map handle (Linux only, set after eBPF init)
    #[cfg(target_os = "linux")]
    bpf_sessions: Option<BpfHashMap<aya::maps::MapData, SessionKey, SessionEntry>>,
}

impl BpfSync {
    /// Create a new BpfSync instance.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            #[cfg(target_os = "linux")]
            bpf_sessions: None,
        }
    }

    /// Initialize with the BPF map from the loaded program.
    #[cfg(target_os = "linux")]
    pub fn init_from_bpf(&mut self, bpf: &mut aya::Bpf) -> Result<()> {
        let map = bpf.take_map("SESSIONS")
            .context("SESSIONS map not found in BPF program")?;
        
        // Convert the map to the typed HashMap
        let sessions_map: BpfHashMap<_, SessionKey, SessionEntry> = map.try_into()
            .context("Failed to convert SESSIONS map to typed HashMap")?;
        
        self.bpf_sessions = Some(sessions_map);
        info!("BPF SESSIONS map initialized with full sync capability");
        Ok(())
    }

    /// Add a session to both local storage and BPF map.
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

        // Store locally
        self.sessions.insert(session_id, entry);
        
        // Sync to BPF map if available
        #[cfg(target_os = "linux")]
        if let Some(ref mut map) = self.bpf_sessions {
            let session_key = SessionKey::from_u64(session_id);
            map.insert(&session_key, &entry, 0)
                .context("Failed to insert session into BPF map")?;
            info!("BPF: Synced session {:016x} -> {:?}", session_id, remote_addr);
        }

        #[cfg(not(target_os = "linux"))]
        info!("Session inserted: {:016x} -> {:?}", session_id, remote_addr);

        Ok(())
    }

    /// Remove a session from both local storage and BPF map.
    pub fn remove_session(&mut self, session_id: u64) -> Result<()> {
        self.sessions.remove(&session_id);
        
        #[cfg(target_os = "linux")]
        if let Some(ref mut map) = self.bpf_sessions {
            let session_key = SessionKey::from_u64(session_id);
            let _ = map.remove(&session_key); // Ignore if missing
            info!("BPF: Removed session {:016x}", session_id);
        }

        #[cfg(not(target_os = "linux"))]
        info!("Session removed: {:016x}", session_id);
        
        Ok(())
    }

    /// Get a session entry by ID from local storage.
    pub fn get_session(&self, session_id: u64) -> Option<&SessionEntry> {
        self.sessions.get(&session_id)
    }

    /// Check if BPF sync is available (Linux with eBPF loaded).
    pub fn is_bpf_enabled(&self) -> bool {
        #[cfg(target_os = "linux")]
        { self.bpf_sessions.is_some() }
        
        #[cfg(not(target_os = "linux"))]
        { false }
    }
    
    /// Get count of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for BpfSync {
    fn default() -> Self {
        Self::new()
    }
}
