use anyhow::{Context, Result};
use log::info;
use omni_common::SessionEntry;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use aya::maps::HashMap as BpfHashMap;

/// Manages synchronization between userspace sessions and BPF maps.
pub struct BpfSync {
    #[cfg(target_os = "linux")]
    sessions_map: Option<BpfHashMap<aya::maps::MapData, u64, SessionEntry>>,
}

impl BpfSync {
    /// Create a new BpfSync instance (no-op on non-Linux).
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            sessions_map: None,
        }
    }

    /// Initialize with the BPF map from the loaded program.
    #[cfg(target_os = "linux")]
    pub fn init_from_bpf(&mut self, bpf: &mut aya::Bpf) -> Result<()> {
        let map = bpf.take_map("SESSIONS")
            .context("SESSIONS map not found in BPF program")?;
        let sessions_map: BpfHashMap<_, u32, SessionEntry> = map.try_into()
            .context("Failed to convert SESSIONS map")?;
        self.sessions_map = Some(sessions_map);
        info!("BPF SESSIONS map initialized");
        Ok(())
    }

    /// Add a session to the BPF map.
    pub fn insert_session(
        &mut self, 
        session_id: u64,  // Changed from u32 to u64
        key: [u8; 32], 
        remote_addr: IpAddr,
        remote_port: u16
    ) -> Result<()> {
        let addr_bytes = match remote_addr {
            IpAddr::V4(v4) => {
                let mut bytes = [0u8; 16];
                // IPv4-mapped IPv6: ::ffff:x.x.x.x
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
            last_seq: 0,  // Initialize replay protection counter
        };

        #[cfg(target_os = "linux")]
        if let Some(ref mut map) = self.sessions_map {
            map.insert(&session_id, &entry, 0)
                .context("Failed to insert session into BPF map")?;
            info!("BPF: Inserted session {} -> {:?}", session_id, remote_addr);
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = entry;
            info!("BPF sync skipped (non-Linux): session {}", session_id);
        }

        Ok(())
    }

    /// Remove a session from the BPF map.
    pub fn remove_session(&mut self, session_id: u64) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(ref mut map) = self.sessions_map {
            let _ = map.remove(&session_id); // Ignore if missing
            info!("BPF: Removed session {}", session_id);
        }

        #[cfg(not(target_os = "linux"))]
        info!("BPF sync skipped (non-Linux): remove session {}", session_id);

        Ok(())
    }
}
