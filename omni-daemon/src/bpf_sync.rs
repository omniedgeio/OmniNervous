use anyhow::Result;
use log::info;
use omni_common::SessionEntry;
use std::net::IpAddr;

/// Manages synchronization between userspace sessions and BPF maps.
/// NOTE: BPF map sync is temporarily disabled pending aya u64 key support.
/// The daemon will function in userspace mode; XDP decryption remains available
/// but session lookup will use a simpler mechanism.
pub struct BpfSync {
    #[allow(dead_code)]
    sessions: Vec<(u64, SessionEntry)>,
}

impl BpfSync {
    /// Create a new BpfSync instance.
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    /// Initialize with the BPF map from the loaded program.
    #[cfg(target_os = "linux")]
    pub fn init_from_bpf(&mut self, _bpf: &mut aya::Bpf) -> Result<()> {
        // TODO: Implement proper BPF map sync once aya supports u64 keys
        // or we implement a shim using two u32 keys.
        info!("BPF SESSIONS map initialization skipped (u64 key support pending)");
        Ok(())
    }

    /// Add a session to the BPF map.
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
            last_seq: 0,
        };

        // Store in local vec for now (TODO: sync to BPF map)
        self.sessions.push((session_id, entry));
        info!("BPF sync: Stored session {} -> {:?} (local)", session_id, remote_addr);

        Ok(())
    }

    /// Remove a session from the BPF map.
    pub fn remove_session(&mut self, session_id: u64) -> Result<()> {
        self.sessions.retain(|(id, _)| *id != session_id);
        info!("BPF sync: Removed session {} (local)", session_id);
        Ok(())
    }
}
