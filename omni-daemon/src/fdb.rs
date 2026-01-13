use std::collections::HashMap;
use std::net::SocketAddr;
use log::info;

/// Represents an entry in the Forwarding Database.
#[derive(Debug, Clone)]
pub struct FdbRecord {
    pub session_id: u32,
    pub endpoint: SocketAddr,
    pub last_seen: std::time::Instant,
}

/// The Forwarding Database for L2 switching.
pub struct Fdb {
    table: HashMap<[u8; 6], FdbRecord>,
}

impl Fdb {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    /// Learn a MAC address and associate it with a session.
    pub fn learn(&mut self, mac: [u8; 6], session_id: u32, endpoint: SocketAddr) {
        let record = FdbRecord {
            session_id,
            endpoint,
            last_seen: std::time::Instant::now(),
        };
        self.table.insert(mac, record);
        info!("FDB learned: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> session {}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], session_id);
    }

    /// Lookup a MAC address to find the session and endpoint.
    pub fn lookup(&self, mac: &[u8; 6]) -> Option<&FdbRecord> {
        self.table.get(mac)
    }

    /// Remove stale entries older than the given duration.
    pub fn expire(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        self.table.retain(|_, record| now.duration_since(record.last_seen) < max_age);
    }

    /// Get the number of entries in the FDB.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Check if the FDB is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}
