#![allow(dead_code)]
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use aya::Bpf;
#[cfg(target_os = "linux")]
use aya::maps::{XskMap, MapData};

use anyhow::{Context, Result};

/// Lean BPF sync surface for Phase 6.5+ (no-op bindings; safe scaffolding)
pub struct BpfSync {
    // Linux: bound flag indicates if init_from_bpf ran; non-Linux: unused
    #[cfg(target_os = "linux")]
    bound: bool,
    #[cfg(target_os = "linux")]
    debug_stats: bool, // Just track if DEBUG_STATS map exists
}

impl BpfSync {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            bound: false,
            #[cfg(target_os = "linux")]
            debug_stats: false,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn init_from_bpf(&mut self, bpf: &mut Bpf) -> Result<()> {
        // Check if DEBUG_STATS map exists for performance instrumentation
        self.debug_stats = bpf.map("DEBUG_STATS").is_some();
        self.bound = true;
        if self.debug_stats {
            log::info!("BPF: DEBUG_STATS map available for performance instrumentation");
        } else {
            log::warn!("BPF: DEBUG_STATS map not found");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn init_from_bpf(&mut self, _bpf: *mut ()) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn set_tun_index(&mut self, _ifindex: u32) -> Result<()> {
        // Update TUN index in BPF map (Phase 6.5): no-op in lean patch
        if self.bound {
            log::info!("BPF: would set TUN index to {}", _ifindex);
        } else {
            log::info!("Phase6.5: BPF not bound yet; skipping TUN index {}", _ifindex);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn set_tun_index(&mut self, _ifindex: u32) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn set_phys_index(&mut self, _ifindex: u32) -> Result<()> {
        if self.bound {
            log::info!("BPF: would set PHYS index to {}", _ifindex);
        } else {
            log::info!("Phase6.5: BPF not bound yet; skipping PHYS index {}", _ifindex);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn set_phys_index(&mut self, _ifindex: u32) -> Result<()> {
        Ok(())
    }


    #[cfg(not(target_os = "linux"))]
    pub fn get_xsk_map(&mut self) -> Option<&mut XskMap<MapData>> {
        None
    }

    /// Insert a session entry and optionally sync to BPF map (no-op in lean patch)
    pub fn insert_session(&mut self, _session_id: u64, _key: [u8; 32], _remote_addr: IpAddr, _remote_port: u16) -> Result<()> {
        Ok(())
    }

    /// Remove a session entry (no-op in lean patch)
    pub fn remove_session(&mut self, _session_id: u64) -> Result<()> {
        Ok(())
    }

    /// Debug stats accessor - returns basic status indicators
    pub fn get_debug_stats(&self) -> Result<Vec<u32>> {
        // Return basic connectivity and map status
        #[cfg(target_os = "linux")]
        {
            if self.bound {
                let debug_map_status = if self.debug_stats { 1 } else { 0 };
                Ok(vec![1, debug_map_status, 0, 0, 0, 0, 0, 0, 0, 0, 0]) // [bound, debug_stats, ...]
            } else {
                Ok(vec![0; 11])
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(vec![0; 11])
        }
    }

    /// Whether BPF is enabled (true if init_from_bpf bound)
    pub fn is_bpf_enabled(&self) -> bool { #[cfg(target_os = "linux")] { self.bound } #[cfg(not(target_os = "linux"))] { false } }

    /// Current number of tracked sessions (0 in lean patch)
    pub fn session_count(&self) -> usize { 0 }

    /// Update both tun and phys indices (helper)
    pub fn update_indices(&mut self, tun_ifindex: u32, phys_ifindex: u32) -> Result<()> {
        self.set_tun_index(tun_ifindex).context("set_tun_index failed")?;
        self.set_phys_index(phys_ifindex).context("set_phys_index failed")?;
        Ok(())
    }
 }

impl Default for BpfSync {
    fn default() -> Self { Self::new() }
}
