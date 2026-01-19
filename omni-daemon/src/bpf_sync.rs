#![allow(dead_code)]
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use aya::Bpf;
#[cfg(target_os = "linux")]
use aya::maps::{XskMap, MapData};

use anyhow::{Result};

/// Lightweight BPF sync layer placeholder for Phase 6.5 and Phase 7.
/// This keeps API surface stable for existing call sites without pulling
/// in heavy Linux eBPF specifics in this patch.
#[derive(Default)]
pub struct BpfSync {
    // In this lean implementation, we don't hold heavy handles here.
}

impl BpfSync {
    pub fn new() -> Self { Self::default() }

    #[cfg(target_os = "linux")]
    pub fn init_from_bpf(&mut self, _bpf: *mut Bpf) -> Result<()> {
        // In a fuller implementation, bind to BPF maps here.
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn init_from_bpf(&mut self, _bpf: *mut ()) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn set_tun_index(&mut self, _ifindex: u32) -> Result<()> {
        // Update TUN index in BPF map (Phase 6.5)
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn set_tun_index(&mut self, _ifindex: u32) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn set_phys_index(&mut self, _ifindex: u32) -> Result<()> {
        // Update physical iface index in BPF map (Phase 6.5)
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn set_phys_index(&mut self, _ifindex: u32) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn get_xsk_map(&mut self) -> Option<&mut XskMap<MapData>> {
        // Not available in this lean patch; fall back to None to skip specialized path
        None
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

    /// Debug stats accessor (no-op in lean patch)
    pub fn get_debug_stats(&self) -> Result<Vec<u32>> {
        Ok(vec![])
    }

    /// Whether BPF is enabled (false in lean patch)
    pub fn is_bpf_enabled(&self) -> bool { false }

    /// Current number of tracked sessions (0 in lean patch)
    pub fn session_count(&self) -> usize { 0 }

    /// Update both tun and phys indices (helper)
    pub fn update_indices(&mut self, tun_ifindex: u32, phys_ifindex: u32) -> Result<()> {
        self.set_tun_index(tun_ifindex)?;
        self.set_phys_index(phys_ifindex)?;
        Ok(())
    }
 }

impl Default for BpfSync {
    fn default() -> Self { Self::new() }
}
