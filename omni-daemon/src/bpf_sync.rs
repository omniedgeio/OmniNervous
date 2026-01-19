#![allow(dead_code)]
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use aya::Bpf;
#[cfg(target_os = "linux")]
use aya::maps::{XskMap, MapData};

use anyhow::{Result};

/// Lean BPF sync surface for Phase 6.5+ (no-op bindings; safe scaffolding)
#[derive(Default)]
pub struct BpfSync {
    // Linux: bound flag indicates if init_from_bpf ran; non-Linux: unused
    #[cfg(target_os = "linux")]
    bound: bool,
}

impl BpfSync {
    pub fn new() -> Self { Self::default() }

    #[cfg(target_os = "linux")]
    pub fn init_from_bpf(&mut self, _bpf: &mut Bpf) -> Result<()> {
        // In a fuller implementation, bind to BPF maps here.
        self.bound = true;
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

    #[cfg(target_os = "linux")]
    pub fn get_xsk_map(&mut self) -> Option<&mut XskMap<MapData>> {
        // Lean patch: not bound yet, return None to skip AF_XDP path
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
