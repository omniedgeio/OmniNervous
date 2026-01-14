//! Cross-platform virtual network interface (TUN)
//!
//! Provides Layer 3 TUN interface support:
//! - Linux: TUN via /dev/net/tun
//! - macOS: utun via socket API
//! - Windows: Wintun driver (requires wintun.dll)
//!
//! Note: Layer 2 TAP support requires tap-windows driver on Windows
//! and is planned for future implementation.

use anyhow::{Context, Result};
use log::info;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use log::warn;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Virtual network interface configuration
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name (e.g., "omni0")
    pub name: String,
    /// Virtual IP address
    pub address: Ipv4Addr,
    /// Network mask
    pub netmask: Ipv4Addr,
    /// MTU (default: 1420 for WireGuard compatibility)
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "omni0".to_string(),
            address: Ipv4Addr::new(10, 200, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1420,
        }
    }
}

/// Cross-platform virtual network interface (Layer 3 TUN)
pub struct VirtualInterface {
    device: tun2::AsyncDevice,
    config: TunConfig,
}

impl VirtualInterface {
    /// Create and configure a virtual network interface
    pub async fn create(config: TunConfig) -> Result<Self> {
        info!("Creating TUN interface '{}' with IP {}/{}", 
              config.name, config.address, config.netmask);
        
        let mut tun_config = tun2::Configuration::default();
        
        tun_config
            .tun_name(&config.name)
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();
        
        // Platform-specific configuration
        #[cfg(target_os = "linux")]
        tun_config.platform_config(|p| {
            p.packet_information(false);
        });
        
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.packet_information(false);
        });
        
        let device = tun2::create_as_async(&tun_config)
            .context("Failed to create TUN device")?;
        
        info!("✅ TUN interface '{}' created successfully", config.name);
        info!("   Address: {}/{}", config.address, config.netmask);
        info!("   MTU: {}", config.mtu);
        
        Ok(Self { device, config })
    }
    
    /// Read a packet from the virtual interface
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.device.read(buf).await
            .context("Failed to read from TUN device")?;
        Ok(n)
    }
    
    /// Write a packet to the virtual interface
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.device.write(buf).await
            .context("Failed to write to TUN device")?;
        Ok(n)
    }
    
    /// Get interface name
    pub fn name(&self) -> &str {
        &self.config.name
    }
    
    /// Get interface IP address
    pub fn address(&self) -> Ipv4Addr {
        self.config.address
    }
    
    /// Get interface netmask
    pub fn netmask(&self) -> Ipv4Addr {
        self.config.netmask
    }
}

/// Check if we have permission to create TUN devices
pub fn check_tun_permissions() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if fs::metadata("/dev/net/tun").is_err() {
            anyhow::bail!("TUN device not available. Is the tun module loaded?");
        }
        if unsafe { libc::geteuid() } != 0 {
            warn!("Not running as root. TUN creation may fail without CAP_NET_ADMIN.");
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::geteuid() } != 0 {
            anyhow::bail!("Root privileges required for TUN device on macOS");
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        // Check for wintun.dll
        if !std::path::Path::new("wintun.dll").exists() {
            warn!("wintun.dll not found in current directory. TUN creation may fail.");
            warn!("Download from: https://www.wintun.net/");
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert_eq!(config.name, "omni0");
        assert_eq!(config.address, Ipv4Addr::new(10, 200, 0, 1));
        assert_eq!(config.mtu, 1420);
    }
}
