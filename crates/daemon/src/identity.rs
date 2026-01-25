use anyhow::{Context, Result};
use log::info;
use std::fs;
use std::path::PathBuf;
use rand::rngs::OsRng;
use rand::RngCore;

/// Default path for identity key storage
const DEFAULT_IDENTITY_DIR: &str = ".omni";
const IDENTITY_FILE: &str = "identity.key";

/// Represents the local node's cryptographic identity.
#[derive(Debug)]
pub struct Identity {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl Identity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);
        
        Self::from_private_key(private_key)
    }

    /// Create identity from existing private key.
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let public_key = Self::derive_public_key(&private_key);
        Self { private_key, public_key }
    }

    /// Derive public key from private key (X25519).
    /// Uses the X25519 base point multiplication to get the public key.
    fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        // Use snow's DH function to derive public key from private key
        // This creates a proper X25519 keypair relationship
        use snow::resolvers::{DefaultResolver, CryptoResolver};
        use snow::params::DHChoice;
        
        let resolver = DefaultResolver;
        let mut dh = resolver.resolve_dh(&DHChoice::Curve25519).unwrap();
        dh.set(private_key);
        
        let mut pk = [0u8; 32];
        pk.copy_from_slice(dh.pubkey());
        pk
    }

    /// Get the default identity path.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_IDENTITY_DIR)
    }

    /// Load identity from disk.
    pub fn load(path: Option<&PathBuf>) -> Result<Self> {
        let base_path = path.cloned().unwrap_or_else(Self::default_path);
        let key_path = base_path.join(IDENTITY_FILE);

        let data = fs::read(&key_path)
            .context(format!("Failed to read identity from {:?}", key_path))?;

        if data.len() != 64 {
            anyhow::bail!("Invalid identity file: expected 64 bytes, got {}", data.len());
        }

        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        private_key.copy_from_slice(&data[0..32]);
        public_key.copy_from_slice(&data[32..64]);

        // Validate keypair integrity
        let derived = Self::derive_public_key(&private_key);
        if derived != public_key {
            anyhow::bail!("Invalid identity file: public key does not match private key. The file may be corrupted.");
        }



        info!("Loaded identity from {:?}", key_path);
        Ok(Self { private_key, public_key })
    }

    /// Save identity to disk.
    pub fn save(&self, path: Option<&PathBuf>) -> Result<()> {
        let base_path = path.cloned().unwrap_or_else(Self::default_path);
        
        // Create directory if it doesn't exist
        fs::create_dir_all(&base_path)
            .context("Failed to create identity directory")?;

        let key_path = base_path.join(IDENTITY_FILE);
        
        // Combine private + public key
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&self.private_key);
        data.extend_from_slice(&self.public_key);

        fs::write(&key_path, &data)
            .context(format!("Failed to write identity to {:?}", key_path))?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&key_path, perms)?;
        }

        info!("Saved identity to {:?}", key_path);
        Ok(())
    }

    /// Load or generate identity.
    pub fn load_or_generate(path: Option<&PathBuf>) -> Result<Self> {
        match Self::load(path) {
            Ok(id) => Ok(id),
            Err(_) => {
                info!("Generating new identity...");
                let id = Self::generate();
                id.save(path)?;
                Ok(id)
            }
        }
    }

    /// Format public key as hex string for display.
    pub fn public_key_hex(&self) -> String {
        self.public_key.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Get raw public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key
    }

    /// Get raw private key bytes.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key
    }
}
