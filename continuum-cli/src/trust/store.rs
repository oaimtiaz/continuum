//! Trust store for persisting server fingerprints.
//!
//! This module provides persistent storage for known server fingerprints.
//! With token-embedded fingerprints, TOFU is no longer needed - the fingerprint
//! is verified during the TLS handshake using the enrollment token.

use anyhow::{Context, Result};
use continuum_auth::identity::Fingerprint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Trust store entry for a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedServer {
    /// Server fingerprint (SHA256 of public key)
    pub fingerprint: String,
    /// When the server was first trusted (Unix timestamp)
    pub trusted_at: i64,
    /// Optional label
    pub label: Option<String>,
}

/// Persistent trust store for known servers.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    /// Map of server address -> trusted server info
    servers: HashMap<String, TrustedServer>,
}

impl TrustStore {
    /// Load the trust store from disk, or create a new one if it doesn't exist.
    pub fn load() -> Result<Self> {
        let path = Self::store_path()?;

        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read trust store at {}", path.display()))?;
            let store: TrustStore = toml::from_str(&content)
                .with_context(|| format!("Failed to parse trust store at {}", path.display()))?;
            Ok(store)
        } else {
            Ok(Self::default())
        }
    }

    /// Save the trust store to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::store_path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        let content = toml::to_string_pretty(self).context("Failed to serialize trust store")?;
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write trust store to {}", path.display()))?;

        Ok(())
    }

    /// Get the path to the trust store file.
    fn store_path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("com", "continuum", "continuum")
            .context("Could not determine config directory")?;
        Ok(dirs.config_dir().join("trust.toml"))
    }

    /// Trust a server by storing its fingerprint.
    ///
    /// Called after successful enrollment to persist the server's identity.
    pub fn trust(&mut self, address: &str, fingerprint: &Fingerprint, label: Option<&str>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs() as i64;

        self.servers.insert(
            address.to_string(),
            TrustedServer {
                fingerprint: fingerprint.to_string(),
                trusted_at: now,
                label: label.map(String::from),
            },
        );
    }

    /// Get a trusted server by address.
    pub fn get(&self, address: &str) -> Option<&TrustedServer> {
        self.servers.get(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use continuum_auth::identity::PrivateKey;

    #[test]
    fn test_trust_and_get() {
        let mut store = TrustStore::default();
        let address = "localhost:50051";

        // Generate a real fingerprint from a key
        let key = PrivateKey::generate();
        let fp = Fingerprint::from_public_key(&key.public_key());

        // Initially not trusted
        assert!(store.get(address).is_none());

        // Trust the server
        store.trust(address, &fp, Some("test"));

        // Now should be trusted with correct fingerprint
        let trusted = store.get(address).expect("should be trusted");
        assert_eq!(trusted.fingerprint, fp.to_string());
        assert_eq!(trusted.label.as_deref(), Some("test"));
    }
}
