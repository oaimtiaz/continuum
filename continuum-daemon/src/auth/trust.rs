//! Same-machine trust detection.
//!
//! Provides secure same-machine trust via a shared secret file.
//!
//! # Security
//!
//! - NEVER uses `/tmp` (world-writable)
//! - Only uses `$XDG_RUNTIME_DIR` or `/run/user/$UID`
//! - File permissions: 0600 (owner read/write only)
//! - Directory permissions: 0700 (owner only)

use continuum_auth::identity::Fingerprint;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const LOCAL_TRUST_FILENAME: &str = "local-trust-token";
const SERVER_FINGERPRINT_FILENAME: &str = "server-fingerprint";

/// Manages the local trust token for same-machine detection.
pub struct LocalTrustManager {
    token_path: PathBuf,
    secret: [u8; 32],
}

impl LocalTrustManager {
    /// Create or load the local trust token.
    ///
    /// # Security
    /// - Uses `$XDG_RUNTIME_DIR` exclusively (never `/tmp`)
    /// - Falls back to `/run/user/$UID` if XDG not set
    /// - File permissions: 0600 (owner read/write only)
    /// - Directory permissions: 0700 (owner only)
    ///
    /// # Errors
    /// Returns error if no secure runtime directory is available.
    pub fn new() -> std::io::Result<Self> {
        let runtime_dir = Self::get_secure_runtime_dir()?;

        let continuum_dir = runtime_dir.join("continuum");
        std::fs::create_dir_all(&continuum_dir)?;

        // Set directory permissions (owner only)
        #[cfg(unix)]
        std::fs::set_permissions(&continuum_dir, std::fs::Permissions::from_mode(0o700))?;

        let token_path = continuum_dir.join(LOCAL_TRUST_FILENAME);

        let secret = if token_path.exists() {
            let content = std::fs::read(&token_path)?;
            if content.len() == 32 {
                content.try_into().expect("checked length")
            } else {
                Self::generate_and_write(&token_path)?
            }
        } else {
            Self::generate_and_write(&token_path)?
        };

        Ok(Self { token_path, secret })
    }

    /// Get a secure runtime directory.
    ///
    /// Priority:
    /// 1. `$XDG_RUNTIME_DIR` (Linux standard, tmpfs, user-specific)
    /// 2. `/run/user/$UID` (fallback for systems without XDG)
    /// 3. Error if neither available (do NOT fall back to `/tmp`)
    fn get_secure_runtime_dir() -> std::io::Result<PathBuf> {
        // Try XDG_RUNTIME_DIR first
        if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
            let path = PathBuf::from(&dir);
            if path.exists() && Self::is_secure_directory(&path)? {
                return Ok(path);
            }
        }

        // Try /run/user/$UID
        #[cfg(unix)]
        {
            let uid = unsafe { libc::getuid() };
            let path = PathBuf::from(format!("/run/user/{}", uid));
            if path.exists() && Self::is_secure_directory(&path)? {
                return Ok(path);
            }
        }

        // Do NOT fall back to /tmp - it's world-writable
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No secure runtime directory available. Set $XDG_RUNTIME_DIR.",
        ))
    }

    /// Check if directory is secure (owned by current user, not world-writable).
    #[cfg(unix)]
    fn is_secure_directory(path: &PathBuf) -> std::io::Result<bool> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        let mode = meta.mode();
        let uid = meta.uid();
        let current_uid = unsafe { libc::getuid() };

        // Must be owned by current user
        if uid != current_uid {
            return Ok(false);
        }

        // Must not be world-writable
        if mode & 0o002 != 0 {
            return Ok(false);
        }

        Ok(true)
    }

    #[cfg(not(unix))]
    fn is_secure_directory(_path: &PathBuf) -> std::io::Result<bool> {
        // On non-Unix, assume secure (Windows ACLs handle this differently)
        Ok(true)
    }

    fn generate_and_write(path: &PathBuf) -> std::io::Result<[u8; 32]> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).expect("failed to generate random bytes");

        std::fs::write(path, &secret)?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        Ok(secret)
    }

    /// Get the path to the trust token file.
    pub fn token_path(&self) -> &PathBuf {
        &self.token_path
    }

    /// Write server fingerprint to secure runtime directory for local enrollment.
    ///
    /// Clients can read this file to establish TLS trust without a token.
    pub fn write_server_fingerprint(&self, fingerprint: &Fingerprint) -> std::io::Result<()> {
        let fingerprint_path = self
            .token_path
            .parent()
            .expect("token_path has parent")
            .join(SERVER_FINGERPRINT_FILENAME);

        std::fs::write(&fingerprint_path, fingerprint.to_string())?;

        #[cfg(unix)]
        std::fs::set_permissions(&fingerprint_path, std::fs::Permissions::from_mode(0o600))?;

        Ok(())
    }

    /// Get the raw secret bytes (for testing only).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Generate the expected proof hash that clients should present.
    ///
    /// This is SHA256(secret), not the secret itself.
    pub fn expected_proof(&self) -> [u8; 32] {
        Sha256::digest(&self.secret).into()
    }

    /// Verify a same-machine trust proof.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn verify_proof(&self, proof: &[u8]) -> bool {
        if proof.len() != 32 {
            return false;
        }

        let expected = self.expected_proof();
        let provided: [u8; 32] = proof.try_into().expect("checked length");

        expected.ct_eq(&provided).into()
    }
}

impl std::fmt::Debug for LocalTrustManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalTrustManager")
            .field("token_path", &self.token_path)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_proof_verification() {
        // Create a manager with a known secret for testing
        let secret = [42u8; 32];
        let expected_proof: [u8; 32] = Sha256::digest(&secret).into();

        // Manually create manager (bypassing file system for unit test)
        let manager = LocalTrustManager {
            token_path: PathBuf::from("/tmp/test"),
            secret,
        };

        // Correct proof should verify
        assert!(manager.verify_proof(&expected_proof));

        // Wrong proof should fail
        let wrong_proof = [0u8; 32];
        assert!(!manager.verify_proof(&wrong_proof));

        // Wrong length should fail
        assert!(!manager.verify_proof(&[1, 2, 3]));
    }

    #[test]
    fn test_expected_proof_is_hash_of_secret() {
        let secret = [1u8; 32];
        let manager = LocalTrustManager {
            token_path: PathBuf::from("/tmp/test"),
            secret,
        };

        let expected: [u8; 32] = Sha256::digest(&secret).into();
        assert_eq!(manager.expected_proof(), expected);
    }

    #[test]
    #[cfg(unix)]
    fn test_local_trust_manager_creation() {
        // Only run if XDG_RUNTIME_DIR is set (CI environments may not have it)
        if env::var("XDG_RUNTIME_DIR").is_ok() {
            let manager = LocalTrustManager::new();
            if let Ok(m) = manager {
                assert!(m.token_path.exists());
                // Verify proof round-trip
                let proof = m.expected_proof();
                assert!(m.verify_proof(&proof));
            }
        }
    }
}
