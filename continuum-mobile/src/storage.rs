//! Secure storage callback interface.
//!
//! TypeScript implements this trait using expo-secure-store.

use crate::errors::StorageError;

/// Callback interface for secure credential storage.
///
/// TypeScript implements this using expo-secure-store (iOS Keychain / Android Keystore).
///
/// # Thread Safety
///
/// This trait is `Send + Sync` as required by UniFFI for callback interfaces.
/// The TypeScript implementation should dispatch to the main thread if needed
/// (expo-secure-store handles this internally).
///
/// # Implementation Notes
///
/// - On iOS, Keychain operations may need to run on the main thread
/// - expo-secure-store handles this automatically
/// - If implementing a custom storage, ensure thread safety
#[uniffi::export(callback_interface)]
pub trait SecureStorage: Send + Sync {
    /// Get a value from secure storage.
    ///
    /// Returns `Ok(None)` if the key doesn't exist.
    /// Returns `Err(StorageError)` if storage is unavailable.
    fn get(&self, key: String) -> Result<Option<String>, StorageError>;

    /// Set a value in secure storage.
    ///
    /// Overwrites any existing value for the key.
    fn set(&self, key: String, value: String) -> Result<(), StorageError>;

    /// Remove a value from secure storage.
    ///
    /// Returns `Ok(())` even if the key didn't exist.
    fn remove(&self, key: String) -> Result<(), StorageError>;
}
