//! Error types for the mobile client.
//!
//! These are designed for proper UI feedback - each variant maps to
//! a specific user-facing message or action.

use thiserror::Error;

/// Errors from client operations.
///
/// Each variant is designed to map to specific UI feedback:
/// - `NotAuthenticated` → redirect to login
/// - `NetworkUnavailable` → show offline banner
/// - `Timeout` → show retry option
/// - etc.
#[derive(Debug, Error, uniffi::Error)]
pub enum ClientError {
    /// User needs to log in (token missing or 401 response)
    #[error("Not authenticated - please log in")]
    NotAuthenticated,

    /// Network is unavailable (no connectivity)
    #[error("Network unavailable")]
    NetworkUnavailable,

    /// Request timed out (server slow or unresponsive)
    #[error("Request timed out")]
    Timeout,

    /// Server returned an error
    #[error("Server error: {message}")]
    ServerError { message: String },

    /// Attention request was already resolved by another device
    #[error("Already resolved")]
    AlreadyResolved,

    /// Attention request has expired
    #[error("Request expired")]
    Expired,

    /// Target host is offline
    #[error("Host is offline")]
    HostOffline,

    /// mTLS handshake failed (certificate issue)
    #[error("Connection failed: {reason}")]
    MtlsFailed { reason: String },

    /// Not enrolled with the target daemon
    #[error("Not enrolled - scan QR code to enroll")]
    NotEnrolled,

    /// Enrollment failed (daemon rejected)
    #[error("Enrollment failed: {reason}")]
    EnrollmentFailed { reason: String },

    /// Invalid enrollment token (from QR code)
    #[error("Invalid enrollment token")]
    InvalidEnrollmentToken,

    /// Secure storage operation failed
    #[error("Storage error: {message}")]
    StorageError { message: String },
}

/// Errors from secure storage operations.
#[derive(Debug, Error, uniffi::Error)]
pub enum StorageError {
    /// Requested key was not found
    #[error("Key not found")]
    NotFound,

    /// Storage is unavailable (device locked, etc.)
    #[error("Storage unavailable")]
    Unavailable,

    /// Generic storage failure
    #[error("Storage failed: {message}")]
    Failed { message: String },
}

impl From<StorageError> for ClientError {
    fn from(e: StorageError) -> Self {
        ClientError::StorageError {
            message: e.to_string(),
        }
    }
}
