//! Enrollment error types.

/// Errors that can occur during enrollment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnrollmentError {
    /// The enrollment token has expired.
    #[error("token expired")]
    TokenExpired,

    /// The provided token does not match any pending session.
    #[error("invalid token")]
    InvalidToken,

    /// The signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,
}
