//! Authentication error types.

/// Errors that can occur during authentication verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthnError {
    /// The signature is invalid.
    #[error("invalid signature")]
    InvalidSignature,

    /// The client is not in the allowlist.
    #[error("not allowlisted")]
    NotAllowlisted,

    /// The timestamp is too old.
    #[error("timestamp expired")]
    TimestampExpired,

    /// The timestamp is too far in the future.
    #[error("timestamp in future")]
    TimestampInFuture,

    /// A replay attack was detected.
    #[error("replay detected")]
    ReplayDetected,

    /// The proof is malformed.
    #[error("malformed proof")]
    MalformedProof,
}
