//! Authentication proof types.
//!
//! `AuthProof` is used for per-request authentication. The client signs
//! a canonical message containing the request details, and the server
//! verifies the signature.

use crate::identity::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// A random nonce used in authentication proofs.
///
/// 16 bytes (128 bits) of random data to prevent replay attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomNonce([u8; 16]);

impl RandomNonce {
    /// Generate a new random nonce.
    #[must_use]
    pub fn new() -> Self {
        Self(rand::random::<[u8; 16]>())
    }

    /// Create a nonce from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the raw nonce bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl Default for RandomNonce {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication proof for per-request verification.
///
/// Contains all information needed to verify that a request came from
/// an enrolled client.
///
/// # Note on Public Fields
///
/// Fields are intentionally public for serialization/deserialization.
/// This is a data transfer object - **validation happens in `verify_v1()`**,
/// not at construction time. Constructing an `AuthProof` does NOT mean
/// it's valid; always call `verify_v1()` before trusting the identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProof {
    /// The client's public key.
    pub public_key: PublicKey,
    /// Signature over the canonical message.
    pub signature: Signature,
    /// Unix timestamp in seconds.
    pub timestamp: i64,
    /// Random nonce for replay prevention.
    pub nonce: RandomNonce,
    /// Method being called (e.g., "CreateTask").
    pub method: String,
    /// Path/resource being accessed.
    pub path: String,
    /// Optional SHA-256 hash of the request body.
    pub body_hash: Option<[u8; 32]>,
}

impl std::fmt::Debug for AuthProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthProof")
            .field("public_key", &self.public_key)
            .field("signature", &self.signature)
            .field("timestamp", &self.timestamp)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_hash", &self.body_hash.map(|_| "[hash]"))
            .finish()
    }
}
