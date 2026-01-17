//! Authentication verification.
//!
//! This module provides traits and functions for verifying `AuthProof`.

use crate::identity::Fingerprint;

use super::error::AuthnError;
use super::proof::AuthProof;

/// Maximum allowed method length (fits in u8).
const MAX_METHOD_LEN: usize = 255;

/// Maximum allowed path length (fits in u16).
const MAX_PATH_LEN: usize = 65535;

/// Trait for checking if a fingerprint is in the client allowlist.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` for concurrent verification.
pub trait Allowlist: Send + Sync {
    /// Check if the given fingerprint is allowed.
    fn contains(&self, fingerprint: &Fingerprint) -> bool;
}

/// Trait for replay detection.
///
/// # Thread Safety
///
/// Uses `&self` to allow concurrent access. Implementations should
/// use interior mutability (e.g., `Mutex`, `DashMap`).
///
/// # Atomicity
///
/// The `check_and_insert` operation **MUST be atomic**. Specifically:
/// - The check and insert must happen as a single logical operation
/// - No other thread should be able to observe a state where the nonce
///   has been checked but not yet inserted
/// - Use atomic compare-and-swap patterns, or hold a lock across both operations
///
/// Non-atomic implementations create a TOCTOU race condition where two
/// concurrent requests with the same nonce could both pass the check.
///
/// # Retention
///
/// Entries should be retained for at least `2 * max_skew_seconds`
/// to prevent replay attacks at the edge of the validity window.
pub trait ReplayCache: Send + Sync {
    /// Check if the nonce is new and record it atomically.
    ///
    /// Returns `true` if the nonce was new and has been recorded.
    /// Returns `false` if this is a replay (nonce already seen).
    ///
    /// # Atomicity
    ///
    /// This operation must be atomic - see trait documentation for details.
    fn check_and_insert(&self, fingerprint: &Fingerprint, nonce: &[u8; 16], timestamp: i64)
    -> bool;
}

/// Result of successful authentication verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity(Fingerprint);

impl VerifiedIdentity {
    /// Create a new verified identity.
    ///
    /// # Visibility
    ///
    /// This constructor is crate-private to ensure `VerifiedIdentity` can only
    /// be created through the `verify_v1()` function, which performs cryptographic
    /// verification. This prevents accidental authentication bypasses.
    #[must_use]
    pub(crate) fn new(fingerprint: Fingerprint) -> Self {
        Self(fingerprint)
    }

    /// Get the verified fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.0
    }

    /// Consume and return the fingerprint.
    #[must_use]
    pub fn into_fingerprint(self) -> Fingerprint {
        self.0
    }
}

/// Magic preamble for authentication messages.
const AUTH_MAGIC: &[u8; 16] = b"CONTINUUM-AUTH\x00\x00";

/// Protocol version for v1 authentication.
const AUTH_VERSION_V1: u8 = 0x01;

/// Build the canonical message that gets signed.
///
/// Wire format (all multi-byte integers are big-endian):
///
/// | Field          | Size | Description                            |
/// |----------------|------|----------------------------------------|
/// | magic          | 16   | "CONTINUUM-AUTH\x00\x00"               |
/// | version        | 1    | Protocol version (0x01 for v1)         |
/// | timestamp      | 8    | Unix timestamp in seconds (i64 BE)     |
/// | nonce          | 16   | Random nonce bytes                     |
/// | method_len     | 1    | Length of method string (max 255)      |
/// | method         | var  | UTF-8 method string                    |
/// | path_len       | 2    | Length of path string (u16 BE)         |
/// | path           | var  | UTF-8 path string                      |
/// | body_hash_flag | 1    | 0x00=no body, 0x01=body present        |
/// | body_hash      | 32   | SHA-256 of body (if flag==0x01)        |
///
/// # Errors
///
/// Returns `AuthnError::MalformedProof` if:
/// - Method length exceeds 255 bytes
/// - Path length exceeds 65535 bytes
pub fn build_canonical_message(
    timestamp: i64,
    nonce: &[u8; 16],
    method: &str,
    path: &str,
    body_hash: Option<&[u8; 32]>,
) -> Result<Vec<u8>, AuthnError> {
    let method_bytes = method.as_bytes();
    let path_bytes = path.as_bytes();

    // Validate lengths before encoding to prevent silent truncation
    if method_bytes.len() > MAX_METHOD_LEN {
        return Err(AuthnError::MalformedProof);
    }
    if path_bytes.len() > MAX_PATH_LEN {
        return Err(AuthnError::MalformedProof);
    }

    let mut msg = Vec::with_capacity(128);

    // Magic preamble (16 bytes)
    msg.extend_from_slice(AUTH_MAGIC);

    // Version (1 byte)
    msg.push(AUTH_VERSION_V1);

    // Timestamp (8 bytes, big-endian)
    msg.extend_from_slice(&timestamp.to_be_bytes());

    // Nonce (16 bytes)
    msg.extend_from_slice(nonce);

    // Method (1-byte length + UTF-8)
    // Safety: we already validated method_bytes.len() <= 255
    msg.push(method_bytes.len() as u8);
    msg.extend_from_slice(method_bytes);

    // Path (2-byte length, big-endian + UTF-8)
    // Safety: we already validated path_bytes.len() <= 65535
    msg.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
    msg.extend_from_slice(path_bytes);

    // Body hash flag and optional hash
    match body_hash {
        Some(hash) => {
            msg.push(0x01);
            msg.extend_from_slice(hash);
        }
        None => {
            msg.push(0x00);
        }
    }

    Ok(msg)
}

/// Verify an authentication proof.
///
/// # Errors
///
/// Returns an error if:
/// - The timestamp is outside the allowed skew window
/// - The signature is invalid
/// - The client is not in the allowlist
/// - The nonce has been seen before (replay)
#[must_use = "verification result must be checked"]
pub fn verify_v1(
    proof: &AuthProof,
    now_utc_seconds: i64,
    max_skew_seconds: i64,
    allowlist: &impl Allowlist,
    replay_cache: &impl ReplayCache,
) -> Result<VerifiedIdentity, AuthnError> {
    // Check timestamp skew using saturating arithmetic to handle extreme values
    let age = now_utc_seconds.saturating_sub(proof.timestamp);
    if age > max_skew_seconds {
        return Err(AuthnError::TimestampExpired);
    }
    // Handle future timestamps separately to avoid issues with negative saturating_sub
    let future_age = proof.timestamp.saturating_sub(now_utc_seconds);
    if future_age > max_skew_seconds {
        return Err(AuthnError::TimestampInFuture);
    }

    // Get fingerprint for allowlist check
    let fingerprint = Fingerprint::from_public_key(&proof.public_key);

    // Check allowlist
    if !allowlist.contains(&fingerprint) {
        return Err(AuthnError::NotAllowlisted);
    }

    // Build the canonical message
    let message = build_canonical_message(
        proof.timestamp,
        proof.nonce.as_bytes(),
        &proof.method,
        &proof.path,
        proof.body_hash.as_ref(),
    )?;

    // Verify signature
    if !proof.public_key.verify(&message, &proof.signature) {
        return Err(AuthnError::InvalidSignature);
    }

    // Check replay cache AFTER signature verification.
    // This order is intentional: checking before would allow attackers to pollute
    // the cache with invalid signatures, causing legitimate requests to be rejected.
    // By verifying the signature first, only valid requests can add to the cache.
    if !replay_cache.check_and_insert(&fingerprint, proof.nonce.as_bytes(), proof.timestamp) {
        return Err(AuthnError::ReplayDetected);
    }

    Ok(VerifiedIdentity::new(fingerprint))
}
