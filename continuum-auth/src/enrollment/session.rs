//! Enrollment session state machine.
//!
//! Simplified to 2-state: Pending → Finalized

use chrono::{DateTime, Duration, Utc};
use subtle::ConstantTimeEq;

/// Default enrollment session expiration time.
const ENROLLMENT_EXPIRATION_MINUTES: i64 = 5;

/// An enrollment session in the Pending state.
///
/// Waiting for client to present token and identity.
///
/// # Security
///
/// Token hash comparisons use constant-time equality to prevent timing attacks.
/// Fields are private to prevent external code from extending expiration or
/// bypassing hash verification.
#[derive(Debug, Clone)]
pub struct PendingEnrollment {
    /// SHA-256 hash of the token's random bytes (for replay detection).
    token_hash: [u8; 32],
    /// When this session expires.
    expires_at: DateTime<Utc>,
}

impl PendingEnrollment {
    /// Create a new pending enrollment session.
    ///
    /// The hash should come from `SignedEnrollmentToken::hash()`.
    #[must_use]
    pub fn new(token_hash: [u8; 32]) -> Self {
        Self {
            token_hash,
            expires_at: Utc::now() + Duration::minutes(ENROLLMENT_EXPIRATION_MINUTES),
        }
    }

    /// Check if this session has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Get the expiration time.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Check if the given token hash matches this session's token.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    #[must_use]
    pub fn token_hash_matches(&self, other_hash: &[u8; 32]) -> bool {
        self.token_hash.ct_eq(other_hash).into()
    }

    /// Force expiration for testing purposes.
    #[cfg(test)]
    pub(crate) fn force_expire(&mut self) {
        self.expires_at = Utc::now() - Duration::seconds(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment::SignedEnrollmentToken;

    #[test]
    fn test_pending_enrollment_not_expired_initially() {
        let key = crate::identity::PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);
        let pending = PendingEnrollment::new(token.hash());

        assert!(!pending.is_expired());
    }

    #[test]
    fn test_pending_enrollment_expires_after_time() {
        let key = crate::identity::PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);
        let mut pending = PendingEnrollment::new(token.hash());

        // Force expiration for testing
        pending.force_expire();

        assert!(pending.is_expired());
    }

    #[test]
    fn test_token_hash_matches_correct_hash() {
        let key = crate::identity::PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);
        let token_hash = token.hash();
        let pending = PendingEnrollment::new(token_hash);

        assert!(pending.token_hash_matches(&token_hash));
    }

    #[test]
    fn test_token_hash_rejects_wrong_hash() {
        let key = crate::identity::PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);
        let pending = PendingEnrollment::new(token.hash());

        let wrong_hash = [0u8; 32];
        assert!(!pending.token_hash_matches(&wrong_hash));
    }
}
