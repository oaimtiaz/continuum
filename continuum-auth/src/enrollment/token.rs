//! Enrollment token types.
//!
//! Tokens are short-lived, single-use secrets generated during enrollment.
//! The [`SignedEnrollmentToken`] contains:
//! - Random entropy for single-use identification
//! - Server fingerprint for pinned trust (eliminates TOFU)
//! - Expiration timestamp
//! - Cryptographic signature binding all fields together

use base64::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::identity::{Fingerprint, PrivateKey, PublicKey, Signature};

use super::EnrollmentError;

/// Current wire format version.
const TOKEN_VERSION: u8 = 1;

/// Domain separation prefix for signing.
///
/// Prevents cross-protocol attacks by ensuring signatures are only valid
/// in the enrollment context.
const DOMAIN_PREFIX: &[u8] = b"CONTINUUM-ENROLL-v1:";

/// A cryptographically signed enrollment token with embedded server fingerprint.
///
/// Wire format (v1, 137 bytes total):
/// - 1 byte: version (currently 1)
/// - 32 bytes: random token bytes (entropy for single-use identification)
/// - 32 bytes: server fingerprint (SHA256 of server's public key)
/// - 8 bytes: expiration timestamp (Unix seconds, big-endian i64)
/// - 64 bytes: Ed25519 signature over (DOMAIN_PREFIX || version || random || fingerprint || expires_at)
///
/// The embedded fingerprint eliminates Trust-On-First-Use (TOFU) by allowing
/// the client to verify the server's identity during the TLS handshake.
#[derive(Clone)]
pub struct SignedEnrollmentToken {
    /// Wire format version
    version: u8,
    /// Random token bytes (32 bytes of entropy)
    random: [u8; 32],
    /// Server fingerprint (SHA256 of public key)
    fingerprint: [u8; 32],
    /// Expiration timestamp (Unix seconds)
    expires_at: i64,
    /// Signature over all fields with domain prefix
    signature: Signature,
}

impl SignedEnrollmentToken {
    /// Generate a new signed enrollment token with embedded server fingerprint.
    ///
    /// # Arguments
    /// * `signing_key` - Server's private key for signing
    /// * `validity_seconds` - How long until expiration (clamped to 60-3600 seconds)
    ///
    /// The server's fingerprint is automatically derived from the signing key
    /// and embedded in the token, eliminating the need for TOFU.
    ///
    /// # Panics
    ///
    /// Panics if the system clock is set to before the Unix epoch (January 1, 1970).
    /// This indicates a severely misconfigured system and is not recoverable.
    #[must_use]
    pub fn generate(signing_key: &PrivateKey, validity_seconds: i64) -> Self {
        // H6: Use OsRng directly for cryptographic entropy instead of ThreadRng
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);

        // Derive fingerprint from the signing key's public key
        let public_key = signing_key.public_key();
        let fingerprint = Fingerprint::from_public_key(&public_key).hash_bytes();

        let validity = validity_seconds.clamp(60, 3600); // 1 min to 1 hour
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before Unix epoch")
            .as_secs() as i64
            + validity;

        // Sign all fields with domain prefix
        let message = Self::build_signing_message(TOKEN_VERSION, &random, &fingerprint, expires_at);
        let signature = signing_key.sign(&message);

        Self {
            version: TOKEN_VERSION,
            random,
            fingerprint,
            expires_at,
            signature,
        }
    }

    /// Validate token signature and check expiration.
    ///
    /// # Arguments
    /// * `public_key` - Server's public key for signature verification
    /// * `now` - Current Unix timestamp in seconds
    ///
    /// # Errors
    /// Returns error if token is expired, signature is invalid, or version is unsupported.
    pub fn validate(&self, public_key: &PublicKey, now: i64) -> Result<(), EnrollmentError> {
        // Check version first (can be done before crypto, doesn't leak timing info
        // about token validity since version is not secret)
        if self.version != TOKEN_VERSION {
            return Err(EnrollmentError::InvalidToken);
        }

        // Verify signature BEFORE checking expiration.
        // This order is intentional: checking expiration first would leak timing
        // information about whether a token was ever valid. An attacker could probe
        // expired tokens to learn they were once legitimate.
        let message = Self::build_signing_message(
            self.version,
            &self.random,
            &self.fingerprint,
            self.expires_at,
        );
        if !public_key.verify(&message, &self.signature) {
            return Err(EnrollmentError::InvalidSignature);
        }

        // Check expiration last (after signature verification proves legitimacy)
        if now > self.expires_at {
            return Err(EnrollmentError::TokenExpired);
        }

        Ok(())
    }

    /// Build the message that gets signed.
    ///
    /// Format: DOMAIN_PREFIX || version || random || fingerprint || expires_at (BE)
    ///
    /// The domain prefix prevents cross-protocol signature attacks.
    fn build_signing_message(
        version: u8,
        random: &[u8; 32],
        fingerprint: &[u8; 32],
        expires_at: i64,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(DOMAIN_PREFIX.len() + 1 + 32 + 32 + 8);
        message.extend_from_slice(DOMAIN_PREFIX);
        message.push(version);
        message.extend_from_slice(random);
        message.extend_from_slice(fingerprint);
        message.extend_from_slice(&expires_at.to_be_bytes());
        message
    }

    /// Get the token hash for deduplication/replay detection.
    ///
    /// Only the random bytes are hashed, not the signature or expiration.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.random).into()
    }

    /// Get expiration timestamp (Unix seconds).
    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Get the random bytes (for internal use only).
    ///
    /// This is not exposed publicly to prevent leaking entropy.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn random_bytes(&self) -> &[u8; 32] {
        &self.random
    }

    /// Get the embedded server fingerprint.
    ///
    /// This fingerprint should be compared against the server's TLS certificate
    /// during the handshake to verify the server's identity.
    #[must_use]
    pub fn server_fingerprint(&self) -> Fingerprint {
        Fingerprint::from_hash_bytes(self.fingerprint)
    }

    /// Get the raw fingerprint bytes (for efficient comparison).
    #[must_use]
    pub fn fingerprint_bytes(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Encode token as base64 for transport.
    ///
    /// Wire format: version(1) || random(32) || fingerprint(32) || expires_at(8) || signature(64) = 137 bytes
    #[must_use]
    pub fn to_base64(&self) -> String {
        let mut bytes = Vec::with_capacity(137);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.random);
        bytes.extend_from_slice(&self.fingerprint);
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.signature.to_bytes());
        BASE64_STANDARD.encode(&bytes)
    }

    /// Decode token from base64.
    ///
    /// Accepts both plain base64 and dash-separated format (as produced by Display).
    ///
    /// # Errors
    /// Returns error if the format is invalid or the version is unsupported.
    pub fn from_base64(encoded: &str) -> Result<Self, EnrollmentError> {
        // Strip dashes if present (Display format uses dashes for readability)
        let clean: String = encoded.chars().filter(|c| *c != '-').collect();
        let bytes = BASE64_STANDARD
            .decode(&clean)
            .map_err(|_| EnrollmentError::InvalidToken)?;

        if bytes.len() != 137 {
            return Err(EnrollmentError::InvalidToken);
        }

        let version = bytes[0];

        // Validate version early to fail fast on unsupported tokens
        if version != TOKEN_VERSION {
            return Err(EnrollmentError::InvalidToken);
        }

        let random: [u8; 32] = bytes[1..33]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidToken)?;

        let fingerprint: [u8; 32] = bytes[33..65]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidToken)?;

        let expires_at = i64::from_be_bytes(
            bytes[65..73]
                .try_into()
                .map_err(|_| EnrollmentError::InvalidToken)?,
        );

        let signature = Signature::from_bytes(&bytes[73..137])
            .map_err(|_| EnrollmentError::InvalidToken)?;

        Ok(Self {
            version,
            random,
            fingerprint,
            expires_at,
            signature,
        })
    }
}

impl std::fmt::Display for SignedEnrollmentToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as chunked base64 for human readability
        let b64 = self.to_base64();
        let chunks: Vec<&str> = b64
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or("????"))
            .collect();
        write!(f, "{}", chunks.join("-"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_token_generation_and_validation() {
        let key = crate::identity::PrivateKey::generate();
        let public_key = key.public_key();

        let token = SignedEnrollmentToken::generate(&key, 300); // 5 minutes

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Token should be valid now
        assert!(token.validate(&public_key, now).is_ok());
    }

    #[test]
    fn test_signed_token_contains_fingerprint() {
        let key = crate::identity::PrivateKey::generate();
        let public_key = key.public_key();
        let expected_fingerprint = Fingerprint::from_public_key(&public_key);

        let token = SignedEnrollmentToken::generate(&key, 300);

        // Token should contain the server's fingerprint
        assert_eq!(token.server_fingerprint(), expected_fingerprint);
    }

    #[test]
    fn test_signed_token_expiration() {
        let key = crate::identity::PrivateKey::generate();
        let public_key = key.public_key();

        let token = SignedEnrollmentToken::generate(&key, 60); // 1 minute

        // Token should be expired if we check far in the future
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600; // 1 hour later

        let result = token.validate(&public_key, future);
        assert!(matches!(result, Err(EnrollmentError::TokenExpired)));
    }

    #[test]
    fn test_signed_token_wrong_key_rejected() {
        let key1 = crate::identity::PrivateKey::generate();
        let key2 = crate::identity::PrivateKey::generate();

        let token = SignedEnrollmentToken::generate(&key1, 300);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Token should be rejected when verified with different key
        let result = token.validate(&key2.public_key(), now);
        assert!(matches!(result, Err(EnrollmentError::InvalidSignature)));
    }

    #[test]
    fn test_signed_token_base64_roundtrip() {
        let key = crate::identity::PrivateKey::generate();
        let public_key = key.public_key();

        let token = SignedEnrollmentToken::generate(&key, 300);
        let encoded = token.to_base64();

        // Encoded token should be 137 bytes base64 = ~184 chars
        assert!(encoded.len() > 180);

        // Decode and validate
        let decoded = SignedEnrollmentToken::from_base64(&encoded).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        assert!(decoded.validate(&public_key, now).is_ok());
        assert_eq!(token.expires_at(), decoded.expires_at());
        assert_eq!(token.random_bytes(), decoded.random_bytes());
        assert_eq!(token.fingerprint_bytes(), decoded.fingerprint_bytes());
    }

    #[test]
    fn test_signed_token_invalid_base64() {
        let result = SignedEnrollmentToken::from_base64("not-valid-base64!!!");
        assert!(matches!(result, Err(EnrollmentError::InvalidToken)));
    }

    #[test]
    fn test_signed_token_wrong_length() {
        // Valid base64 but wrong length
        let result = SignedEnrollmentToken::from_base64("YWJjZA=="); // "abcd"
        assert!(matches!(result, Err(EnrollmentError::InvalidToken)));
    }

    #[test]
    fn test_signed_token_hash_uniqueness() {
        let key = crate::identity::PrivateKey::generate();

        let token1 = SignedEnrollmentToken::generate(&key, 300);
        let token2 = SignedEnrollmentToken::generate(&key, 300);

        // Different tokens should have different hashes
        assert_ne!(token1.hash(), token2.hash());
    }

    #[test]
    fn test_signed_token_display_format() {
        let key = crate::identity::PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);

        let display = format!("{}", token);
        // Display should contain dashes (chunked format)
        assert!(display.contains('-'));
    }

    #[test]
    fn test_signed_token_validity_clamping() {
        let key = crate::identity::PrivateKey::generate();

        // Test minimum clamping (below 60 should become 60)
        let token_short = SignedEnrollmentToken::generate(&key, 10);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Should expire at least 60 seconds from now
        assert!(token_short.expires_at() >= now + 60);

        // Test maximum clamping (above 3600 should become 3600)
        let token_long = SignedEnrollmentToken::generate(&key, 10000);
        assert!(token_long.expires_at() <= now + 3601); // Allow 1 second tolerance
    }

    #[test]
    fn test_signed_token_domain_separation_prevents_cross_protocol_attacks() {
        // This test verifies that the domain prefix "CONTINUUM-ENROLL-v1:" prevents
        // an attacker from using a signature from one protocol context in another.
        //
        // Attack scenario: An attacker obtains a valid signature from a different
        // protocol (e.g., a chat message signature) and tries to use it as an
        // enrollment token signature.

        let key = crate::identity::PrivateKey::generate();
        let public_key = key.public_key();

        // Generate a valid enrollment token
        let valid_token = SignedEnrollmentToken::generate(&key, 300);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // The valid token should work
        assert!(valid_token.validate(&public_key, now).is_ok());

        // Now manually sign the same data WITHOUT the domain prefix
        // (simulating a signature from a different protocol that doesn't use domain separation)
        let mut message_without_prefix = Vec::new();
        message_without_prefix.push(TOKEN_VERSION);
        message_without_prefix.extend_from_slice(valid_token.random_bytes());
        message_without_prefix.extend_from_slice(valid_token.fingerprint_bytes());
        message_without_prefix.extend_from_slice(&valid_token.expires_at().to_be_bytes());

        let malicious_signature = key.sign(&message_without_prefix);

        // Try to create a token with this malicious signature
        // We need to use base64 encoding/decoding to inject the bad signature
        let mut bad_token_bytes = Vec::with_capacity(137);
        bad_token_bytes.push(TOKEN_VERSION);
        bad_token_bytes.extend_from_slice(valid_token.random_bytes());
        bad_token_bytes.extend_from_slice(valid_token.fingerprint_bytes());
        bad_token_bytes.extend_from_slice(&valid_token.expires_at().to_be_bytes());
        bad_token_bytes.extend_from_slice(&malicious_signature.to_bytes());

        let bad_token_b64 = base64::prelude::BASE64_STANDARD.encode(&bad_token_bytes);
        let bad_token = SignedEnrollmentToken::from_base64(&bad_token_b64).unwrap();

        // The token with the wrong domain signature MUST be rejected
        let result = bad_token.validate(&public_key, now);
        assert!(
            matches!(result, Err(EnrollmentError::InvalidSignature)),
            "Token signed without domain prefix should be rejected"
        );
    }

    #[test]
    fn test_domain_prefix_in_signature_is_required() {
        // Verify the domain prefix is actually included and required
        // by showing that the DOMAIN_PREFIX constant affects validation
        let key = crate::identity::PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Valid token should pass
        assert!(token.validate(&key.public_key(), now).is_ok());

        // Sign with a DIFFERENT domain prefix (simulating a different protocol)
        let different_prefix = b"CONTINUUM-ENROLL-v2:"; // Wrong version
        let mut message = Vec::new();
        message.extend_from_slice(different_prefix);
        message.push(TOKEN_VERSION);
        message.extend_from_slice(token.random_bytes());
        message.extend_from_slice(token.fingerprint_bytes());
        message.extend_from_slice(&token.expires_at().to_be_bytes());

        let bad_signature = key.sign(&message);

        // Construct token with signature from different domain
        let mut bad_token_bytes = Vec::with_capacity(137);
        bad_token_bytes.push(TOKEN_VERSION);
        bad_token_bytes.extend_from_slice(token.random_bytes());
        bad_token_bytes.extend_from_slice(token.fingerprint_bytes());
        bad_token_bytes.extend_from_slice(&token.expires_at().to_be_bytes());
        bad_token_bytes.extend_from_slice(&bad_signature.to_bytes());

        let bad_token_b64 = base64::prelude::BASE64_STANDARD.encode(&bad_token_bytes);
        let bad_token = SignedEnrollmentToken::from_base64(&bad_token_b64).unwrap();

        // Must be rejected
        assert!(
            matches!(bad_token.validate(&key.public_key(), now), Err(EnrollmentError::InvalidSignature)),
            "Token signed with wrong domain prefix should be rejected"
        );
    }

    #[test]
    fn test_wire_format_version() {
        let key = crate::identity::PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);
        let encoded = token.to_base64();

        // Decode raw bytes and check version
        let bytes = base64::prelude::BASE64_STANDARD.decode(&encoded).unwrap();
        assert_eq!(bytes[0], TOKEN_VERSION);
        assert_eq!(bytes.len(), 137); // 1 + 32 + 32 + 8 + 64
    }
}
