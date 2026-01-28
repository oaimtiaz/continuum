//! Enrollment token parsing for mobile devices.
//!
//! Mobile devices enroll with daemons by scanning QR codes that contain
//! enrollment tokens. This module handles parsing those tokens.
//!
//! # Token Format
//!
//! Enrollment tokens are 137 bytes, base64 encoded:
//! - 1 byte: version (currently 1)
//! - 32 bytes: random (entropy for single-use identification)
//! - 32 bytes: server fingerprint (SHA256 of daemon's public key)
//! - 8 bytes: expiration timestamp (Unix seconds, big-endian)
//! - 64 bytes: Ed25519 signature

use continuum_auth::enrollment::SignedEnrollmentToken;
use continuum_auth::identity::Fingerprint;

use crate::errors::ClientError;

/// Parsed enrollment token with extracted server fingerprint.
///
/// The fingerprint is used to verify the daemon's identity during TLS handshake.
pub struct ParsedEnrollmentToken {
    /// The raw signed token (for sending to daemon)
    pub raw_token: String,
    /// Server fingerprint extracted from the token
    pub server_fingerprint: Fingerprint,
    /// Expiration timestamp (Unix seconds)
    pub expires_at: i64,
}

impl ParsedEnrollmentToken {
    /// Parse an enrollment token from base64 (from QR code).
    ///
    /// # Errors
    ///
    /// Returns `ClientError::InvalidEnrollmentToken` if:
    /// - Token is not valid base64
    /// - Token is wrong length (not 137 bytes)
    /// - Version is unsupported
    pub fn parse(token_base64: &str) -> Result<Self, ClientError> {
        let token = SignedEnrollmentToken::from_base64(token_base64)
            .map_err(|_| ClientError::InvalidEnrollmentToken)?;

        Ok(Self {
            raw_token: token_base64.to_string(),
            server_fingerprint: token.server_fingerprint(),
            expires_at: token.expires_at(),
        })
    }

    /// Check if the token has expired.
    ///
    /// # Arguments
    ///
    /// * `now` - Current Unix timestamp in seconds
    pub fn is_expired(&self, now: i64) -> bool {
        now > self.expires_at
    }
}

/// Enrollment state for a daemon.
///
/// Stored in secure storage after successful enrollment.
#[derive(Clone)]
pub struct DaemonEnrollment {
    /// Daemon fingerprint (also the key in storage)
    pub daemon_fingerprint: Fingerprint,
    /// Human-readable label
    pub label: Option<String>,
    /// Relay address to reach this daemon
    pub relay_endpoint: String,
}

impl DaemonEnrollment {
    /// Create a new enrollment record.
    pub fn new(
        daemon_fingerprint: Fingerprint,
        relay_endpoint: String,
        label: Option<String>,
    ) -> Self {
        Self {
            daemon_fingerprint,
            label,
            relay_endpoint,
        }
    }

    /// Serialize to JSON for storage.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "fingerprint": self.daemon_fingerprint.as_str(),
            "relay_endpoint": self.relay_endpoint,
            "label": self.label,
        })
        .to_string()
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, ClientError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| ClientError::StorageError {
                message: "Invalid enrollment JSON".to_string(),
            })?;

        let fingerprint_str = value["fingerprint"]
            .as_str()
            .ok_or(ClientError::StorageError {
                message: "Missing fingerprint".to_string(),
            })?;
        let fingerprint =
            Fingerprint::parse(fingerprint_str).map_err(|_| ClientError::StorageError {
                message: "Invalid fingerprint".to_string(),
            })?;

        let relay_endpoint = value["relay_endpoint"]
            .as_str()
            .ok_or(ClientError::StorageError {
                message: "Missing relay_endpoint".to_string(),
            })?
            .to_string();

        let label = value["label"].as_str().map(|s| s.to_string());

        Ok(Self {
            daemon_fingerprint: fingerprint,
            relay_endpoint,
            label,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use continuum_auth::identity::PrivateKey;

    #[test]
    fn test_parse_valid_token() {
        // Generate a test token
        let key = PrivateKey::generate();
        let token = SignedEnrollmentToken::generate(&key, 300);
        let base64 = token.to_base64();

        let parsed = ParsedEnrollmentToken::parse(&base64).unwrap();

        // Fingerprint should match
        assert_eq!(
            parsed.server_fingerprint,
            Fingerprint::from_public_key(&key.public_key())
        );

        // Should not be expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(!parsed.is_expired(now));
    }

    #[test]
    fn test_parse_invalid_token() {
        let result = ParsedEnrollmentToken::parse("not-valid-base64!!!");
        assert!(matches!(result, Err(ClientError::InvalidEnrollmentToken)));
    }

    #[test]
    fn test_enrollment_json_roundtrip() {
        let key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&key.public_key());

        let enrollment = DaemonEnrollment::new(
            fingerprint.clone(),
            "https://relay.example.com".to_string(),
            Some("My Laptop".to_string()),
        );

        let json = enrollment.to_json();
        let restored = DaemonEnrollment::from_json(&json).unwrap();

        assert_eq!(restored.daemon_fingerprint, fingerprint);
        assert_eq!(restored.relay_endpoint, "https://relay.example.com");
        assert_eq!(restored.label, Some("My Laptop".to_string()));
    }
}
