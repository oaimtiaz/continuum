//! Cryptographic identity types for Continuum authentication.
//!
//! This module provides Ed25519-based keypairs with proper secret handling:
//! - Private keys are zeroized on drop
//! - No Debug/Display implementations that leak secrets
//! - Fingerprints use constant-time comparison
//! - URL-safe fingerprint format: `SHA256:{url_safe_base64_no_padding}`
//! - PKCS#8 DER exports are automatically zeroized

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during key operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The provided bytes have an invalid length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    /// The provided bytes do not represent a valid key.
    #[error("invalid key format")]
    InvalidFormat,

    /// The fingerprint string has an invalid format.
    #[error("invalid fingerprint format")]
    InvalidFingerprint,
}

/// A zeroize-on-drop wrapper for secret bytes.
///
/// Used for PKCS#8 DER exports to ensure key material doesn't linger in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Get a reference to the secret bytes.
    ///
    /// # Security
    ///
    /// The returned reference should not be stored. Copying the bytes
    /// defeats the purpose of automatic zeroization.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a regular Vec<u8>.
    ///
    /// # Security Warning
    ///
    /// This copies the secret bytes into a regular Vec that will NOT be
    /// automatically zeroized. Only use this when the receiving code cannot
    /// accept `SecretBytes` (e.g., third-party APIs).
    ///
    /// Prefer keeping data as `SecretBytes` and using `as_bytes()` or `Deref`
    /// for temporary access instead.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<I> std::ops::Index<I> for SecretBytes
where
    I: std::slice::SliceIndex<[u8]>,
{
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

/// A private Ed25519 signing key.
///
/// # Security
///
/// - Zeroized on drop to prevent key material from lingering in memory
/// - No `Debug` implementation to prevent accidental logging
/// - `to_bytes()` requires explicit opt-in to access raw key material
pub struct PrivateKey(ed25519_dalek::SigningKey);

// Note: SigningKey implements ZeroizeOnDrop, so key material is automatically
// zeroized when dropped. We don't need a manual Zeroize implementation.

impl PrivateKey {
    /// Generate a new random private key.
    #[must_use]
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng))
    }

    /// Load a private key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `KeyError::InvalidLength` if the slice is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| KeyError::InvalidLength {
            expected: 32,
            actual: bytes.len(),
        })?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&bytes)))
    }

    /// Sign a message with this private key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message))
    }

    /// Derive the public key from this private key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Export the raw private key bytes.
    ///
    /// # Security
    ///
    /// Handle with extreme care. Consider zeroizing the returned array
    /// after use if storing or transmitting.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Export the private key as PKCS#8 DER bytes.
    ///
    /// The format is: PKCS#8 PrivateKeyInfo wrapping the Ed25519 private key.
    /// This is the format expected by rcgen and rustls.
    ///
    /// # Security
    ///
    /// Handle with extreme care. The returned bytes contain the full private key.
    /// The `SecretBytes` wrapper automatically zeroizes the key material when dropped.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> SecretBytes {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        SecretBytes(
            self.0
                .to_pkcs8_der()
                .expect("Ed25519 key should always encode to PKCS#8")
                .as_bytes()
                .to_vec(),
        )
    }

    /// Load a private key from PKCS#8 DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `KeyError::InvalidFormat` if the bytes are not valid PKCS#8.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, KeyError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let key =
            ed25519_dalek::SigningKey::from_pkcs8_der(bytes).map_err(|_| KeyError::InvalidFormat)?;
        Ok(Self(key))
    }
}

// Explicitly NO Debug implementation for PrivateKey

/// A public Ed25519 verification key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

impl PublicKey {
    /// Load a public key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `KeyError::InvalidLength` if the slice is not exactly 32 bytes.
    /// Returns `KeyError::InvalidFormat` if the bytes don't represent a valid point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| KeyError::InvalidLength {
            expected: 32,
            actual: bytes.len(),
        })?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidFormat)?;
        Ok(Self(key))
    }

    /// Export the raw public key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify a signature over a message.
    ///
    /// Uses `verify_strict` to reject weak/small-order keys.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.0.verify_strict(message, &signature.0).is_ok()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", Fingerprint::from_public_key(self))
    }
}

/// An Ed25519 signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(ed25519_dalek::Signature);

impl Signature {
    /// Load a signature from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `KeyError::InvalidLength` if the slice is not exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let bytes: [u8; 64] = bytes.try_into().map_err(|_| KeyError::InvalidLength {
            expected: 64,
            actual: bytes.len(),
        })?;
        Ok(Self(ed25519_dalek::Signature::from_bytes(&bytes)))
    }

    /// Export the raw signature bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only first 8 bytes of signature for debugging
        let bytes = self.0.to_bytes();
        write!(
            f,
            "Signature({:02x}{:02x}{:02x}{:02x}...)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

/// A SHA-256 fingerprint of a public key.
///
/// Format: `SHA256:{base64_no_padding}` (SSH-compatible)
///
/// # Security
///
/// Comparisons use constant-time equality to prevent timing attacks.
/// The Hash derive is intentionally kept despite manual PartialEq because:
/// - Hash doesn't need to be constant-time (the hash value is not secret)
/// - The fingerprint string itself is public information
/// - Only equality comparisons need timing-attack protection
#[derive(Clone, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::derived_hash_with_manual_eq)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// The prefix used for fingerprint strings.
    pub const PREFIX: &'static str = "SHA256:";

    /// Create a fingerprint from a public key.
    ///
    /// Computes SHA-256 hash of the public key bytes and encodes
    /// as base64 without padding (SSH-compatible format).
    #[must_use]
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(public_key.to_bytes());
        let hash = hasher.finalize();
        // Use URL-safe base64 without padding (relay-compatible format)
        Self(format!(
            "{}{}",
            Self::PREFIX,
            URL_SAFE_NO_PAD.encode(hash)
        ))
    }

    /// Parse a fingerprint from a string.
    ///
    /// # Errors
    ///
    /// Returns `KeyError::InvalidFingerprint` if the string doesn't have the
    /// correct format (`SHA256:{base64}`).
    pub fn parse(s: &str) -> Result<Self, KeyError> {
        if !s.starts_with(Self::PREFIX) {
            return Err(KeyError::InvalidFingerprint);
        }

        let encoded = &s[Self::PREFIX.len()..];
        // Validate it's valid base64 of correct length (32 bytes = 43 chars in base64 no-pad)
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| KeyError::InvalidFingerprint)?;

        if decoded.len() != 32 {
            return Err(KeyError::InvalidFingerprint);
        }

        Ok(Self(s.to_string()))
    }

    /// Get the raw hash bytes (without the prefix).
    ///
    /// # Panics
    ///
    /// This method cannot panic for properly constructed `Fingerprint` values.
    /// Since `Fingerprint` can only be created via `from_public_key()`, `parse()`,
    /// or `from_hash_bytes()`, all of which ensure validity, the internal format
    /// is guaranteed to be correct.
    #[must_use]
    pub fn hash_bytes(&self) -> [u8; 32] {
        let encoded = self
            .0
            .strip_prefix(Self::PREFIX)
            .expect("Fingerprint invariant violated: missing prefix");
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("Fingerprint invariant violated: invalid base64");
        decoded
            .try_into()
            .expect("Fingerprint invariant violated: wrong length")
    }

    /// Create a fingerprint from raw hash bytes.
    ///
    /// This is the inverse of `hash_bytes()` - it takes the 32-byte SHA-256 hash
    /// directly rather than computing it from a public key.
    ///
    /// Used when deserializing fingerprints embedded in enrollment tokens.
    #[must_use]
    pub fn from_hash_bytes(hash: [u8; 32]) -> Self {
        Self(format!("{}{}", Self::PREFIX, URL_SAFE_NO_PAD.encode(hash)))
    }

    /// Get the fingerprint as a string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_signing() {
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();

        let message = b"test message";
        let signature = private_key.sign(message);

        assert!(public_key.verify(message, &signature));
    }

    #[test]
    fn test_key_roundtrip() {
        let private_key = PrivateKey::generate();
        let bytes = private_key.to_bytes();
        let restored = PrivateKey::from_bytes(&bytes).unwrap();

        // Verify they produce the same public key
        assert_eq!(
            private_key.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
    }

    #[test]
    fn test_fingerprint_format() {
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();
        let fingerprint = Fingerprint::from_public_key(&public_key);

        // Should start with SHA256:
        assert!(fingerprint.as_str().starts_with("SHA256:"));

        // Base64 of 32 bytes without padding = 43 characters
        // Total = 7 (prefix) + 43 = 50 characters
        assert_eq!(fingerprint.as_str().len(), 50);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();

        let fp1 = Fingerprint::from_public_key(&public_key);
        let fp2 = Fingerprint::from_public_key(&public_key);

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_parse() {
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();
        let fingerprint = Fingerprint::from_public_key(&public_key);

        let parsed = Fingerprint::parse(fingerprint.as_str()).unwrap();
        assert_eq!(fingerprint, parsed);
    }

    #[test]
    fn test_fingerprint_parse_invalid() {
        // Missing prefix
        assert!(Fingerprint::parse("abc123").is_err());

        // Invalid base64
        assert!(Fingerprint::parse("SHA256:!!!invalid!!!").is_err());

        // Wrong length (valid base64 but not 32 bytes)
        assert!(Fingerprint::parse("SHA256:YWJj").is_err());
    }

    #[test]
    fn test_fingerprint_hash_bytes_roundtrip() {
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();
        let fingerprint = Fingerprint::from_public_key(&public_key);

        // Extract hash bytes and reconstruct
        let hash = fingerprint.hash_bytes();
        let reconstructed = Fingerprint::from_hash_bytes(hash);

        assert_eq!(fingerprint, reconstructed);
    }

    #[test]
    fn test_signature_wrong_key_rejected() {
        let key1 = PrivateKey::generate();
        let key2 = PrivateKey::generate();

        let message = b"test message";
        let signature = key1.sign(message);

        // Signature should not verify with different key
        assert!(!key2.public_key().verify(message, &signature));
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Too short
        assert!(PrivateKey::from_bytes(&[0u8; 16]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 16]).is_err());
        assert!(Signature::from_bytes(&[0u8; 32]).is_err());

        // Too long
        assert!(PrivateKey::from_bytes(&[0u8; 64]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 64]).is_err());
        assert!(Signature::from_bytes(&[0u8; 128]).is_err());
    }

    #[test]
    fn test_signature_verification_rejects_weak_keys() {
        // All zeros is the identity point - ed25519-dalek accepts it at construction
        // but verify_strict() will reject signatures from weak/small-order keys.
        // This test verifies that our verify() method (which uses verify_strict)
        // properly rejects such keys during signature verification.
        let weak_key_bytes = [0u8; 32];

        // Construction may succeed (identity point is technically valid bytes)
        // but verification should fail
        if let Ok(weak_key) = PublicKey::from_bytes(&weak_key_bytes) {
            let message = b"test message";
            // Create a dummy signature (all zeros)
            let dummy_sig = Signature::from_bytes(&[0u8; 64]).unwrap();

            // verify_strict should reject this
            assert!(!weak_key.verify(message, &dummy_sig));
        }
        // If from_bytes rejects it, that's also acceptable
    }

    #[test]
    fn test_pkcs8_der_roundtrip() {
        // Generate a key, export to PKCS#8 DER, reimport, verify same key
        let original = PrivateKey::generate();
        let der = original.to_pkcs8_der();

        // Reimport from DER
        let restored = PrivateKey::from_pkcs8_der(der.as_bytes()).unwrap();

        // Both should produce the same public key
        assert_eq!(
            original.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );

        // Both should produce identical signatures
        let message = b"test message for PKCS#8 roundtrip";
        let sig1 = original.sign(message);
        let sig2 = restored.sign(message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_pkcs8_der_signing_functional() {
        // Verify that a key exported/imported via PKCS#8 still signs correctly
        let original = PrivateKey::generate();
        let der = original.to_pkcs8_der();
        let restored = PrivateKey::from_pkcs8_der(der.as_bytes()).unwrap();

        let message = b"PKCS#8 functional test";
        let signature = restored.sign(message);

        // Verify with the original's public key
        assert!(original.public_key().verify(message, &signature));

        // Verify with the restored's public key
        assert!(restored.public_key().verify(message, &signature));
    }

    #[test]
    fn test_pkcs8_der_invalid_format_rejected() {
        // Random bytes should be rejected
        assert!(PrivateKey::from_pkcs8_der(&[0u8; 48]).is_err());
        assert!(PrivateKey::from_pkcs8_der(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
        assert!(PrivateKey::from_pkcs8_der(&[]).is_err());
    }

    #[test]
    fn test_pkcs8_der_expected_length() {
        let key = PrivateKey::generate();
        let der = key.to_pkcs8_der();

        // Ed25519 PKCS#8 v2 DER includes the public key, making it ~83 bytes:
        // SEQUENCE { version, algorithm (OID), OCTET STRING (32-byte private key),
        //            [1] EXPLICIT BIT STRING (32-byte public key) }
        // The ed25519-dalek crate uses PKCS#8 v2 format by default.
        assert!(
            der.len() >= 48 && der.len() <= 100,
            "PKCS#8 DER unexpected length: {} bytes",
            der.len()
        );
    }

    #[test]
    fn test_secret_bytes_zeroize_on_drop() {
        // This test verifies the SecretBytes type is properly constructed
        // (actual zeroization happens on drop, which we can't easily test)
        let key = PrivateKey::generate();
        let der = key.to_pkcs8_der();

        // Verify we can access the bytes
        assert!(!der.as_bytes().is_empty());
        assert!(!der.is_empty()); // Via Deref

        // Verify indexing works
        let _first_byte = der[0];
    }
}
