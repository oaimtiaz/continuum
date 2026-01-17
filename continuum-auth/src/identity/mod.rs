//! Cryptographic identity types for Continuum authentication.
//!
//! This module provides Ed25519-based keypairs for client and server identity:
//!
//! - [`PrivateKey`] - Signing key with automatic zeroization on drop
//! - [`PublicKey`] - Verification key for signature checks
//! - [`Signature`] - Ed25519 signature over a message
//! - [`Fingerprint`] - SSH-compatible fingerprint format: `SHA256:{base64_no_padding}`
//!
//! # Security Properties
//!
//! - Private keys are zeroized on drop to prevent lingering in memory
//! - No `Debug` implementation for `PrivateKey` prevents accidental logging
//! - Fingerprint comparison uses constant-time equality to prevent timing attacks
//! - `verify_strict` is used to reject weak/small-order keys
//!
//! # Example
//!
//! ```
//! use continuum_auth::identity::{PrivateKey, Fingerprint};
//!
//! // Generate a new keypair
//! let private_key = PrivateKey::generate();
//! let public_key = private_key.public_key();
//!
//! // Get the fingerprint for display/comparison
//! let fingerprint = Fingerprint::from_public_key(&public_key);
//! println!("Key fingerprint: {}", fingerprint);
//!
//! // Sign and verify a message
//! let message = b"Hello, Continuum!";
//! let signature = private_key.sign(message);
//! assert!(public_key.verify(message, &signature));
//! ```

mod keys;

pub use keys::{Fingerprint, KeyError, PrivateKey, PublicKey, SecretBytes, Signature};
