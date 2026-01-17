//! Pure authentication library for Continuum.
//!
//! This crate is intentionally IO-free:
//! - No filesystem operations
//! - No network calls
//! - No database interactions
//! - No logging
//!
//! Dependencies are injected via traits:
//! - [`authn::Allowlist`] - Client fingerprint authorization
//! - [`authn::ReplayCache`] - Nonce tracking for replay prevention
//! - [`trust::KnownHosts`] - Server fingerprint storage
//!
//! # Example
//!
//! ```ignore
//! use continuum_auth::{identity::PrivateKey, authn::*};
//!
//! // Client generates a keypair and creates a proof
//! let key = PrivateKey::generate();
//! let proof = AuthProof { /* ... */ };
//!
//! // Server verifies the proof
//! let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
//! ```

pub mod authn;
pub mod cert;
pub mod enrollment;
pub mod identity;
pub mod trust;

pub use authn::{
    Allowlist, AuthProof, AuthnError, RandomNonce, ReplayCache, VerifiedIdentity, verify_v1,
};
pub use identity::{Fingerprint, KeyError, PrivateKey, PublicKey, Signature};
pub use trust::{KnownHosts, TrustDecision, evaluate_server_trust};
pub use cert::{CertError, extract_public_key_from_cert};
