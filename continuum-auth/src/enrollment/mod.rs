//! Enrollment state machine for client registration.
//!
//! The enrollment flow is:
//! 1. Server generates a [`SignedEnrollmentToken`] containing server fingerprint
//! 2. Token is sent to client out-of-band (e.g., displayed in terminal)
//! 3. Client connects to server using embedded fingerprint for TLS verification
//! 4. Client sends the token to server; server creates [`PendingEnrollment`]
//! 5. Server verifies token signature and expiration
//! 6. On success, server adds client identity to allowlist
//!
//! # Security
//!
//! - Tokens embed server fingerprint to eliminate Trust-On-First-Use (TOFU)
//! - Domain-separated signatures prevent cross-protocol attacks
//! - Sessions expire after 5 minutes

mod error;
mod session;
mod token;

pub use error::EnrollmentError;
pub use session::PendingEnrollment;
pub use token::SignedEnrollmentToken;
