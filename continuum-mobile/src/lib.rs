//! Continuum Mobile Client Core
//!
//! This crate provides the mobile client functionality for Continuum,
//! exposed via UniFFI for iOS (Swift) and Android (Kotlin) consumption.
//!
//! # Architecture
//!
//! The mobile client handles two types of authentication:
//! - **OAuth** to the dashboard/SaaS for status and attention requests
//! - **mTLS** to daemons for direct tunnel connections (terminal/PTY)
//!
//! # Threading Model
//!
//! Uses a single-threaded Tokio runtime for mobile efficiency.
//! Public API methods call `block_on` exactly once at the boundary.
//! Internal async methods use `.await` - never nest `block_on` calls.

uniffi::setup_scaffolding!();

mod client;
mod enrollment;
mod errors;
mod models;
mod storage;
mod tls;
mod tunnel;

pub use client::*;
pub use enrollment::{DaemonEnrollment, ParsedEnrollmentToken};
pub use errors::*;
pub use models::*;
pub use storage::*;
pub use tls::ClientIdentity;
pub use tunnel::TerminalTunnel;
