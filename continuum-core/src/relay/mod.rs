//! Relay support for Continuum.
//!
//! This module provides optional relay tunneling support, allowing clients to reach
//! daemons behind NAT/firewalls using Auth0 for authentication.
//!
//! ## Feature Flag
//!
//! This module is only available when the `relay` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! continuum-core = { version = "0.1", features = ["relay"] }
//! ```
//!
//! ## Components
//!
//! - [`DeviceAuthClient`] - Auth0 Device Authorization Flow client
//! - [`TunnelAdapter`] - Bridges gRPC streams to AsyncRead/AsyncWrite

mod device_auth;
mod tunnel_adapter;

pub use device_auth::{DeviceAuthClient, DeviceCodeResponse, RelayAuthConfig, RelayAuthError, TokenSet};
pub use tunnel_adapter::TunnelAdapter;
