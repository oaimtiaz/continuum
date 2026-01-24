//! Authentication and authorization for the daemon.
//!
//! Provides:
//! - [`AuthStore`]: Persistent storage for authorized clients and enrollment tokens
//! - [`LocalTrustManager`]: Same-machine trust detection

mod store;
mod trust;

pub use store::{generate_short_code, hash_token, is_short_code, AuthStore, AuthStoreError};
pub use trust::LocalTrustManager;
