//! TLS configuration for the daemon.
//!
//! Provides X.509 certificate generation, TLS server configuration,
//! and dynamic TLS reload support.

mod cert;
mod connect_info;
mod reload;
mod server;

pub use cert::{build_self_signed, CertParams, TlsIdentity};
pub use connect_info::TlsConnectInfo;
pub use reload::ReloadableTlsAcceptor;
pub use server::TlsConfigError;
pub use server::TlsServerConfig;
