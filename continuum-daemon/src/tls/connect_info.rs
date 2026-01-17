//! TLS connection info for mTLS authentication checks.

use std::net::SocketAddr;
use continuum_auth::identity::Fingerprint;

/// Connection info extracted from TLS streams.
///
/// This is made available via `request.extensions()` in gRPC handlers
/// when using mTLS, allowing services to verify client identity.
#[derive(Debug, Clone)]
pub struct TlsConnectInfo {
    /// Remote socket address of the client (kept for future logging/debugging)
    #[allow(dead_code)]
    pub remote_addr: Option<SocketAddr>,
    /// Client fingerprint extracted from first certificate
    pub client_fingerprint: Option<Fingerprint>,
}

impl TlsConnectInfo {
    /// Create a new TlsConnectInfo.
    pub fn new(
        remote_addr: Option<SocketAddr>,
        client_fingerprint: Option<Fingerprint>,
    ) -> Self {
        Self {
            remote_addr,
            client_fingerprint,
        }
    }
}
