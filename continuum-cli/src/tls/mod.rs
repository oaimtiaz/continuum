//! TLS configuration for secure client connections.

mod client;

use anyhow::{Context, Result};
use continuum_auth::identity::Fingerprint;
use rustls::ClientConfig;
use sha2::{Digest, Sha256};
use tonic::transport::Channel;

pub use client::{build_mtls_config, ClientIdentity, EnrollmentVerifier};
pub use continuum_auth::cert::extract_public_key_from_cert;

/// Extract fingerprint from a DER-encoded certificate.
///
/// Computes SHA256 of the public key to create a stable fingerprint.
pub fn fingerprint_from_cert_der(cert_der: &[u8]) -> Result<Fingerprint> {
    let public_key_bytes =
        extract_public_key_from_cert(cert_der).context("Failed to extract public key")?;
    let hash: [u8; 32] = Sha256::digest(&public_key_bytes).into();
    Ok(Fingerprint::from_hash_bytes(hash))
}

/// Build a TLS channel with the given configuration.
///
/// Converts HTTP addresses to HTTPS and creates a tonic Channel
/// using the provided TLS config.
pub async fn build_tls_channel(addr: &str, tls_config: ClientConfig) -> Result<Channel> {
    let tls_addr = addr.replace("http://", "https://");
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http2()
        .build();
    Channel::from_shared(tls_addr)?
        .connect_with_connector(https_connector)
        .await
        .context("Failed to connect via TLS")
}
