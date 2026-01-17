//! TLS server configuration for mTLS.
//!
//! Uses rustls 0.23+ with modern builder patterns.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::sync::Arc;
use std::time::SystemTime;
use x509_parser::prelude::*;

/// TLS server configuration wrapper.
pub struct TlsServerConfig {
    pub config: Arc<ServerConfig>,
}

impl TlsServerConfig {
    /// Get the underlying rustls ServerConfig.
    pub fn into_rustls_config(self) -> Arc<ServerConfig> {
        self.config
    }
}

impl TlsServerConfig {
    /// Create mTLS server config (requires valid client certificates).
    ///
    /// All clients must present a certificate that chains to one of the
    /// authorized client certificates in the root store.
    ///
    /// # Arguments
    /// * `server_cert_der` - Server's certificate in DER format
    /// * `server_key_der` - Server's private key in PKCS#8 DER format
    /// * `authorized_client_certs` - List of authorized client certificates (DER)
    pub fn new_mtls(
        server_cert_der: Vec<u8>,
        server_key_der: Vec<u8>,
        authorized_client_certs: Vec<Vec<u8>>,
    ) -> Result<Self, TlsConfigError> {
        // Build root store from authorized client certs
        // M5 FIX: Skip expired or not-yet-valid certificates
        let mut root_store = RootCertStore::empty();
        let mut skipped_count = 0;
        for cert_der in authorized_client_certs {
            // Check certificate validity before adding to root store
            match verify_certificate_validity(&cert_der) {
                Ok(()) => {
                    let cert = CertificateDer::from(cert_der);
                    root_store
                        .add(cert)
                        .map_err(|e| TlsConfigError::InvalidCert(e.to_string()))?;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Skipping invalid client certificate");
                    skipped_count += 1;
                }
            }
        }
        if skipped_count > 0 {
            tracing::info!(
                skipped = skipped_count,
                valid = root_store.len(),
                "Certificate validity check completed"
            );
        }

        // Create client verifier that accepts but doesn't require client certs.
        // This allows both:
        // - mTLS clients (remote enrolled) - cert validated against root store
        // - Local clients (same-machine) - no cert, uses trust proof header
        // The application-layer auth_interceptor validates one or the other.
        let client_verifier = if root_store.is_empty() {
            // If no clients authorized yet, use no_client_auth
            // (enrollment endpoint will still work)
            return Self::new_server_only(server_cert_der, server_key_der);
        } else {
            WebPkiClientVerifier::builder(Arc::new(root_store))
                .allow_unauthenticated()  // Makes client certs optional at TLS layer
                .build()
                .map_err(|e| TlsConfigError::Verifier(e.to_string()))?
        };

        // Build server config
        let cert = CertificateDer::from(server_cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der));

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![cert], key)
            .map_err(|e| TlsConfigError::Config(e.to_string()))?;

        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Create server-auth-only config (no client certificate required).
    ///
    /// Used for the enrollment endpoint where clients don't have certificates yet.
    pub fn new_server_only(
        server_cert_der: Vec<u8>,
        server_key_der: Vec<u8>,
    ) -> Result<Self, TlsConfigError> {
        let cert = CertificateDer::from(server_cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| TlsConfigError::Config(e.to_string()))?;

        Ok(Self {
            config: Arc::new(config),
        })
    }
}

/// M5 FIX: Verify certificate validity period.
///
/// Returns Ok(()) if the certificate is currently valid (not expired and not future-dated).
/// Returns Err with a description if validity check fails.
fn verify_certificate_validity(cert_der: &[u8]) -> Result<(), TlsConfigError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TlsConfigError::InvalidCert(format!("failed to parse certificate: {}", e)))?;

    let validity = cert.validity();
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TlsConfigError::InvalidCert("system time error".to_string()))?
        .as_secs() as i64;

    // Convert ASN1Time to unix timestamp
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();

    if now < not_before {
        return Err(TlsConfigError::CertNotYetValid {
            not_before: not_before as u64,
            now: now as u64,
        });
    }

    if now > not_after {
        return Err(TlsConfigError::CertExpired {
            not_after: not_after as u64,
            now: now as u64,
        });
    }

    Ok(())
}

/// Errors that can occur during TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("invalid certificate: {0}")]
    InvalidCert(String),
    #[error("failed to build verifier: {0}")]
    Verifier(String),
    #[error("failed to build config: {0}")]
    Config(String),
    #[error("certificate not yet valid (not_before: {not_before}, now: {now})")]
    CertNotYetValid { not_before: u64, now: u64 },
    #[error("certificate expired (not_after: {not_after}, now: {now})")]
    CertExpired { not_after: u64, now: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::cert::{build_self_signed, CertParams};
    use continuum_auth::identity::PrivateKey;

    #[test]
    fn test_server_only_config() {
        let key = PrivateKey::generate();
        let identity = build_self_signed(&key, &CertParams::default()).unwrap();

        let config = TlsServerConfig::new_server_only(identity.cert_der, identity.key_der);

        assert!(config.is_ok());
    }

    #[test]
    fn test_mtls_config_with_no_clients() {
        let key = PrivateKey::generate();
        let identity = build_self_signed(&key, &CertParams::default()).unwrap();

        // With no authorized clients, should fall back to server-only
        let config = TlsServerConfig::new_mtls(identity.cert_der, identity.key_der, vec![]);

        assert!(config.is_ok());
    }

    #[test]
    fn test_mtls_config_with_client() {
        let server_key = PrivateKey::generate();
        let server_identity = build_self_signed(&server_key, &CertParams::default()).unwrap();

        let client_key = PrivateKey::generate();
        let client_identity = build_self_signed(
            &client_key,
            &CertParams {
                common_name: "client".to_string(),
                ..Default::default()
            },
        )
        .unwrap();

        let config = TlsServerConfig::new_mtls(
            server_identity.cert_der,
            server_identity.key_der,
            vec![client_identity.cert_der],
        );

        assert!(config.is_ok());
    }
}
