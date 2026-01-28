//! TLS configuration for mTLS connections.
//!
//! Provides client-side TLS configuration using rustls for mobile devices.
//! This is a simplified version of `continuum-cli/src/tls/client.rs` adapted
//! for mobile constraints.
//!
//! # Verifiers
//!
//! - [`EnrollmentVerifier`]: Pins to fingerprint embedded in enrollment token

use continuum_auth::cert::extract_public_key_from_cert;
use continuum_auth::identity::{Fingerprint, PrivateKey};
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::ClientConfig;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::errors::ClientError;

/// Client TLS identity (certificate + private key).
///
/// The private key uses `Zeroizing` to ensure key material
/// is securely erased from memory when dropped.
#[derive(Clone)]
pub struct ClientIdentity {
    /// DER-encoded certificate
    pub cert_der: Vec<u8>,
    /// DER-encoded private key (PKCS#8) - zeroized on drop
    pub key_der: Zeroizing<Vec<u8>>,
    /// Client fingerprint
    pub fingerprint: Fingerprint,
}

impl ClientIdentity {
    /// Generate a new client identity from an Ed25519 keypair.
    pub fn generate(private_key: &PrivateKey) -> Result<Self, ClientError> {
        let public_key = private_key.public_key();
        let fingerprint = Fingerprint::from_public_key(&public_key);

        // Build Ed25519 keypair for rcgen (PKCS#8 format)
        let key_der = private_key.to_pkcs8_der();
        let key_pair = KeyPair::try_from(&key_der[..]).map_err(|e| ClientError::MtlsFailed {
            reason: format!("Failed to create KeyPair: {}", e),
        })?;

        // Create certificate parameters
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, fingerprint.to_string());

        // Generate self-signed certificate with the keypair
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| ClientError::MtlsFailed {
                reason: format!("Failed to generate certificate: {}", e),
            })?;
        let cert_der = cert.der().to_vec();

        Ok(Self {
            cert_der,
            key_der: Zeroizing::new(key_der.to_vec()),
            fingerprint,
        })
    }

    /// Load a client identity from stored cert and key DER bytes.
    pub fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self, ClientError> {
        // Extract public key from certificate and compute fingerprint
        let public_key_bytes =
            extract_public_key_from_cert(&cert_der).map_err(|e| ClientError::MtlsFailed {
                reason: format!("Failed to extract public key: {}", e),
            })?;
        let public_key = continuum_auth::identity::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| ClientError::MtlsFailed {
                reason: format!("Invalid public key in certificate: {}", e),
            })?;
        let fingerprint = Fingerprint::from_public_key(&public_key);

        Ok(Self {
            cert_der,
            key_der: Zeroizing::new(key_der),
            fingerprint,
        })
    }
}

/// Certificate verifier that pins to a fingerprint.
///
/// This eliminates Trust-On-First-Use (TOFU) by comparing the server's public key
/// against the expected fingerprint during the TLS handshake.
///
/// # Security
///
/// - Extracts the public key from the X.509 certificate
/// - Uses constant-time comparison to prevent timing attacks
/// - Rejects connections if fingerprints don't match
#[derive(Debug)]
pub struct EnrollmentVerifier {
    /// Expected server fingerprint hash bytes
    expected_fingerprint: [u8; 32],
}

impl EnrollmentVerifier {
    /// Create a new enrollment verifier with the expected fingerprint hash bytes.
    pub fn new(expected_fingerprint: [u8; 32]) -> Arc<Self> {
        Arc::new(Self {
            expected_fingerprint,
        })
    }

    /// Create from a Fingerprint type.
    pub fn from_fingerprint(fingerprint: &Fingerprint) -> Arc<Self> {
        Self::new(fingerprint.hash_bytes())
    }
}

impl rustls::client::danger::ServerCertVerifier for EnrollmentVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Extract public key from certificate
        let public_key_bytes = extract_public_key_from_cert(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Hash the public key bytes
        let computed_hash: [u8; 32] = Sha256::digest(&public_key_bytes).into();

        // Constant-time comparison
        if computed_hash.ct_eq(&self.expected_fingerprint).into() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            // Fingerprint mismatch - potential MITM attack
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a TLS client config for mTLS with custom server verification.
///
/// Uses `EnrollmentVerifier` to pin to a known server fingerprint.
pub fn build_mtls_config<V>(
    client_identity: &ClientIdentity,
    verifier: Arc<V>,
) -> Result<ClientConfig, ClientError>
where
    V: rustls::client::danger::ServerCertVerifier + 'static,
{
    let cert = CertificateDer::from(client_identity.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from((*client_identity.key_der).clone()));

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| ClientError::MtlsFailed {
            reason: format!("Failed to build TLS config: {}", e),
        })?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn test_client_identity_generation() {
        let private_key = PrivateKey::generate();
        let identity = ClientIdentity::generate(&private_key).unwrap();

        assert!(!identity.cert_der.is_empty());
        assert!(!identity.key_der.is_empty());
        assert!(identity.fingerprint.to_string().starts_with("SHA256:"));
    }

    #[test]
    fn test_enrollment_verifier_accepts_matching_fingerprint() {
        let server_key = PrivateKey::generate();
        let server_identity = ClientIdentity::generate(&server_key).unwrap();

        let expected_fingerprint = Fingerprint::from_public_key(&server_key.public_key());
        let expected_hash = expected_fingerprint.hash_bytes();

        let verifier = EnrollmentVerifier::new(expected_hash);

        let cert = CertificateDer::from(server_identity.cert_der);
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );

        assert!(result.is_ok(), "Matching fingerprint should be accepted");
    }

    #[test]
    fn test_enrollment_verifier_rejects_mismatched_fingerprint() {
        let server_key = PrivateKey::generate();
        let other_key = PrivateKey::generate();

        let server_identity = ClientIdentity::generate(&server_key).unwrap();

        let wrong_fingerprint = Fingerprint::from_public_key(&other_key.public_key());
        let wrong_hash = wrong_fingerprint.hash_bytes();

        let verifier = EnrollmentVerifier::new(wrong_hash);

        let cert = CertificateDer::from(server_identity.cert_der);
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        );

        assert!(result.is_err(), "Mismatched fingerprint should be rejected");
    }
}
