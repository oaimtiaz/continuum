//! X.509 certificate generation from Ed25519 identities.
//!
//! Uses rcgen to generate self-signed certificates for mTLS.

use continuum_auth::identity::PrivateKey;
use continuum_auth::Fingerprint;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::net::IpAddr;

/// Parameters for certificate generation.
#[derive(Debug, Clone)]
pub struct CertParams {
    /// Subject common name (e.g., "continuum-daemon" or client fingerprint)
    pub common_name: String,
    /// Validity period in days
    pub validity_days: u32,
    /// Optional subject alternative names (DNS names)
    pub san_dns: Vec<String>,
    /// Optional subject alternative names (IP addresses)
    pub san_ips: Vec<IpAddr>,
}

impl Default for CertParams {
    fn default() -> Self {
        Self {
            common_name: "continuum".to_string(),
            validity_days: 90,
            san_dns: vec!["localhost".to_string()],
            san_ips: vec![
                "127.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
        }
    }
}

/// TLS identity bundle (certificate + private key in DER format).
#[derive(Clone)]
pub struct TlsIdentity {
    /// Certificate in DER format
    pub cert_der: Vec<u8>,
    /// Private key in PKCS#8 DER format
    pub key_der: Vec<u8>,
    /// Fingerprint of the underlying Ed25519 public key
    pub fingerprint: Fingerprint,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("fingerprint", &self.fingerprint)
            .field("cert_der_len", &self.cert_der.len())
            .finish()
    }
}

/// Generate a self-signed certificate from an Ed25519 keypair.
///
/// # Arguments
/// * `private_key` - The Ed25519 private key to use
/// * `params` - Certificate parameters (CN, validity, SANs)
///
/// # Returns
/// A `TlsIdentity` containing the certificate and key in various formats.
pub fn build_self_signed(
    private_key: &PrivateKey,
    params: &CertParams,
) -> Result<TlsIdentity, CertError> {
    // Convert Ed25519 key to PKCS#8 DER format for rcgen
    let pkcs8_der = private_key.to_pkcs8_der();
    let key_pair =
        KeyPair::try_from(&pkcs8_der[..]).map_err(|e| CertError::KeyPair(e.to_string()))?;

    let mut cert_params = CertificateParams::default();
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(DnType::CommonName, &params.common_name);

    // Set validity period
    cert_params.not_before = time::OffsetDateTime::now_utc();
    cert_params.not_after =
        cert_params.not_before + time::Duration::days(params.validity_days as i64);

    // Add Subject Alternative Names
    for dns in &params.san_dns {
        // rcgen requires Ia5String for DNS names
        if let Ok(san) = dns.clone().try_into() {
            cert_params.subject_alt_names.push(SanType::DnsName(san));
        }
    }
    for ip in &params.san_ips {
        cert_params.subject_alt_names.push(SanType::IpAddress(*ip));
    }

    // Generate self-signed certificate
    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| CertError::Generation(e.to_string()))?;

    let cert_der = cert.der().to_vec();
    let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

    Ok(TlsIdentity {
        cert_der,
        // Note: pkcs8_der is SecretBytes which zeroizes on drop.
        // We copy here since TlsIdentity stores key_der for later use.
        key_der: pkcs8_der.to_vec(),
        fingerprint,
    })
}


/// Errors that can occur during certificate operations.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("failed to create key pair: {0}")]
    KeyPair(String),
    #[error("failed to generate certificate: {0}")]
    Generation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_self_signed_default_params() {
        let key = PrivateKey::generate();
        let params = CertParams::default();

        let identity = build_self_signed(&key, &params).unwrap();

        assert!(!identity.cert_der.is_empty());
        assert!(!identity.key_der.is_empty());
    }

    #[test]
    fn test_build_self_signed_custom_params() {
        let key = PrivateKey::generate();
        let params = CertParams {
            common_name: "test-daemon".to_string(),
            validity_days: 30,
            san_dns: vec!["example.local".to_string()],
            san_ips: vec!["192.168.1.1".parse().unwrap()],
        };

        let identity = build_self_signed(&key, &params).unwrap();

        assert!(!identity.cert_der.is_empty());
        assert!(!identity.key_der.is_empty());
    }

    #[test]
    fn test_fingerprint_matches_key() {
        let key = PrivateKey::generate();
        let expected_fp = Fingerprint::from_public_key(&key.public_key());

        let identity = build_self_signed(&key, &CertParams::default()).unwrap();

        assert_eq!(identity.fingerprint, expected_fp);
    }

}
