//! Certificate utilities for X.509 parsing.
//!
//! # Security
//!
//! - Input is limited to 16KB to prevent DoS
//! - The x509_parser library handles ASN.1 parsing safely

use thiserror::Error;
use x509_parser::prelude::*;

/// Maximum certificate size (16KB is generous for a single cert)
pub const MAX_CERT_SIZE: usize = 16 * 1024;

/// Errors that can occur during certificate parsing.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("certificate too large: {0} bytes (max {MAX_CERT_SIZE})")]
    TooLarge(usize),

    #[error("failed to parse X.509 certificate: {0}")]
    ParseError(String),
}

/// Extract raw public key bytes from a DER-encoded X.509 certificate.
///
/// # Errors
///
/// Returns `CertError::TooLarge` if certificate exceeds 16KB.
/// Returns `CertError::ParseError` if the certificate is malformed.
pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, CertError> {
    // Input size validation (DoS protection)
    if cert_der.len() > MAX_CERT_SIZE {
        return Err(CertError::TooLarge(cert_der.len()));
    }

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| CertError::ParseError(format!("{:?}", e)))?;

    Ok(cert.public_key().subject_public_key.data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_too_large() {
        let large_data = vec![0u8; MAX_CERT_SIZE + 1];
        let result = extract_public_key_from_cert(&large_data);
        assert!(matches!(result, Err(CertError::TooLarge(_))));
    }

    #[test]
    fn test_invalid_cert() {
        let invalid_data = b"not a certificate";
        let result = extract_public_key_from_cert(invalid_data);
        assert!(matches!(result, Err(CertError::ParseError(_))));
    }
}
