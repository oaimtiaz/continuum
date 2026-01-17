//! Enrollment command for registering with the daemon.
//!
//! Implements the client side of the enrollment flow:
//! 1. Generate or load client identity (Ed25519 keypair)
//! 2. Connect to daemon's enrollment service
//! 3. Complete enrollment with token
//! 4. Store server fingerprint (TOFU)

use anyhow::{Context, Result};
use continuum_auth::enrollment::SignedEnrollmentToken;
use continuum_auth::identity::{Fingerprint, PrivateKey};
use continuum_proto::enrollment::v1::complete_enrollment_response::Status as EnrollmentStatus;
use continuum_proto::enrollment::v1::enrollment_service_client::EnrollmentServiceClient;
use continuum_proto::enrollment::v1::CompleteEnrollmentRequest;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tonic::transport::Channel;

use crate::tls::{
    build_tls_channel, extract_public_key_from_cert, fingerprint_from_cert_der, ClientIdentity,
    EnrollmentVerifier,
};
use crate::trust::TrustStore;

/// Client identity persistence.
pub struct IdentityStore {
    /// Path to the identity directory
    dir: PathBuf,
}

impl IdentityStore {
    /// Open the identity store.
    pub fn open() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("com", "continuum", "continuum")
            .context("Could not determine config directory")?;
        let dir = dirs.data_dir().join("identity");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Load or generate the client identity.
    pub fn load_or_generate(&self) -> Result<(PrivateKey, ClientIdentity)> {
        let key_path = self.dir.join("key.der");
        let cert_path = self.dir.join("cert.der");

        if key_path.exists() && cert_path.exists() {
            // Load existing identity
            let key_der = std::fs::read(&key_path).context("Failed to read private key")?;
            let cert_der = std::fs::read(&cert_path).context("Failed to read certificate")?;

            let private_key =
                PrivateKey::from_pkcs8_der(&key_der).context("Failed to parse private key")?;
            let identity =
                ClientIdentity::from_der(cert_der, key_der).context("Failed to load identity")?;

            Ok((private_key, identity))
        } else {
            // Generate new identity
            let private_key = PrivateKey::generate();
            let identity = ClientIdentity::generate(&private_key)?;

            // Save to disk
            std::fs::write(&key_path, &identity.key_der).context("Failed to save private key")?;
            std::fs::write(&cert_path, &identity.cert_der).context("Failed to save certificate")?;

            // Set restrictive permissions on key
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }

            Ok((private_key, identity))
        }
    }

    /// Get the client fingerprint if identity exists.
    #[allow(dead_code)]
    pub fn fingerprint(&self) -> Result<Option<Fingerprint>> {
        let cert_path = self.dir.join("cert.der");
        if cert_path.exists() {
            let cert_der = std::fs::read(&cert_path)?;
            // Extract public key from cert and compute fingerprint (must match server's computation)
            let public_key_bytes = extract_public_key_from_cert(&cert_der)
                .context("Failed to extract public key from certificate")?;
            let public_key = continuum_auth::identity::PublicKey::from_bytes(&public_key_bytes)?;
            Ok(Some(Fingerprint::from_public_key(&public_key)))
        } else {
            Ok(None)
        }
    }
}

/// Run the enrollment flow.
///
/// # Arguments
/// * `enrollment_addr` - Address of the enrollment service (port 50051)
/// * `trust_store_addr` - Address to key the trust store entry by (port 50052, the main API)
/// * `token` - Enrollment token from administrator
/// * `label` - Optional human-readable label for this server
pub async fn run_enrollment(
    enrollment_addr: &str,
    trust_store_addr: &str,
    token: &str,
    label: Option<&str>,
) -> Result<EnrollmentResult> {
    // Parse token to get server fingerprint for TLS verification
    let parsed_token =
        SignedEnrollmentToken::from_base64(token).context("Invalid enrollment token format")?;
    let server_fingerprint = parsed_token.server_fingerprint();

    // Load or generate identity
    let identity_store = IdentityStore::open()?;
    let (private_key, identity) = identity_store.load_or_generate()?;

    eprintln!("Client fingerprint: {}", identity.fingerprint);

    // Attempt to compute same-machine trust proof
    let local_trust_proof = compute_local_trust_proof();

    // Connect to enrollment service with TLS (server fingerprint from token)
    let channel = connect_enrollment_channel(enrollment_addr, &server_fingerprint)
        .await
        .context("Failed to connect to daemon")?;

    let mut client = EnrollmentServiceClient::new(channel);

    // Complete enrollment
    let request = CompleteEnrollmentRequest {
        token: token.to_string(),
        public_key: private_key.public_key().to_bytes().to_vec(), // Raw 32-byte Ed25519 public key
        client_cert_der: identity.cert_der.clone(),
        local_trust_proof: local_trust_proof.unwrap_or_default().to_vec(),
    };

    let response = client
        .complete_enrollment(request)
        .await
        .context("Enrollment request failed")?
        .into_inner();

    let status = EnrollmentStatus::try_from(response.status).unwrap_or(EnrollmentStatus::Rejected);

    match status {
        EnrollmentStatus::Approved => {
            // Store server certificate fingerprint keyed by main API address
            if !response.server_cert_der.is_empty() {
                let server_fp = fingerprint_from_cert_der(&response.server_cert_der)
                    .context("Failed to extract server fingerprint")?;

                let mut trust_store = TrustStore::load()?;
                trust_store.trust(trust_store_addr, &server_fp, label);
                trust_store.save()?;
                eprintln!("Server fingerprint stored: {}", server_fp);
            }

            Ok(EnrollmentResult::Approved {
                client_fingerprint: response.client_fingerprint,
            })
        }
        EnrollmentStatus::PendingApproval => Ok(EnrollmentResult::Pending {
            client_fingerprint: response.client_fingerprint,
        }),
        EnrollmentStatus::Rejected | EnrollmentStatus::Unknown => Ok(EnrollmentResult::Rejected {
            reason: if response.rejection_reason.is_empty() {
                "Unknown reason".to_string()
            } else {
                response.rejection_reason
            },
        }),
    }
}

/// Result of an enrollment attempt.
pub enum EnrollmentResult {
    Approved { client_fingerprint: String },
    Pending { client_fingerprint: String },
    Rejected { reason: String },
}

/// Compute the same-machine trust proof (SHA256 of local trust secret).
pub fn compute_local_trust_proof() -> Option<[u8; 32]> {
    // Try to read the local trust token
    let runtime_dir = get_runtime_dir()?;
    let token_path = runtime_dir.join("continuum").join("local-trust-token");

    let secret = std::fs::read(&token_path).ok()?;
    if secret.len() != 32 {
        return None;
    }

    // Return SHA256 of secret (not the secret itself)
    Some(Sha256::digest(&secret).into())
}

/// Get the runtime directory (same logic as daemon).
pub fn get_runtime_dir() -> Option<PathBuf> {
    // Try XDG_RUNTIME_DIR first
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(&dir);
        if path.exists() {
            return Some(path);
        }
    }

    // Try /run/user/$UID
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        let path = PathBuf::from(format!("/run/user/{}", uid));
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Read the server fingerprint from the local runtime directory.
pub fn read_local_server_fingerprint() -> Result<Fingerprint> {
    let runtime_dir = get_runtime_dir().context("No runtime directory available")?;
    let path = runtime_dir.join("continuum").join("server-fingerprint");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read server fingerprint from {}", path.display()))?;
    Fingerprint::parse(content.trim()).context("Invalid server fingerprint format")
}

/// Run local enrollment (same-machine, no token).
///
/// # Arguments
/// * `enrollment_addr` - Address of the enrollment service (port 50051)
/// * `trust_store_addr` - Address to key the trust store entry by (port 50052, the main API)
/// * `label` - Optional human-readable label for this server
pub async fn run_local_enrollment(
    enrollment_addr: &str,
    trust_store_addr: &str,
    label: Option<&str>,
) -> Result<EnrollmentResult> {
    // Read server fingerprint from local file
    let server_fingerprint = read_local_server_fingerprint()
        .context("Server fingerprint not found. Is the daemon running locally?")?;

    // Load or generate identity
    let identity_store = IdentityStore::open()?;
    let (private_key, identity) = identity_store.load_or_generate()?;

    eprintln!("Client fingerprint: {}", identity.fingerprint);

    // Compute same-machine proof (required for local enrollment)
    let local_trust_proof = compute_local_trust_proof()
        .context("Local trust proof not available. Ensure you're on the same machine as the daemon.")?;

    // Connect to enrollment service with TLS (server fingerprint from local file)
    let channel = connect_enrollment_channel(enrollment_addr, &server_fingerprint)
        .await
        .context("Failed to connect to daemon")?;

    let mut client = EnrollmentServiceClient::new(channel);

    // Complete enrollment with empty token but valid local_trust_proof
    let request = CompleteEnrollmentRequest {
        token: String::new(),
        public_key: private_key.public_key().to_bytes().to_vec(),
        client_cert_der: identity.cert_der.clone(),
        local_trust_proof: local_trust_proof.to_vec(),
    };

    let response = client
        .complete_enrollment(request)
        .await
        .context("Enrollment request failed")?
        .into_inner();

    let status = EnrollmentStatus::try_from(response.status).unwrap_or(EnrollmentStatus::Rejected);

    match status {
        EnrollmentStatus::Approved => {
            // Store server certificate fingerprint keyed by main API address
            if !response.server_cert_der.is_empty() {
                let server_fp = fingerprint_from_cert_der(&response.server_cert_der)
                    .context("Failed to extract server fingerprint")?;

                let mut trust_store = TrustStore::load()?;
                trust_store.trust(trust_store_addr, &server_fp, label);
                trust_store.save()?;
                eprintln!("Server fingerprint stored: {}", server_fp);
            }

            Ok(EnrollmentResult::Approved {
                client_fingerprint: response.client_fingerprint,
            })
        }
        EnrollmentStatus::PendingApproval => Ok(EnrollmentResult::Pending {
            client_fingerprint: response.client_fingerprint,
        }),
        EnrollmentStatus::Rejected | EnrollmentStatus::Unknown => Ok(EnrollmentResult::Rejected {
            reason: if response.rejection_reason.is_empty() {
                "Unknown reason".to_string()
            } else {
                response.rejection_reason
            },
        }),
    }
}

/// Connect to daemon for enrollment with TLS verification using server fingerprint from token.
async fn connect_enrollment_channel(
    daemon_addr: &str,
    server_fingerprint: &Fingerprint,
) -> Result<Channel> {
    use rustls::ClientConfig;

    // Create verifier that pins to the server fingerprint from the token
    let verifier = EnrollmentVerifier::from_fingerprint(server_fingerprint);

    // Build TLS config without client cert (we're enrolling, so no client identity yet)
    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    build_tls_channel(daemon_addr, tls_config).await
}

/// Check enrollment status for a client.
pub async fn check_status(daemon_addr: &str) -> Result<bool> {
    let identity_store = IdentityStore::open()?;

    let fingerprint = identity_store
        .fingerprint()?
        .context("No client identity found. Run 'continuum enroll' first.")?;

    let channel = tonic::transport::Channel::from_shared(daemon_addr.to_string())
        .context("Invalid daemon address")?
        .connect()
        .await
        .context("Failed to connect to daemon")?;

    let mut client = EnrollmentServiceClient::new(channel);

    let request = continuum_proto::enrollment::v1::GetEnrollmentStatusRequest {
        client_fingerprint: fingerprint.to_string(),
    };

    let response = client
        .get_enrollment_status(request)
        .await
        .context("Status check failed")?
        .into_inner();

    Ok(response.is_authorized)
}
