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
    EnrollmentVerifier, TofuVerifier,
};
use crate::trust::TrustStore;

/// Crockford Base32 charset (for short code detection)
const SHORT_CODE_CHARSET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
const SHORT_CODE_LENGTH: usize = 6;

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
            let key_der = std::fs::read(&key_path).context("Failed to read private key")?;
            let cert_der = std::fs::read(&cert_path).context("Failed to read certificate")?;

            let private_key =
                PrivateKey::from_pkcs8_der(&key_der).context("Failed to parse private key")?;
            let identity =
                ClientIdentity::from_der(cert_der, key_der).context("Failed to load identity")?;

            Ok((private_key, identity))
        } else {
            let private_key = PrivateKey::generate();
            let identity = ClientIdentity::generate(&private_key)?;

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
/// * `token` - Enrollment token from administrator (full token or short code)
/// * `label` - Optional human-readable label for this server
pub async fn run_enrollment(
    enrollment_addr: &str,
    trust_store_addr: &str,
    token: &str,
    label: Option<&str>,
) -> Result<EnrollmentResult> {
    // Check if this is a short code (6 chars) vs full token (184 chars)
    if is_short_code(token) {
        return run_short_code_enrollment(enrollment_addr, trust_store_addr, token, label).await;
    }

    let parsed_token =
        SignedEnrollmentToken::from_base64(token).context("Invalid enrollment token format")?;
    let server_fingerprint = parsed_token.server_fingerprint();

    let identity_store = IdentityStore::open()?;
    let (private_key, identity) = identity_store.load_or_generate()?;

    eprintln!("Client fingerprint: {}", identity.fingerprint);

    let local_trust_proof = compute_local_trust_proof();

    let channel = connect_enrollment_channel(enrollment_addr, &server_fingerprint)
        .await
        .context("Failed to connect to daemon")?;

    let mut client = EnrollmentServiceClient::new(channel);

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

/// Check if input looks like a short code (6 chars in Crockford Base32).
fn is_short_code(input: &str) -> bool {
    let normalized: String = input
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if normalized.len() != SHORT_CODE_LENGTH {
        return false;
    }

    normalized.chars().all(|c| SHORT_CODE_CHARSET.contains(&(c as u8)))
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
    let server_fingerprint = read_local_server_fingerprint()
        .context("Server fingerprint not found. Is the daemon running locally?")?;

    let identity_store = IdentityStore::open()?;
    let (private_key, identity) = identity_store.load_or_generate()?;

    eprintln!("Client fingerprint: {}", identity.fingerprint);

    let local_trust_proof = compute_local_trust_proof()
        .context("Local trust proof not available. Ensure you're on the same machine as the daemon.")?;

    let channel = connect_enrollment_channel(enrollment_addr, &server_fingerprint)
        .await
        .context("Failed to connect to daemon")?;

    let mut client = EnrollmentServiceClient::new(channel);

    // Empty token but valid local_trust_proof triggers same-machine auto-approval
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
/// Uses server-only TLS (no client cert) - for initial enrollment before client has identity.
async fn connect_enrollment_channel(
    daemon_addr: &str,
    server_fingerprint: &Fingerprint,
) -> Result<Channel> {
    use rustls::ClientConfig;

    let verifier = EnrollmentVerifier::from_fingerprint(server_fingerprint);

    // No client cert - we're enrolling so no identity yet
    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    build_tls_channel(daemon_addr, tls_config).await
}

/// Connect to daemon with TOFU (Trust-On-First-Use) for short code enrollment.
///
/// Returns the channel and the captured server fingerprint.
async fn connect_tofu_channel(daemon_addr: &str) -> Result<(Channel, std::sync::Arc<TofuVerifier>)> {
    use rustls::ClientConfig;

    let verifier = TofuVerifier::new();
    let verifier_clone = verifier.clone();

    let tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let channel = build_tls_channel(daemon_addr, tls_config).await?;
    Ok((channel, verifier_clone))
}

/// Run enrollment with a short code (TOFU flow).
///
/// # Arguments
/// * `enrollment_addr` - Address of the enrollment service (port 50051)
/// * `trust_store_addr` - Address to key the trust store entry by (port 50052, the main API)
/// * `short_code` - Short enrollment code (e.g., "ABC-123")
/// * `label` - Optional human-readable label for this server
pub async fn run_short_code_enrollment(
    enrollment_addr: &str,
    trust_store_addr: &str,
    short_code: &str,
    label: Option<&str>,
) -> Result<EnrollmentResult> {
    eprintln!("Using short code enrollment (TOFU)...");

    let identity_store = IdentityStore::open()?;
    let (private_key, identity) = identity_store.load_or_generate()?;

    eprintln!("Client fingerprint: {}", identity.fingerprint);

    let (channel, tofu_verifier) = connect_tofu_channel(enrollment_addr)
        .await
        .context("Failed to connect to daemon")?;

    let mut client = EnrollmentServiceClient::new(channel);

    let request = CompleteEnrollmentRequest {
        token: short_code.to_string(),
        public_key: private_key.public_key().to_bytes().to_vec(),
        client_cert_der: identity.cert_der.clone(),
        local_trust_proof: vec![],
    };

    let response = client
        .complete_enrollment(request)
        .await
        .context("Enrollment request failed")?
        .into_inner();

    let status = EnrollmentStatus::try_from(response.status).unwrap_or(EnrollmentStatus::Rejected);

    match status {
        EnrollmentStatus::Approved => {
            let server_fp = tofu_verifier
                .captured_fingerprint()
                .context("Failed to capture server fingerprint")?;

            let mut trust_store = TrustStore::load()?;
            trust_store.trust(trust_store_addr, &server_fp, label);
            trust_store.save()?;
            eprintln!("Server fingerprint stored: {}", server_fp);

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

/// Connect to daemon with mTLS (mutual TLS) for authenticated operations.
/// Requires both server fingerprint verification and client certificate.
async fn connect_authenticated_channel(
    daemon_addr: &str,
    server_fingerprint: &Fingerprint,
    client_identity: &ClientIdentity,
) -> Result<Channel> {
    use crate::tls::build_mtls_config;

    let verifier = EnrollmentVerifier::from_fingerprint(server_fingerprint);
    let tls_config = build_mtls_config(client_identity, verifier)?;

    build_tls_channel(daemon_addr, tls_config).await
}

/// Check enrollment status for a client.
///
/// # Arguments
/// * `main_api_addr` - Address of the main API (port 50052), where enrollment service is also available with mTLS
pub async fn check_status(main_api_addr: &str) -> Result<bool> {
    let identity_store = IdentityStore::open()?;

    let (_, client_identity) = identity_store
        .load_or_generate()
        .context("No client identity found. Run 'continuum enroll' first.")?;

    let trust_store = TrustStore::load()?;
    let trusted = trust_store
        .get(main_api_addr)
        .context("Server not trusted. Run 'continuum enroll' first.")?;
    let server_fingerprint = Fingerprint::parse(&trusted.fingerprint)
        .context("Invalid fingerprint in trust store")?;

    // Enrollment service also available on main API port with mTLS
    let channel =
        connect_authenticated_channel(main_api_addr, &server_fingerprint, &client_identity)
            .await?;

    let mut client = EnrollmentServiceClient::new(channel);

    let request = continuum_proto::enrollment::v1::GetEnrollmentStatusRequest {
        client_fingerprint: client_identity.fingerprint.to_string(),
    };

    let response = client
        .get_enrollment_status(request)
        .await
        .context("Status check failed")?
        .into_inner();

    Ok(response.is_authorized)
}

/// Generate an enrollment token remotely via relay.
///
/// Requires an already-enrolled client to authenticate via mTLS.
/// Rate limited to 3 live tokens per daemon.
pub async fn generate_token_remote(
    relay_config: &crate::relay::RelayConfig,
    daemon_id: &str,
    label: Option<&str>,
) -> Result<(String, i64)> {
    use continuum_proto::enrollment::v1::RequestEnrollmentTokenRequest;

    let channel = crate::relay::connect_via_relay_channel(relay_config, daemon_id).await?;

    let mut client = EnrollmentServiceClient::new(channel);

    let request = RequestEnrollmentTokenRequest {
        label: label.unwrap_or_default().to_string(),
    };

    let response = client
        .request_enrollment_token(request)
        .await
        .context("Token generation failed")?
        .into_inner();

    Ok((response.token, response.expires_at))
}
