//! Enrollment gRPC service implementation.

use crate::auth::{generate_short_code, hash_token, is_short_code, AuthStore, AuthStoreError};
use crate::tls::{TlsConnectInfo, TlsIdentity};

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64
}
use continuum_auth::cert::extract_public_key_from_cert;
use continuum_auth::enrollment::SignedEnrollmentToken;
use continuum_auth::identity::{Fingerprint, PrivateKey, PublicKey};
use continuum_proto::enrollment::v1::complete_enrollment_response::Status as EnrollmentStatus;
use continuum_proto::enrollment::v1::*;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tonic::{Request, Response, Status};

/// Implementation of the EnrollmentService gRPC service.
#[derive(Clone)]
pub struct EnrollmentServiceImpl {
    auth_store: Arc<AuthStore>,
    server_key: Arc<PrivateKey>,
    server_identity: Arc<TlsIdentity>,
    /// Expected same-machine trust proof (SHA256 of local trust secret)
    local_trust_proof: Option<[u8; 32]>,
}

impl EnrollmentServiceImpl {
    /// Create a new enrollment service.
    pub fn new(
        auth_store: Arc<AuthStore>,
        server_key: Arc<PrivateKey>,
        server_identity: Arc<TlsIdentity>,
        local_trust_proof: Option<[u8; 32]>,
    ) -> Self {
        Self {
            auth_store,
            server_key,
            server_identity,
            local_trust_proof,
        }
    }

    /// Check if the provided proof matches the expected same-machine proof.
    fn check_same_machine_trust(&self, proof: &[u8]) -> bool {
        match &self.local_trust_proof {
            Some(expected) if proof.len() == 32 => {
                let provided: [u8; 32] = proof.try_into().expect("checked length");
                expected.ct_eq(&provided).into()
            }
            _ => false,
        }
    }

    /// C3: Require mTLS authentication for admin operations.
    ///
    /// Checks request extensions for TLS connection info and verifies
    /// the client is in the authorization allowlist.
    fn require_authenticated<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(info) = request.extensions().get::<TlsConnectInfo>() {
            if let Some(ref fp) = info.client_fingerprint {
                if self.auth_store.is_authorized_cached(fp) {
                    return Ok(());
                }
            }
        }
        Err(Status::unauthenticated("Admin operations require mTLS authentication"))
    }
}

#[tonic::async_trait]
impl enrollment_service_server::EnrollmentService for EnrollmentServiceImpl {
    async fn initiate_enrollment(
        &self,
        request: Request<InitiateEnrollmentRequest>,
    ) -> Result<Response<InitiateEnrollmentResponse>, Status> {
        let req = request.into_inner();

        // Clamp validity to 1 minute - 1 hour
        let validity = if req.validity_seconds == 0 {
            300 // Default 5 minutes
        } else {
            req.validity_seconds.clamp(60, 3600)
        };

        let token = SignedEnrollmentToken::generate(&self.server_key, validity as i64);
        let short_code = generate_short_code();

        let token_base64 = token.to_base64();
        let token_hash = hash_token(&token_base64);

        self.auth_store
            .create_enrollment_token_with_short_code(
                &token_hash,
                &short_code,
                if req.label.is_empty() {
                    None
                } else {
                    Some(&req.label)
                },
                token.expires_at(),
            )
            .await
            .map_err(|e| Status::internal(format!("failed to store token: {}", e)))?;

        tracing::info!(
            label = %req.label,
            short_code = %short_code,
            expires_at = token.expires_at(),
            "Enrollment token generated"
        );

        Ok(Response::new(InitiateEnrollmentResponse {
            token: token_base64,
            display_string: format!("{}", token),
            expires_at: token.expires_at(),
            short_code,
        }))
    }

    async fn complete_enrollment(
        &self,
        request: Request<CompleteEnrollmentRequest>,
    ) -> Result<Response<CompleteEnrollmentResponse>, Status> {
        let req = request.into_inner();

        let public_key = PublicKey::from_bytes(&req.public_key)
            .map_err(|_| Status::invalid_argument("invalid public key: must be 32 bytes"))?;
        let fingerprint = Fingerprint::from_public_key(&public_key);
        let fingerprint_str = fingerprint.to_string();

        tracing::info!(fingerprint = %fingerprint_str, "Enrollment attempt");

        // C2: Verify certificate contains the claimed public key (prevents identity confusion)
        let cert_public_key = extract_public_key_from_cert(&req.client_cert_der)
            .map_err(|_| Status::invalid_argument("invalid certificate"))?;

        // Constant-time comparison prevents timing attacks on key material
        if cert_public_key.len() != req.public_key.len()
            || !bool::from(cert_public_key.as_slice().ct_eq(&req.public_key))
        {
            tracing::warn!(
                fingerprint = %fingerprint_str,
                "Certificate public key mismatch"
            );
            return Err(Status::invalid_argument(
                "certificate does not match claimed public key",
            ));
        }

        // Check if this is local enrollment (no token, valid same-machine proof)
        let is_same_machine = self.check_same_machine_trust(&req.local_trust_proof);
        let is_local_enrollment = req.token.is_empty() && is_same_machine;

        if is_local_enrollment {
            tracing::info!(fingerprint = %fingerprint_str, "Local enrollment authorized");
        } else if is_short_code(&req.token) {
            // Short code enrollment (TOFU - client trusts first server)
            tracing::info!(fingerprint = %fingerprint_str, "Short code enrollment attempt");

            match self
                .auth_store
                .consume_short_code(&req.token, &fingerprint_str)
                .await
            {
                Ok(()) => {
                    tracing::info!(fingerprint = %fingerprint_str, "Short code validated");
                }
                Err(AuthStoreError::TokenAlreadyUsed) => {
                    tracing::warn!(fingerprint = %fingerprint_str, "Short code already used or expired");
                    return Ok(Response::new(CompleteEnrollmentResponse {
                        status: EnrollmentStatus::Rejected.into(),
                        server_cert_der: vec![],
                        client_fingerprint: fingerprint_str,
                        rejection_reason: "Invalid or expired code".to_string(),
                    }));
                }
                Err(e) => {
                    tracing::error!(error = %e, "Short code database error");
                    return Err(Status::internal("internal error"));
                }
            }
        } else {
            // Full token enrollment - verify cryptographic signature
            let token = match SignedEnrollmentToken::from_base64(&req.token) {
                Ok(t) => t,
                Err(_) => {
                    tracing::warn!(fingerprint = %fingerprint_str, "Token parse failed");
                    return Ok(Response::new(CompleteEnrollmentResponse {
                        status: EnrollmentStatus::Rejected.into(),
                        server_cert_der: vec![],
                        client_fingerprint: fingerprint_str,
                        // H5: Generic error message prevents oracle attacks
                        rejection_reason: "Token validation failed".to_string(),
                    }));
                }
            };

            let now = current_timestamp();
            if token.validate(&self.server_key.public_key(), now).is_err() {
                tracing::warn!(fingerprint = %fingerprint_str, "Token signature verification failed");
                return Ok(Response::new(CompleteEnrollmentResponse {
                    status: EnrollmentStatus::Rejected.into(),
                    server_cert_der: vec![],
                    client_fingerprint: fingerprint_str,
                    // H5: Generic error message prevents oracle attacks
                    rejection_reason: "Token validation failed".to_string(),
                }));
            }

            match self
                .auth_store
                .consume_validated_token(&token, &fingerprint_str)
                .await
            {
                Ok(()) => {}
                Err(AuthStoreError::TokenAlreadyUsed) => {
                    // Token was used by another concurrent request (race condition prevented)
                    tracing::warn!(fingerprint = %fingerprint_str, "Token already consumed (concurrent use detected)");
                    return Ok(Response::new(CompleteEnrollmentResponse {
                        status: EnrollmentStatus::Rejected.into(),
                        server_cert_der: vec![],
                        client_fingerprint: fingerprint_str,
                        // H5: Generic error message prevents oracle attacks
                        rejection_reason: "Token validation failed".to_string(),
                    }));
                }
                Err(e) => {
                    tracing::error!(error = %e, "Token database error");
                    return Err(Status::internal("internal error"));
                }
            }
        }

        let label = if is_local_enrollment {
            Some("local")
        } else {
            None
        };

        self.auth_store
            .authorize_client(&fingerprint_str, &req.client_cert_der, label)
            .await
            .map_err(|e| Status::internal(format!("failed to authorize client: {}", e)))?;

        tracing::info!(
            fingerprint = %fingerprint_str,
            same_machine = is_same_machine,
            local_enrollment = is_local_enrollment,
            "Client enrolled and authorized"
        );

        Ok(Response::new(CompleteEnrollmentResponse {
            status: EnrollmentStatus::Approved.into(),
            server_cert_der: self.server_identity.cert_der.clone(),
            client_fingerprint: fingerprint_str,
            rejection_reason: String::new(),
        }))
    }

    async fn get_enrollment_status(
        &self,
        request: Request<GetEnrollmentStatusRequest>,
    ) -> Result<Response<GetEnrollmentStatusResponse>, Status> {
        // H1 FIX: Require mTLS authentication to prevent fingerprint enumeration attacks.
        // Without this, an attacker could probe for valid fingerprints.
        self.require_authenticated(&request)?;

        let req = request.into_inner();

        // Validate fingerprint format
        Fingerprint::parse(&req.client_fingerprint)
            .map_err(|_| Status::invalid_argument("invalid fingerprint format"))?;

        let (is_authorized, authorized_at) = self
            .auth_store
            .get_client_status(&req.client_fingerprint)
            .await
            .map_err(|e| Status::internal(format!("database error: {}", e)))?;

        Ok(Response::new(GetEnrollmentStatusResponse {
            is_authorized,
            authorized_at: authorized_at.unwrap_or(0),
        }))
    }

    async fn list_authorized_clients(
        &self,
        request: Request<ListAuthorizedClientsRequest>,
    ) -> Result<Response<ListAuthorizedClientsResponse>, Status> {
        // C3: Admin operations require authentication
        self.require_authenticated(&request)?;

        let clients = self
            .auth_store
            .list_all_clients()
            .await
            .map_err(|e| Status::internal(format!("database error: {}", e)))?;

        Ok(Response::new(ListAuthorizedClientsResponse {
            clients: clients
                .into_iter()
                .map(|c| AuthorizedClient {
                    fingerprint: c.fingerprint,
                    label: c.label.unwrap_or_default(),
                    authorized_at: c.authorized_at,
                    last_seen_at: c.last_seen_at.unwrap_or(0),
                })
                .collect(),
        }))
    }

    async fn revoke_client(
        &self,
        request: Request<RevokeClientRequest>,
    ) -> Result<Response<RevokeClientResponse>, Status> {
        // C3: Admin operations require authentication
        self.require_authenticated(&request)?;

        let req = request.into_inner();

        // Validate fingerprint format
        Fingerprint::parse(&req.fingerprint)
            .map_err(|_| Status::invalid_argument("invalid fingerprint format"))?;

        let success = self
            .auth_store
            .revoke_client(&req.fingerprint)
            .await
            .map_err(|e| Status::internal(format!("database error: {}", e)))?;

        if success {
            tracing::info!(fingerprint = %req.fingerprint, "Client revoked");
        }

        Ok(Response::new(RevokeClientResponse { success }))
    }

    async fn request_enrollment_token(
        &self,
        request: Request<RequestEnrollmentTokenRequest>,
    ) -> Result<Response<RequestEnrollmentTokenResponse>, Status> {
        // Require mTLS authentication (client must be enrolled)
        self.require_authenticated(&request)?;

        let req = request.into_inner();

        // Generate signed token and short code
        const DEFAULT_VALIDITY_SECONDS: i64 = 300;
        const MAX_LIVE_TOKENS: i32 = 3;

        let token = SignedEnrollmentToken::generate(&self.server_key, DEFAULT_VALIDITY_SECONDS);
        let short_code = generate_short_code();

        // Store token hash with short code
        let token_base64 = token.to_base64();
        let token_hash = hash_token(&token_base64);

        // Atomic insert with rate limit check
        self.auth_store
            .create_token_with_short_code_rate_limited(
                &token_hash,
                &short_code,
                if req.label.is_empty() {
                    None
                } else {
                    Some(&req.label)
                },
                token.expires_at(),
                MAX_LIVE_TOKENS,
            )
            .await
            .map_err(|e| match e {
                AuthStoreError::RateLimitExceeded => Status::resource_exhausted(
                    "Rate limit reached: 3 live tokens maximum. Wait for tokens to expire or be used.",
                ),
                _ => Status::internal(format!("Failed to store token: {}", e)),
            })?;

        tracing::info!(
            label = %req.label,
            short_code = %short_code,
            expires_at = token.expires_at(),
            "Enrollment token created remotely"
        );

        Ok(Response::new(RequestEnrollmentTokenResponse {
            token: token_base64,
            expires_at: token.expires_at(),
            short_code,
        }))
    }
}

