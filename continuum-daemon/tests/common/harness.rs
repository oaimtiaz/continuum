//! Test harnesses for enrollment E2E tests.
//!
//! Uses tonic's pattern of passing server directly to client (no network).

use std::sync::Arc;

use continuum_auth::enrollment::SignedEnrollmentToken;
use continuum_auth::identity::{Fingerprint, PrivateKey, PublicKey};
use continuum_proto::enrollment::v1::complete_enrollment_response::Status as EnrollmentStatus;
use continuum_proto::enrollment::v1::enrollment_service_client::EnrollmentServiceClient;
use continuum_proto::enrollment::v1::enrollment_service_server::{
    EnrollmentService, EnrollmentServiceServer,
};
use continuum_proto::enrollment::v1::*;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

/// Result type for enrollment operations.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum EnrollmentResult {
    Approved { client_fingerprint: String },
    Rejected { reason: String },
    Pending { client_fingerprint: String },
}

/// Test daemon that uses direct service-to-client communication (no network).
///
/// This is faster and simpler than spawning a network server.
pub struct TestDaemon {
    pub server_key: Arc<PrivateKey>,
    pub server_fingerprint: Fingerprint,
    pub pool: SqlitePool,
    server_identity: Arc<TlsIdentity>,
}

impl TestDaemon {
    /// Create a new test daemon with in-memory SQLite.
    pub async fn new() -> Self {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory database");

        Self::with_pool(pool).await
    }

    /// Create a test daemon with a specific database pool.
    pub async fn with_pool(pool: SqlitePool) -> Self {
        // Initialize tables
        Self::init_tables(&pool).await;

        // Generate server key
        let server_key = Arc::new(PrivateKey::generate());
        let server_fingerprint = Fingerprint::from_public_key(&server_key.public_key());

        // Build server identity (certificate)
        let server_identity = Arc::new(
            build_self_signed(&server_key, "continuum-test-daemon")
                .expect("Failed to build server identity"),
        );

        Self {
            server_key,
            server_fingerprint,
            pool,
            server_identity,
        }
    }

    async fn init_tables(pool: &SqlitePool) {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS authorized_clients (
                fingerprint TEXT PRIMARY KEY,
                cert_der BLOB NOT NULL,
                label TEXT,
                authorized_at INTEGER NOT NULL,
                last_seen_at INTEGER
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create authorized_clients table");

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                token_hash TEXT PRIMARY KEY,
                label TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                used_by_fingerprint TEXT
            )
            "#,
        )
        .execute(pool)
        .await
        .expect("Failed to create enrollment_tokens table");
    }

    /// Generate an enrollment token and store it in the database.
    pub async fn generate_token(&self, validity_secs: i64) -> String {
        let token = SignedEnrollmentToken::generate(&self.server_key, validity_secs);
        let token_b64 = token.to_base64();

        // Store token hash in database
        let token_hash = hash_token(&token_b64);
        let now = current_timestamp();
        let expires_at = token.expires_at();

        sqlx::query(
            "INSERT INTO enrollment_tokens (token_hash, created_at, expires_at) VALUES (?, ?, ?)",
        )
        .bind(&token_hash)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .expect("Failed to store token");

        token_b64
    }

    /// Check if a client is authorized.
    pub async fn is_client_authorized(&self, fingerprint: &Fingerprint) -> bool {
        let row = sqlx::query("SELECT 1 FROM authorized_clients WHERE fingerprint = ?")
            .bind(fingerprint.to_string())
            .fetch_optional(&self.pool)
            .await
            .expect("Failed to query database");
        row.is_some()
    }

    /// Revoke a client.
    pub async fn revoke_client(&self, fingerprint: &Fingerprint) {
        sqlx::query("DELETE FROM authorized_clients WHERE fingerprint = ?")
            .bind(fingerprint.to_string())
            .execute(&self.pool)
            .await
            .expect("Failed to revoke client");
    }

    /// Create an enrollment client that talks directly to this daemon (no network).
    pub fn client(&self) -> EnrollmentServiceClient<EnrollmentServiceServer<TestEnrollmentService>> {
        let service = TestEnrollmentService {
            pool: self.pool.clone(),
            server_key: self.server_key.clone(),
            server_identity: self.server_identity.clone(),
        };
        EnrollmentServiceClient::new(EnrollmentServiceServer::new(service))
    }
}

/// Test client for enrollment operations.
pub struct TestClient {
    pub private_key: PrivateKey,
    pub fingerprint: Fingerprint,
    pub cert_der: Vec<u8>,
}

impl TestClient {
    /// Create a new test client with generated identity.
    pub fn new() -> Self {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        // Generate certificate
        let identity = build_self_signed(&private_key, &fingerprint.to_string())
            .expect("Failed to build client identity");

        Self {
            private_key,
            fingerprint,
            cert_der: identity.cert_der,
        }
    }

    /// Enroll with a daemon using direct service call.
    pub async fn enroll(
        &self,
        client: &mut EnrollmentServiceClient<EnrollmentServiceServer<TestEnrollmentService>>,
        token: &str,
    ) -> Result<EnrollmentResult, String> {
        let request = CompleteEnrollmentRequest {
            token: token.to_string(),
            public_key: self.private_key.public_key().to_bytes().to_vec(),
            client_cert_der: self.cert_der.clone(),
            local_trust_proof: vec![],
        };

        let response = client
            .complete_enrollment(request)
            .await
            .map_err(|e| format!("Enrollment failed: {}", e))?
            .into_inner();

        let status =
            EnrollmentStatus::try_from(response.status).unwrap_or(EnrollmentStatus::Rejected);

        match status {
            EnrollmentStatus::Approved => Ok(EnrollmentResult::Approved {
                client_fingerprint: response.client_fingerprint,
            }),
            EnrollmentStatus::PendingApproval => Ok(EnrollmentResult::Pending {
                client_fingerprint: response.client_fingerprint,
            }),
            EnrollmentStatus::Rejected | EnrollmentStatus::Unknown => {
                Ok(EnrollmentResult::Rejected {
                    reason: response.rejection_reason,
                })
            }
        }
    }
}

// ============================================================================
// Test Enrollment Service (implements the gRPC trait)
// ============================================================================

/// Simplified enrollment service for testing.
pub struct TestEnrollmentService {
    pool: SqlitePool,
    server_key: Arc<PrivateKey>,
    server_identity: Arc<TlsIdentity>,
}

#[tonic::async_trait]
impl EnrollmentService for TestEnrollmentService {
    async fn initiate_enrollment(
        &self,
        request: tonic::Request<InitiateEnrollmentRequest>,
    ) -> Result<tonic::Response<InitiateEnrollmentResponse>, tonic::Status> {
        let req = request.into_inner();

        let validity = if req.validity_seconds == 0 {
            300
        } else {
            req.validity_seconds.clamp(60, 3600)
        };

        let token = SignedEnrollmentToken::generate(&self.server_key, validity as i64);
        let token_base64 = token.to_base64();
        let token_hash = hash_token(&token_base64);

        let now = current_timestamp();
        sqlx::query(
            "INSERT INTO enrollment_tokens (token_hash, label, created_at, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&token_hash)
        .bind(if req.label.is_empty() { None } else { Some(&req.label) })
        .bind(now)
        .bind(token.expires_at())
        .execute(&self.pool)
        .await
        .map_err(|e| tonic::Status::internal(format!("failed to store token: {}", e)))?;

        Ok(tonic::Response::new(InitiateEnrollmentResponse {
            token: token_base64,
            display_string: format!("{}", token),
            expires_at: token.expires_at(),
        }))
    }

    async fn complete_enrollment(
        &self,
        request: tonic::Request<CompleteEnrollmentRequest>,
    ) -> Result<tonic::Response<CompleteEnrollmentResponse>, tonic::Status> {
        let req = request.into_inner();

        let public_key = PublicKey::from_bytes(&req.public_key)
            .map_err(|_| tonic::Status::invalid_argument("invalid public key: must be 32 bytes"))?;
        let fingerprint = Fingerprint::from_public_key(&public_key);
        let fingerprint_str = fingerprint.to_string();

        // Validate token
        let token_hash = hash_token(&req.token);
        let now = current_timestamp();

        let row = sqlx::query(
            "SELECT expires_at, used_at FROM enrollment_tokens WHERE token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| tonic::Status::internal(format!("database error: {}", e)))?;

        let (expires_at, used_at): (i64, Option<i64>) = match row {
            None => {
                return Ok(tonic::Response::new(CompleteEnrollmentResponse {
                    status: EnrollmentStatus::Rejected.into(),
                    server_cert_der: vec![],
                    client_fingerprint: fingerprint_str,
                    rejection_reason: "Invalid token".to_string(),
                }));
            }
            Some(r) => {
                use sqlx::Row;
                (r.get("expires_at"), r.get("used_at"))
            }
        };

        if used_at.is_some() {
            return Ok(tonic::Response::new(CompleteEnrollmentResponse {
                status: EnrollmentStatus::Rejected.into(),
                server_cert_der: vec![],
                client_fingerprint: fingerprint_str,
                rejection_reason: "Token already used".to_string(),
            }));
        }

        if now > expires_at {
            return Ok(tonic::Response::new(CompleteEnrollmentResponse {
                status: EnrollmentStatus::Rejected.into(),
                server_cert_der: vec![],
                client_fingerprint: fingerprint_str,
                rejection_reason: "Token expired".to_string(),
            }));
        }

        // Mark token as used (atomic with BEGIN IMMEDIATE for concurrency)
        let result = sqlx::query(
            "UPDATE enrollment_tokens SET used_at = ?, used_by_fingerprint = ? WHERE token_hash = ? AND used_at IS NULL",
        )
        .bind(now)
        .bind(&fingerprint_str)
        .bind(&token_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| tonic::Status::internal(format!("failed to mark token used: {}", e)))?;

        // If no rows were updated, someone else consumed the token
        if result.rows_affected() == 0 {
            return Ok(tonic::Response::new(CompleteEnrollmentResponse {
                status: EnrollmentStatus::Rejected.into(),
                server_cert_der: vec![],
                client_fingerprint: fingerprint_str,
                rejection_reason: "Token already used".to_string(),
            }));
        }

        // Authorize client
        sqlx::query(
            "INSERT OR REPLACE INTO authorized_clients (fingerprint, cert_der, authorized_at) VALUES (?, ?, ?)",
        )
        .bind(&fingerprint_str)
        .bind(&req.client_cert_der)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| tonic::Status::internal(format!("failed to authorize client: {}", e)))?;

        Ok(tonic::Response::new(CompleteEnrollmentResponse {
            status: EnrollmentStatus::Approved.into(),
            server_cert_der: self.server_identity.cert_der.clone(),
            client_fingerprint: fingerprint_str,
            rejection_reason: String::new(),
        }))
    }

    async fn get_enrollment_status(
        &self,
        request: tonic::Request<GetEnrollmentStatusRequest>,
    ) -> Result<tonic::Response<GetEnrollmentStatusResponse>, tonic::Status> {
        let req = request.into_inner();

        Fingerprint::parse(&req.client_fingerprint)
            .map_err(|_| tonic::Status::invalid_argument("invalid fingerprint format"))?;

        let row = sqlx::query("SELECT authorized_at FROM authorized_clients WHERE fingerprint = ?")
            .bind(&req.client_fingerprint)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| tonic::Status::internal(format!("database error: {}", e)))?;

        let (is_authorized, authorized_at) = match row {
            Some(r) => {
                use sqlx::Row;
                (true, r.get::<i64, _>("authorized_at"))
            }
            None => (false, 0),
        };

        Ok(tonic::Response::new(GetEnrollmentStatusResponse {
            is_authorized,
            authorized_at,
        }))
    }

    async fn list_authorized_clients(
        &self,
        _request: tonic::Request<ListAuthorizedClientsRequest>,
    ) -> Result<tonic::Response<ListAuthorizedClientsResponse>, tonic::Status> {
        let rows =
            sqlx::query("SELECT fingerprint, label, authorized_at, last_seen_at FROM authorized_clients")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| tonic::Status::internal(format!("database error: {}", e)))?;

        use sqlx::Row;
        let clients = rows
            .into_iter()
            .map(|r| AuthorizedClient {
                fingerprint: r.get("fingerprint"),
                label: r.get::<Option<String>, _>("label").unwrap_or_default(),
                authorized_at: r.get("authorized_at"),
                last_seen_at: r.get::<Option<i64>, _>("last_seen_at").unwrap_or(0),
            })
            .collect();

        Ok(tonic::Response::new(ListAuthorizedClientsResponse { clients }))
    }

    async fn revoke_client(
        &self,
        request: tonic::Request<RevokeClientRequest>,
    ) -> Result<tonic::Response<RevokeClientResponse>, tonic::Status> {
        let req = request.into_inner();

        Fingerprint::parse(&req.fingerprint)
            .map_err(|_| tonic::Status::invalid_argument("invalid fingerprint format"))?;

        let result = sqlx::query("DELETE FROM authorized_clients WHERE fingerprint = ?")
            .bind(&req.fingerprint)
            .execute(&self.pool)
            .await
            .map_err(|e| tonic::Status::internal(format!("database error: {}", e)))?;

        Ok(tonic::Response::new(RevokeClientResponse {
            success: result.rows_affected() > 0,
        }))
    }
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

/// TLS identity (simplified for tests).
pub struct TlsIdentity {
    pub cert_der: Vec<u8>,
    #[allow(dead_code)]
    pub fingerprint: Fingerprint,
}

/// Build a self-signed certificate.
pub fn build_self_signed(private_key: &PrivateKey, common_name: &str) -> Result<TlsIdentity, String> {
    let pkcs8_der = private_key.to_pkcs8_der();
    let key_pair = KeyPair::try_from(&pkcs8_der[..]).map_err(|e| format!("KeyPair error: {}", e))?;

    let mut cert_params = CertificateParams::default();
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(DnType::CommonName, common_name);

    cert_params.not_before = time::OffsetDateTime::now_utc();
    cert_params.not_after = cert_params.not_before + time::Duration::days(1);

    // Add localhost SANs
    if let Ok(san) = "localhost".to_string().try_into() {
        cert_params.subject_alt_names.push(SanType::DnsName(san));
    }
    cert_params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));

    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| format!("Certificate generation error: {}", e))?;

    let cert_der = cert.der().to_vec();
    let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

    Ok(TlsIdentity { cert_der, fingerprint })
}

/// Hash a token string.
pub fn hash_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    hex::encode(hash)
}

/// Get current timestamp.
pub fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64
}
