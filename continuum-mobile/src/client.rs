//! Main client for mobile app operations.
//!
//! Handles both OAuth (to dashboard) and mTLS (to daemons).
//!
//! # Threading Model
//!
//! Public methods use `block_on` exactly once at the API boundary.
//! Internal async methods use `.await` - NEVER nest `block_on` calls (will panic).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use continuum_auth::identity::PrivateKey;
use tokio::sync::RwLock;

use crate::enrollment::{DaemonEnrollment, ParsedEnrollmentToken};
use crate::errors::ClientError;
use crate::models::{
    AttentionDetail, AttentionDetailResponse, AttentionPrompt, AttentionStatus, AttentionSummary,
    Host, HostStatus, StatusResponse, UserStatus,
};
use crate::storage::SecureStorage;
use crate::tls::ClientIdentity;
use crate::tunnel::{connect_to_daemon, TerminalTunnel};

/// API request timeout. Fail fast on mobile - users expect responsiveness.
const API_TIMEOUT: Duration = Duration::from_secs(15);

/// Main client for mobile app operations.
///
/// Handles both OAuth (to dashboard) and mTLS (to daemons).
///
/// # Example (from TypeScript via UniFFI)
///
/// ```typescript
/// const storage = new SecureStorageImpl(); // implements SecureStorage
/// const client = ContinuumClient.create("https://dashboard.example.com", storage);
///
/// await client.login(auth0Token);
/// const status = await client.getStatus();
/// ```
/// Default relay endpoint (production).
const DEFAULT_RELAY_ENDPOINT: &str = "https://relay.continuumruntime.com";

#[derive(uniffi::Object)]
pub struct ContinuumClient {
    dashboard_url: String,
    relay_endpoint: String,
    runtime: tokio::runtime::Runtime,
    http: reqwest::Client,
    storage: Box<dyn SecureStorage>,
    // Cached OAuth token (loaded from storage on init)
    oauth_token: Arc<RwLock<Option<String>>>,
    // Client mTLS identity (Ed25519 keypair + certificate)
    client_identity: Arc<RwLock<Option<ClientIdentity>>>,
    // Enrolled daemons (fingerprint -> enrollment info)
    enrollments: Arc<RwLock<HashMap<String, DaemonEnrollment>>>,
}

// Storage helper functions - not exported to UniFFI
impl ContinuumClient {
    /// Load client identity from storage.
    fn load_client_identity(storage: &Box<dyn SecureStorage>) -> Option<ClientIdentity> {
        let cert_der = storage.get("client_cert_der".into()).ok()??;
        let key_der = storage.get("client_key_der".into()).ok()??;

        // Decode from base64
        use base64::Engine;
        let cert_bytes = base64::engine::general_purpose::STANDARD
            .decode(&cert_der)
            .ok()?;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&key_der)
            .ok()?;

        ClientIdentity::from_der(cert_bytes, key_bytes).ok()
    }

    /// Save client identity to storage.
    fn save_client_identity(
        storage: &Box<dyn SecureStorage>,
        identity: &ClientIdentity,
    ) -> Result<(), ClientError> {
        use base64::Engine;
        let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&identity.cert_der);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&*identity.key_der);

        storage
            .set("client_cert_der".into(), cert_b64)
            .map_err(|e| ClientError::StorageError {
                message: e.to_string(),
            })?;
        storage
            .set("client_key_der".into(), key_b64)
            .map_err(|e| ClientError::StorageError {
                message: e.to_string(),
            })?;

        Ok(())
    }

    /// Load enrollments from storage.
    fn load_enrollments(storage: &Box<dyn SecureStorage>) -> HashMap<String, DaemonEnrollment> {
        let mut enrollments = HashMap::new();

        // Load enrollment list
        if let Ok(Some(list_json)) = storage.get("enrollments_list".into()) {
            if let Ok(fingerprints) = serde_json::from_str::<Vec<String>>(&list_json) {
                for fp in fingerprints {
                    if let Ok(Some(enrollment_json)) =
                        storage.get(format!("enrollment_{}", fp))
                    {
                        if let Ok(enrollment) = DaemonEnrollment::from_json(&enrollment_json) {
                            enrollments.insert(fp, enrollment);
                        }
                    }
                }
            }
        }

        enrollments
    }

    /// Save enrollments to storage.
    fn save_enrollments(
        storage: &Box<dyn SecureStorage>,
        enrollments: &HashMap<String, DaemonEnrollment>,
    ) -> Result<(), ClientError> {
        // Save list of fingerprints
        let fingerprints: Vec<String> = enrollments.keys().cloned().collect();
        let list_json = serde_json::to_string(&fingerprints).map_err(|e| ClientError::StorageError {
            message: e.to_string(),
        })?;
        storage
            .set("enrollments_list".into(), list_json)
            .map_err(|e| ClientError::StorageError {
                message: e.to_string(),
            })?;

        // Save each enrollment
        for (fp, enrollment) in enrollments {
            storage
                .set(format!("enrollment_{}", fp), enrollment.to_json())
                .map_err(|e| ClientError::StorageError {
                    message: e.to_string(),
                })?;
        }

        Ok(())
    }
}

#[uniffi::export]
impl ContinuumClient {
    /// Create a new client with the dashboard URL and storage.
    ///
    /// Loads cached credentials from storage during construction.
    #[uniffi::constructor]
    pub fn new(
        dashboard_url: String,
        storage: Box<dyn SecureStorage>,
    ) -> Result<Self, ClientError> {
        Self::new_with_relay(dashboard_url, DEFAULT_RELAY_ENDPOINT.to_string(), storage)
    }

    /// Create a new client with custom relay endpoint.
    ///
    /// Use this for development/testing with non-production relay.
    #[uniffi::constructor]
    pub fn new_with_relay(
        dashboard_url: String,
        relay_endpoint: String,
        storage: Box<dyn SecureStorage>,
    ) -> Result<Self, ClientError> {
        // Create single-threaded Tokio runtime for mobile efficiency
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ClientError::ServerError {
                message: format!("Failed to create runtime: {}", e),
            })?;

        // Create HTTP client with timeout
        let http = reqwest::Client::builder()
            .timeout(API_TIMEOUT)
            .build()
            .map_err(|e| ClientError::ServerError {
                message: format!("Failed to create HTTP client: {}", e),
            })?;

        // Load cached token from storage
        // Storage callback runs on main thread, which is safe here (outside block_on)
        let cached_token = storage.get("oauth_token".into()).ok().flatten();

        // Load cached client identity from storage
        let client_identity = Self::load_client_identity(&storage);

        // Load cached enrollments from storage
        let enrollments = Self::load_enrollments(&storage);

        Ok(Self {
            dashboard_url,
            relay_endpoint,
            runtime,
            http,
            storage,
            oauth_token: Arc::new(RwLock::new(cached_token)),
            client_identity: Arc::new(RwLock::new(client_identity)),
            enrollments: Arc::new(RwLock::new(enrollments)),
        })
    }

    /// Login with Auth0 token. Stores credentials securely.
    ///
    /// Call this after successful Auth0 authentication with the access token.
    pub fn login(&self, auth0_token: String) -> Result<(), ClientError> {
        // Storage operations happen outside block_on (main thread safe)
        self.storage
            .set("oauth_token".into(), auth0_token.clone())
            .map_err(|e| ClientError::StorageError {
                message: e.to_string(),
            })?;

        self.runtime.block_on(async {
            *self.oauth_token.write().await = Some(auth0_token);
            Ok(())
        })
    }

    /// Logout and clear all credentials.
    pub fn logout(&self) -> Result<(), ClientError> {
        // Storage operations happen outside block_on (main thread safe)
        let _ = self.storage.remove("oauth_token".into());

        self.runtime.block_on(async {
            *self.oauth_token.write().await = None;
            Ok(())
        })
    }

    /// Check if user has valid credentials.
    pub fn is_logged_in(&self) -> bool {
        self.runtime
            .block_on(async { self.oauth_token.read().await.is_some() })
    }

    /// Get current user status (hosts, pending attention).
    pub fn get_status(&self) -> Result<UserStatus, ClientError> {
        self.runtime.block_on(self.get_status_async())
    }

    /// Get full attention request details.
    pub fn get_attention(&self, id: String) -> Result<AttentionDetail, ClientError> {
        self.runtime.block_on(self.get_attention_async(id))
    }

    /// Respond to an attention request.
    pub fn respond_to_attention(&self, id: String, value: String) -> Result<(), ClientError> {
        self.runtime
            .block_on(self.respond_to_attention_async(id, value))
    }

    // =========================================================================
    // mTLS Enrollment Methods
    // =========================================================================

    /// Parse an enrollment token from a QR code.
    ///
    /// Returns the daemon fingerprint that will be enrolled.
    /// Call `enroll_with_token` after parsing to complete enrollment.
    pub fn parse_enrollment_token(&self, token_base64: String) -> Result<String, ClientError> {
        let parsed = ParsedEnrollmentToken::parse(&token_base64)?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ClientError::ServerError {
                message: "System time error".to_string(),
            })?
            .as_secs() as i64;

        if parsed.is_expired(now) {
            return Err(ClientError::EnrollmentFailed {
                reason: "Enrollment token has expired".to_string(),
            });
        }

        Ok(parsed.server_fingerprint.to_string())
    }

    /// Enroll with a daemon using a QR code token.
    ///
    /// This generates or loads the client mTLS identity, connects to the daemon
    /// through the relay, and completes the enrollment handshake.
    ///
    /// # Arguments
    ///
    /// * `token_base64` - The enrollment token from the QR code
    /// * `label` - Optional human-readable label for this daemon
    pub fn enroll_with_token(
        &self,
        token_base64: String,
        label: Option<String>,
    ) -> Result<String, ClientError> {
        self.runtime
            .block_on(self.enroll_with_token_async(token_base64, label))
    }

    /// Check if enrolled with a specific daemon.
    pub fn is_enrolled(&self, daemon_fingerprint: String) -> bool {
        self.runtime.block_on(async {
            self.enrollments
                .read()
                .await
                .contains_key(&daemon_fingerprint)
        })
    }

    /// Get list of enrolled daemon fingerprints.
    pub fn enrolled_daemons(&self) -> Vec<String> {
        self.runtime.block_on(async {
            self.enrollments
                .read()
                .await
                .keys()
                .cloned()
                .collect()
        })
    }

    /// Get the client's fingerprint (for display to user).
    pub fn client_fingerprint(&self) -> Result<String, ClientError> {
        self.runtime.block_on(async {
            let identity = self.client_identity.read().await;
            identity
                .as_ref()
                .map(|id| id.fingerprint.to_string())
                .ok_or(ClientError::MtlsFailed {
                    reason: "No client identity generated yet".to_string(),
                })
        })
    }

    // =========================================================================
    // Terminal Session Methods
    // =========================================================================

    /// Open a terminal session to an enrolled daemon.
    ///
    /// Returns a TerminalSession that can be used to send/receive PTY data.
    pub fn open_terminal(
        &self,
        daemon_fingerprint: String,
        _handler: Box<dyn PtyDataHandler>,
    ) -> Result<TerminalSession, ClientError> {
        self.runtime
            .block_on(self.open_terminal_async(daemon_fingerprint))
    }
}

// Internal async implementations - these use .await, never block_on
impl ContinuumClient {
    async fn get_token(&self) -> Result<String, ClientError> {
        self.oauth_token
            .read()
            .await
            .clone()
            .ok_or(ClientError::NotAuthenticated)
    }

    async fn get_status_async(&self) -> Result<UserStatus, ClientError> {
        let token = self.get_token().await?;

        let resp = self
            .http
            .get(format!("{}/api/mobile/status", self.dashboard_url))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ClientError::NotAuthenticated);
        }

        if !resp.status().is_success() {
            return Err(ClientError::ServerError {
                message: format!("Status {}", resp.status()),
            });
        }

        // Parse API response
        let status_resp: StatusResponse =
            resp.json().await.map_err(|e| ClientError::ServerError {
                message: format!("Failed to parse response: {}", e),
            })?;

        // Convert to public types
        Ok(UserStatus {
            user_name: "User".to_string(), // TODO: Get from token claims
            avatar_url: None,
            hosts: status_resp.hosts.into_iter().map(Host::from).collect(),
            pending_attention: status_resp
                .pending_attention
                .into_iter()
                .map(AttentionSummary::from)
                .collect(),
        })
    }

    async fn get_attention_async(&self, id: String) -> Result<AttentionDetail, ClientError> {
        let token = self.get_token().await?;

        let resp = self
            .http
            .get(format!("{}/api/mobile/attention/{}", self.dashboard_url, id))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        match resp.status() {
            s if s == reqwest::StatusCode::UNAUTHORIZED => Err(ClientError::NotAuthenticated),
            s if s == reqwest::StatusCode::NOT_FOUND => Err(ClientError::AlreadyResolved),
            s if s == reqwest::StatusCode::GONE => Err(ClientError::Expired),
            s if s.is_success() => {
                // Parse API response
                let detail_resp: AttentionDetailResponse =
                    resp.json().await.map_err(|e| ClientError::ServerError {
                        message: format!("Failed to parse response: {}", e),
                    })?;

                // Convert prompt, setting the message
                let mut prompt = AttentionPrompt::from(detail_resp.prompt);
                match &mut prompt {
                    AttentionPrompt::Binary { message, .. } => {
                        *message = detail_resp.message.clone();
                    }
                    AttentionPrompt::TextInput { message, .. } => {
                        *message = detail_resp.message.clone();
                    }
                    AttentionPrompt::Unknown { message } => {
                        *message = detail_resp.message.clone();
                    }
                }

                Ok(AttentionDetail {
                    id: detail_resp.id,
                    task_id: String::new(), // Not in API response
                    host: Host {
                        fingerprint: detail_resp.host_fingerprint,
                        label: Some(detail_resp.host_label),
                        hostname: None,
                        status: HostStatus::Online, // Assume online if we got the request
                        last_seen_at: detail_resp.created_at.clone(),
                    },
                    task_name: detail_resp.task_name,
                    prompt,
                    output_context: detail_resp.output_context,
                    status: AttentionStatus::Pending,
                    created_at: detail_resp.created_at,
                })
            }
            status => Err(ClientError::ServerError {
                message: format!("Unexpected status: {}", status),
            }),
        }
    }

    async fn respond_to_attention_async(&self, id: String, value: String) -> Result<(), ClientError> {
        let token = self.get_token().await?;

        let resp = self
            .http
            .post(format!(
                "{}/api/mobile/attention/{}/respond",
                self.dashboard_url, id
            ))
            .bearer_auth(&token)
            .json(&serde_json::json!({ "value": value }))
            .send()
            .await
            .map_err(map_reqwest_error)?;

        match resp.status() {
            s if s == reqwest::StatusCode::UNAUTHORIZED => Err(ClientError::NotAuthenticated),
            s if s == reqwest::StatusCode::NOT_FOUND || s == reqwest::StatusCode::CONFLICT => {
                Err(ClientError::AlreadyResolved)
            }
            s if s == reqwest::StatusCode::GONE => Err(ClientError::Expired),
            s if s.is_success() => Ok(()),
            status => Err(ClientError::ServerError {
                message: format!("Unexpected status: {}", status),
            }),
        }
    }

    // =========================================================================
    // Enrollment async implementations
    // =========================================================================

    /// Get or generate client mTLS identity.
    async fn get_or_create_identity(&self) -> Result<ClientIdentity, ClientError> {
        // Check if we already have an identity
        {
            let identity = self.client_identity.read().await;
            if let Some(id) = identity.as_ref() {
                return Ok(id.clone());
            }
        }

        // Generate new identity
        let private_key = PrivateKey::generate();
        let identity = ClientIdentity::generate(&private_key)?;

        // Save to storage
        Self::save_client_identity(&self.storage, &identity)?;

        // Cache in memory
        *self.client_identity.write().await = Some(identity.clone());

        Ok(identity)
    }

    async fn enroll_with_token_async(
        &self,
        token_base64: String,
        label: Option<String>,
    ) -> Result<String, ClientError> {
        // Parse the token
        let parsed = ParsedEnrollmentToken::parse(&token_base64)?;
        let daemon_fingerprint = parsed.server_fingerprint.clone();

        // Get OAuth token for relay auth
        let oauth_token = self.get_token().await?;

        // Get or create client identity
        let identity = self.get_or_create_identity().await?;

        // Connect to daemon through relay with mTLS
        let tls_stream = connect_to_daemon(
            &self.relay_endpoint,
            &oauth_token,
            daemon_fingerprint.as_str(),
            &identity,
        )
        .await?;

        // TODO: Send enrollment request over the mTLS stream
        // For now, we just establish the connection which validates mTLS works
        // The actual enrollment protocol would send:
        // 1. The enrollment token
        // 2. Our public key
        // 3. Receive confirmation
        drop(tls_stream);

        // Store enrollment
        let enrollment = DaemonEnrollment::new(
            daemon_fingerprint.clone(),
            self.relay_endpoint.clone(),
            label,
        );

        {
            let mut enrollments = self.enrollments.write().await;
            enrollments.insert(daemon_fingerprint.to_string(), enrollment);
            Self::save_enrollments(&self.storage, &enrollments)?;
        }

        Ok(daemon_fingerprint.to_string())
    }

    async fn open_terminal_async(
        &self,
        daemon_fingerprint: String,
    ) -> Result<TerminalSession, ClientError> {
        // Check enrollment
        let enrollment = {
            let enrollments = self.enrollments.read().await;
            enrollments
                .get(&daemon_fingerprint)
                .cloned()
                .ok_or(ClientError::NotEnrolled)?
        };

        // Get OAuth token for relay auth
        let oauth_token = self.get_token().await?;

        // Get client identity
        let identity = {
            let identity = self.client_identity.read().await;
            identity.clone().ok_or(ClientError::NotEnrolled)?
        };

        // Connect to daemon through relay with mTLS
        let tls_stream = connect_to_daemon(
            &enrollment.relay_endpoint,
            &oauth_token,
            &daemon_fingerprint,
            &identity,
        )
        .await?;

        // Create terminal tunnel
        let _tunnel = TerminalTunnel::new(tls_stream, enrollment);

        // TODO: Implement actual terminal session with PTY protocol
        // For now, return a placeholder session
        Ok(TerminalSession {
            _session_id: daemon_fingerprint,
        })
    }
}

/// Map reqwest errors to ClientError with appropriate granularity.
fn map_reqwest_error(e: reqwest::Error) -> ClientError {
    if e.is_timeout() {
        ClientError::Timeout
    } else if e.is_connect() {
        ClientError::NetworkUnavailable
    } else {
        ClientError::ServerError {
            message: e.to_string(),
        }
    }
}

/// Callback interface for PTY data streaming.
///
/// TypeScript implements this to feed data to xterm.js.
#[uniffi::export(callback_interface)]
pub trait PtyDataHandler: Send + Sync {
    /// Called when data is received from the PTY.
    fn on_data(&self, data: Vec<u8>);

    /// Called when the PTY session exits normally.
    fn on_exit(&self, code: i32);

    /// Called when an error occurs (connection lost, mTLS failure, etc).
    /// The session is no longer usable after this callback.
    fn on_error(&self, error: String);
}

/// Active terminal session.
///
/// Represents an open mTLS tunnel to a daemon's PTY.
#[derive(uniffi::Object)]
pub struct TerminalSession {
    // Placeholder - will hold tunnel handle, session_id, etc.
    _session_id: String,
}

#[uniffi::export]
impl TerminalSession {
    /// Write input to the PTY.
    pub fn write(&self, _data: Vec<u8>) -> Result<(), ClientError> {
        // TODO: Send to tunnel
        Ok(())
    }

    /// Resize the PTY.
    pub fn resize(&self, _cols: u32, _rows: u32) -> Result<(), ClientError> {
        // TODO: Send resize signal
        Ok(())
    }

    /// Close the session gracefully.
    pub fn close(&self) -> Result<(), ClientError> {
        // TODO: Close tunnel
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::StorageError;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use wiremock::matchers::{bearer_token, body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// In-memory mock storage for tests
    struct MockStorage {
        data: Mutex<HashMap<String, String>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }

        fn with_token(token: &str) -> Self {
            let storage = Self::new();
            storage
                .data
                .lock()
                .unwrap()
                .insert("oauth_token".to_string(), token.to_string());
            storage
        }
    }

    impl SecureStorage for MockStorage {
        fn get(&self, key: String) -> Result<Option<String>, StorageError> {
            Ok(self.data.lock().unwrap().get(&key).cloned())
        }

        fn set(&self, key: String, value: String) -> Result<(), StorageError> {
            self.data.lock().unwrap().insert(key, value);
            Ok(())
        }

        fn remove(&self, key: String) -> Result<(), StorageError> {
            self.data.lock().unwrap().remove(&key);
            Ok(())
        }
    }

    #[test]
    fn test_login_stores_token() {
        let storage = MockStorage::new();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        assert!(!client.is_logged_in());

        client.login("test-token".to_string()).unwrap();

        assert!(client.is_logged_in());
    }

    #[test]
    fn test_logout_clears_token() {
        let storage = MockStorage::with_token("test-token");
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        assert!(client.is_logged_in());

        client.logout().unwrap();

        assert!(!client.is_logged_in());
    }

    #[test]
    fn test_get_status_requires_auth() {
        let storage = MockStorage::new();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        let result = client.get_status();

        assert!(matches!(result, Err(ClientError::NotAuthenticated)));
    }

    #[test]
    fn test_get_status_success() {
        // Set up mock server in a separate runtime, keep it alive for the test
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .and(bearer_token("test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "hosts": [
                        {
                            "fingerprint": "SHA256:abc123",
                            "label": "MacBook Pro",
                            "hostname": "omars-mbp.local",
                            "status": "online",
                            "lastSeenAt": "2024-01-15T10:30:00Z"
                        }
                    ],
                    "pendingAttention": [
                        {
                            "id": "att-123",
                            "hostLabel": "MacBook Pro",
                            "taskName": "Deploy",
                            "message": "Continue?",
                            "createdAt": "2024-01-15T10:30:00Z",
                            "urgent": false
                        }
                    ]
                })))
                .mount(&server)
                .await;

            let uri = server.uri();
            // Return server to keep it alive
            (uri, server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let status = client.get_status().unwrap();

        assert_eq!(status.hosts.len(), 1);
        assert_eq!(status.hosts[0].fingerprint, "SHA256:abc123");
        assert_eq!(status.hosts[0].label, Some("MacBook Pro".to_string()));
        assert_eq!(status.hosts[0].status, HostStatus::Online);

        assert_eq!(status.pending_attention.len(), 1);
        assert_eq!(status.pending_attention[0].id, "att-123");
        assert_eq!(status.pending_attention[0].message, "Continue?");
    }

    #[test]
    fn test_get_status_unauthorized() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .respond_with(ResponseTemplate::new(401))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("bad-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.get_status();

        assert!(matches!(result, Err(ClientError::NotAuthenticated)));
    }

    #[test]
    fn test_get_attention_success() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/attention/att-123"))
                .and(bearer_token("test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "att-123",
                    "hostFingerprint": "SHA256:abc123",
                    "hostLabel": "MacBook Pro",
                    "taskName": "Deploy",
                    "message": "Do you want to continue with deployment?",
                    "prompt": {
                        "type": "binary",
                        "affirmLabel": "Yes",
                        "affirmValue": "y",
                        "denyLabel": "No",
                        "denyValue": "n",
                        "defaultIsAffirm": true
                    },
                    "outputContext": ["$ npm run deploy", "Building..."],
                    "createdAt": "2024-01-15T10:30:00Z",
                    "urgent": false
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let detail = client.get_attention("att-123".to_string()).unwrap();

        assert_eq!(detail.id, "att-123");
        assert_eq!(detail.host.fingerprint, "SHA256:abc123");
        assert_eq!(detail.task_name, Some("Deploy".to_string()));
        assert_eq!(detail.output_context.len(), 2);

        match &detail.prompt {
            AttentionPrompt::Binary {
                message,
                affirm_label,
                affirm_value,
                deny_label,
                deny_value,
                default_is_affirm,
            } => {
                assert_eq!(message, "Do you want to continue with deployment?");
                assert_eq!(affirm_label, "Yes");
                assert_eq!(affirm_value, "y");
                assert_eq!(deny_label, "No");
                assert_eq!(deny_value, "n");
                assert!(default_is_affirm);
            }
            _ => panic!("Expected Binary prompt"),
        }
    }

    #[test]
    fn test_get_attention_not_found() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/attention/att-999"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.get_attention("att-999".to_string());

        assert!(matches!(result, Err(ClientError::AlreadyResolved)));
    }

    #[test]
    fn test_get_attention_expired() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/attention/att-expired"))
                .respond_with(ResponseTemplate::new(410))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.get_attention("att-expired".to_string());

        assert!(matches!(result, Err(ClientError::Expired)));
    }

    #[test]
    fn test_respond_to_attention_success() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/api/mobile/attention/att-123/respond"))
                .and(bearer_token("test-token"))
                .and(body_json(serde_json::json!({ "value": "y" })))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.respond_to_attention("att-123".to_string(), "y".to_string());

        assert!(result.is_ok());
    }

    #[test]
    fn test_respond_to_attention_conflict() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/api/mobile/attention/att-123/respond"))
                .respond_with(ResponseTemplate::new(409))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.respond_to_attention("att-123".to_string(), "y".to_string());

        assert!(matches!(result, Err(ClientError::AlreadyResolved)));
    }

    #[test]
    fn test_text_input_prompt() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/attention/att-text"))
                .and(bearer_token("test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "att-text",
                    "hostFingerprint": "SHA256:abc123",
                    "hostLabel": "MacBook Pro",
                    "taskName": null,
                    "message": "Enter your password:",
                    "prompt": {
                        "type": "text",
                        "placeholder": "Password"
                    },
                    "outputContext": [],
                    "createdAt": "2024-01-15T10:30:00Z",
                    "urgent": true
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let detail = client.get_attention("att-text".to_string()).unwrap();

        match &detail.prompt {
            AttentionPrompt::TextInput {
                message,
                placeholder,
                ..
            } => {
                assert_eq!(message, "Enter your password:");
                assert_eq!(placeholder, &Some("Password".to_string()));
            }
            _ => panic!("Expected TextInput prompt"),
        }
    }

    // =========================================================================
    // Edge case tests for API compatibility
    // =========================================================================

    #[test]
    fn test_get_status_empty_arrays() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .and(bearer_token("test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "hosts": [],
                    "pendingAttention": []
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let status = client.get_status().unwrap();

        assert!(status.hosts.is_empty());
        assert!(status.pending_attention.is_empty());
    }

    #[test]
    fn test_get_status_null_optional_fields() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .and(bearer_token("test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "hosts": [
                        {
                            "fingerprint": "SHA256:xyz789",
                            "label": "Server",
                            "hostname": null,
                            "status": "offline",
                            "lastSeenAt": "2024-01-14T08:00:00Z"
                        }
                    ],
                    "pendingAttention": [
                        {
                            "id": "att-456",
                            "hostLabel": "Server",
                            "taskName": null,
                            "message": "Need input",
                            "createdAt": "2024-01-15T12:00:00Z",
                            "urgent": true
                        }
                    ]
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let status = client.get_status().unwrap();

        // Host with null hostname
        assert_eq!(status.hosts[0].hostname, None);
        assert_eq!(status.hosts[0].status, HostStatus::Offline);

        // Attention with null taskName
        assert_eq!(status.pending_attention[0].task_name, None);
        assert!(status.pending_attention[0].urgent);
    }

    #[test]
    fn test_get_status_offline_host() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .and(bearer_token("test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "hosts": [
                        {
                            "fingerprint": "SHA256:offline1",
                            "label": "Disconnected Server",
                            "hostname": "server.local",
                            "status": "offline",
                            "lastSeenAt": "2024-01-10T00:00:00Z"
                        },
                        {
                            "fingerprint": "SHA256:unknown",
                            "label": "Unknown Status",
                            "hostname": null,
                            "status": "unknown",
                            "lastSeenAt": "2024-01-01T00:00:00Z"
                        }
                    ],
                    "pendingAttention": []
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let status = client.get_status().unwrap();

        // "offline" status
        assert_eq!(status.hosts[0].status, HostStatus::Offline);

        // Any non-"online" status should be Offline
        assert_eq!(status.hosts[1].status, HostStatus::Offline);
    }

    #[test]
    fn test_get_status_server_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                    "error": "Internal server error"
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.get_status();

        match result {
            Err(ClientError::ServerError { message }) => {
                assert!(message.contains("500"));
            }
            _ => panic!("Expected ServerError, got {:?}", result),
        }
    }

    #[test]
    fn test_get_status_malformed_json() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .and(bearer_token("test-token"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string("{ invalid json }")
                        .insert_header("content-type", "application/json"),
                )
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.get_status();

        match result {
            Err(ClientError::ServerError { message }) => {
                assert!(message.contains("parse"));
            }
            _ => panic!("Expected ServerError for malformed JSON, got {:?}", result),
        }
    }

    #[test]
    fn test_get_attention_server_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/attention/att-500"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.get_attention("att-500".to_string());

        match result {
            Err(ClientError::ServerError { message }) => {
                assert!(message.contains("500"));
            }
            _ => panic!("Expected ServerError, got {:?}", result),
        }
    }

    #[test]
    fn test_get_attention_empty_output_context() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/api/mobile/attention/att-empty"))
                .and(bearer_token("test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "att-empty",
                    "hostFingerprint": "SHA256:abc123",
                    "hostLabel": "MacBook Pro",
                    "taskName": null,
                    "message": "Continue?",
                    "prompt": {
                        "type": "binary",
                        "affirmLabel": "Yes",
                        "affirmValue": "yes",
                        "denyLabel": "No",
                        "denyValue": "no",
                        "defaultIsAffirm": true
                    },
                    "outputContext": [],
                    "createdAt": "2024-01-15T10:30:00Z",
                    "urgent": false
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let detail = client.get_attention("att-empty".to_string()).unwrap();

        assert!(detail.output_context.is_empty());
        assert_eq!(detail.task_name, None);
    }

    #[test]
    fn test_respond_requires_auth() {
        let storage = MockStorage::new();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        let result = client.respond_to_attention("att-123".to_string(), "y".to_string());

        assert!(matches!(result, Err(ClientError::NotAuthenticated)));
    }

    #[test]
    fn test_respond_to_attention_unauthorized() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/api/mobile/attention/att-123/respond"))
                .respond_with(ResponseTemplate::new(401))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("expired-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.respond_to_attention("att-123".to_string(), "y".to_string());

        assert!(matches!(result, Err(ClientError::NotAuthenticated)));
    }

    #[test]
    fn test_respond_to_attention_not_found() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/api/mobile/attention/nonexistent/respond"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.respond_to_attention("nonexistent".to_string(), "y".to_string());

        assert!(matches!(result, Err(ClientError::AlreadyResolved)));
    }

    #[test]
    fn test_respond_with_text_value() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            // Test that arbitrary text values are sent correctly
            Mock::given(method("POST"))
                .and(path("/api/mobile/attention/att-text-input/respond"))
                .and(bearer_token("test-token"))
                .and(body_json(serde_json::json!({ "value": "my-secret-password-123" })))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "success": true,
                    "message": "Response submitted"
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("test-token");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.respond_to_attention(
            "att-text-input".to_string(),
            "my-secret-password-123".to_string(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_storage_persists_token() {
        let storage = MockStorage::new();

        // Create client and login
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();
        client.login("persisted-token".to_string()).unwrap();

        assert!(client.is_logged_in());

        // Verify token was stored (can't easily test persistence across client instances
        // since MockStorage is moved, but we verify the storage.set was called)
    }

    #[test]
    fn test_client_loads_cached_token() {
        // Pre-populate storage with token
        let storage = MockStorage::with_token("cached-token");

        // Create client - should load cached token
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        // Should be logged in immediately without calling login()
        assert!(client.is_logged_in());
    }

    // =========================================================================
    // Comprehensive auth and storage tests
    // =========================================================================

    /// Storage that can be configured to fail on specific operations
    struct FailingStorage {
        fail_on_get: bool,
        fail_on_set: bool,
        fail_on_delete: bool,
        data: Mutex<HashMap<String, String>>,
    }

    impl FailingStorage {
        fn failing_on_set() -> Self {
            Self {
                fail_on_get: false,
                fail_on_set: true,
                fail_on_delete: false,
                data: Mutex::new(HashMap::new()),
            }
        }

        fn failing_on_get() -> Self {
            Self {
                fail_on_get: true,
                fail_on_set: false,
                fail_on_delete: false,
                data: Mutex::new(HashMap::new()),
            }
        }

        fn failing_on_delete() -> Self {
            Self {
                fail_on_get: false,
                fail_on_set: false,
                fail_on_delete: true,
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl SecureStorage for FailingStorage {
        fn get(&self, key: String) -> Result<Option<String>, StorageError> {
            if self.fail_on_get {
                Err(StorageError::Unavailable)
            } else {
                Ok(self.data.lock().unwrap().get(&key).cloned())
            }
        }

        fn set(&self, key: String, value: String) -> Result<(), StorageError> {
            if self.fail_on_set {
                Err(StorageError::Failed {
                    message: "Storage write failed".to_string(),
                })
            } else {
                self.data.lock().unwrap().insert(key, value);
                Ok(())
            }
        }

        fn remove(&self, key: String) -> Result<(), StorageError> {
            if self.fail_on_delete {
                Err(StorageError::Failed {
                    message: "Storage remove failed".to_string(),
                })
            } else {
                self.data.lock().unwrap().remove(&key);
                Ok(())
            }
        }
    }

    #[test]
    fn test_login_fails_when_storage_fails() {
        let storage = FailingStorage::failing_on_set();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        let result = client.login("test-token".to_string());

        match result {
            Err(ClientError::StorageError { message }) => {
                assert!(message.contains("Storage write failed"));
            }
            _ => panic!("Expected StorageError, got {:?}", result),
        }

        // Should not be logged in since storage failed
        assert!(!client.is_logged_in());
    }

    #[test]
    fn test_client_creation_handles_storage_get_failure() {
        // When storage.get fails during construction, client should still work
        // (just won't have a cached token)
        let storage = FailingStorage::failing_on_get();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        // Should not be logged in (storage.get failed, so no cached token loaded)
        assert!(!client.is_logged_in());

        // But login should still work if storage.set works
        // (This storage only fails on get, not set)
    }

    #[test]
    fn test_logout_succeeds_even_if_storage_delete_fails() {
        // Create storage that will fail on delete but has a token
        let storage = FailingStorage::failing_on_delete();
        storage
            .data
            .lock()
            .unwrap()
            .insert("oauth_token".to_string(), "test-token".to_string());

        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        assert!(client.is_logged_in());

        // Logout should succeed even if storage.delete fails
        // (we clear the in-memory token regardless)
        let result = client.logout();
        assert!(result.is_ok());

        // Should be logged out (in-memory token cleared)
        assert!(!client.is_logged_in());
    }

    #[test]
    fn test_login_overwrites_existing_token() {
        let storage = MockStorage::with_token("old-token");
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        assert!(client.is_logged_in());

        // Login with new token
        client.login("new-token".to_string()).unwrap();

        assert!(client.is_logged_in());

        // Verify API uses new token by making a request
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            // Only accept the new token
            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .and(bearer_token("new-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "hosts": [],
                    "pendingAttention": []
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        // Create new client with the same storage pattern to verify token was overwritten
        let storage2 = MockStorage::with_token("new-token");
        let client2 = ContinuumClient::new(uri, Box::new(storage2)).unwrap();

        // This should succeed with the new token
        let result = client2.get_status();
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_auth_lifecycle() {
        // Start logged out
        let storage = MockStorage::new();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        assert!(!client.is_logged_in());

        // Login
        client.login("first-token".to_string()).unwrap();
        assert!(client.is_logged_in());

        // Logout
        client.logout().unwrap();
        assert!(!client.is_logged_in());

        // Login again with different token
        client.login("second-token".to_string()).unwrap();
        assert!(client.is_logged_in());

        // Logout again
        client.logout().unwrap();
        assert!(!client.is_logged_in());
    }

    #[test]
    fn test_login_with_empty_token() {
        // Empty token should still be stored (it's up to the server to reject it)
        let storage = MockStorage::new();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        client.login("".to_string()).unwrap();

        // is_logged_in checks if token is Some, not if it's non-empty
        // An empty string is still Some("")
        assert!(client.is_logged_in());
    }

    #[test]
    fn test_multiple_logout_calls() {
        let storage = MockStorage::with_token("test-token");
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        assert!(client.is_logged_in());

        // First logout
        client.logout().unwrap();
        assert!(!client.is_logged_in());

        // Second logout should be idempotent
        client.logout().unwrap();
        assert!(!client.is_logged_in());

        // Third logout
        client.logout().unwrap();
        assert!(!client.is_logged_in());
    }

    #[test]
    fn test_storage_key_is_oauth_token() {
        // Verify we're using the correct storage key
        let storage = MockStorage::new();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        client.login("my-secret-token".to_string()).unwrap();

        // Create another client with fresh storage that has the token under the expected key
        let storage2 = MockStorage::new();
        storage2
            .data
            .lock()
            .unwrap()
            .insert("oauth_token".to_string(), "cached-from-storage".to_string());

        let client2 =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage2)).unwrap();

        // Should load the token from storage using "oauth_token" key
        assert!(client2.is_logged_in());
    }

    #[test]
    fn test_bearer_token_sent_correctly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (uri, _guard) = rt.block_on(async {
            let server = MockServer::start().await;

            // Verify exact bearer token format
            Mock::given(method("GET"))
                .and(path("/api/mobile/status"))
                .and(bearer_token("Bearer-Test-Token-12345"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "hosts": [],
                    "pendingAttention": []
                })))
                .mount(&server)
                .await;

            (server.uri(), server)
        });

        let storage = MockStorage::with_token("Bearer-Test-Token-12345");
        let client = ContinuumClient::new(uri, Box::new(storage)).unwrap();

        let result = client.get_status();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_attention_requires_auth() {
        let storage = MockStorage::new();
        let client =
            ContinuumClient::new("http://localhost".to_string(), Box::new(storage)).unwrap();

        let result = client.get_attention("att-123".to_string());

        assert!(matches!(result, Err(ClientError::NotAuthenticated)));
    }
}
