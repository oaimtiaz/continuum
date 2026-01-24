//! Continuum Daemon - Service that runs on device
//!
//! Exposes gRPC API for CLI and other interfaces, spawns shim processes
//! to execute tasks, and maintains in-memory task state.

use std::pin::Pin;
use std::sync::Arc;

use async_stream::stream;
use clap::{Parser, Subcommand};
use continuum_auth::enrollment::SignedEnrollmentToken;
use continuum_auth::identity::PrivateKey;
use continuum_core::task::TaskId;
use continuum_core::task::TaskStatus as CoreTaskStatus;
use continuum_proto::{
    continuum_server::{Continuum, ContinuumServer},
    enrollment::v1::enrollment_service_server::EnrollmentServiceServer,
    CancelTaskRequest, CancelTaskResponse, GetTaskRequest, GetTaskResponse, ListTasksRequest,
    ListTasksResponse, OutputChunk, RunTaskRequest, RunTaskResponse, SendInputRequest,
    SendInputResponse, StreamOutputRequest, TaskStatus as ProtoTaskStatus, FILE_DESCRIPTOR_SET,
};

use convert::{output_chunk_to_proto, task_to_view};
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use tokio_stream::Stream;
use tonic::{transport::Server, Request, Response, Status};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

// ============================================================================
// CLI Definition
// ============================================================================

/// Continuum Daemon - Task execution service
#[derive(Parser)]
#[command(name = "continuum-daemon", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Skip relay Auth0 authentication (dev mode - requires relay to also be in dev mode)
    #[arg(long, hide = true)]
    relay_no_auth: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon server (default if no command given)
    Serve,

    /// Token management
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Generate an enrollment token
    Generate {
        /// Label for this enrollment (e.g., "alice-laptop")
        #[arg(long)]
        label: Option<String>,

        /// Token validity duration (e.g., "5m", "1h")
        #[arg(long, default_value = "5m")]
        validity: String,
    },
}

mod auth;
mod convert;
mod db;
mod ipc;
mod relay;
mod services;
mod store;
mod supervisor;
mod tls;

use auth::{hash_token, AuthStore, LocalTrustManager};
use db::DbService;
use services::{EnrollmentRateLimiter, EnrollmentServiceImpl, RateLimitInterceptor};
use store::TaskStore;
use supervisor::TaskSupervisor;
use tls::{build_self_signed, CertParams};

/// M4 FIX: TLS handshake timeout to prevent slow-loris style attacks.
/// Connections that don't complete TLS handshake within this time are dropped.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Parse a task ID string into a TaskId.
fn parse_task_id(task_id_str: &str) -> Result<TaskId, Status> {
    let uuid = Uuid::parse_str(task_id_str)
        .map_err(|_| Status::invalid_argument("Invalid task ID format"))?;
    Ok(TaskId::new(uuid))
}

pub struct ContinuumService {
    store: Arc<TaskStore>,
    supervisor: TaskSupervisor,
}

impl std::fmt::Debug for ContinuumService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContinuumService")
            .field("supervisor", &self.supervisor)
            .finish()
    }
}

type StreamOutputResult = Pin<Box<dyn Stream<Item = Result<OutputChunk, Status>> + Send>>;

#[tonic::async_trait]
impl Continuum for ContinuumService {
    type StreamOutputStream = StreamOutputResult;

    async fn run_task(
        &self,
        request: Request<RunTaskRequest>,
    ) -> Result<Response<RunTaskResponse>, Status> {
        let req = request.into_inner();

        let name = if req.name.is_empty() {
            req.cmd
                .first()
                .cloned()
                .unwrap_or_else(|| "task".to_string())
        } else {
            req.name
        };

        let cwd = req.cwd.unwrap_or_else(|| {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "/".to_string())
        });

        if req.cmd.is_empty() {
            return Err(Status::invalid_argument("cmd is required"));
        }

        tracing::info!(name = %name, cmd = ?req.cmd, cwd = %cwd, "RunTask request");

        let task_id = self
            .supervisor
            .spawn_task(name, req.cmd, cwd, req.env)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Wait a moment for the task to start and get initial state
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let task = self
            .store
            .get(&task_id)
            .await
            .ok_or_else(|| Status::internal("Task not found after creation"))?;

        let task_view = task_to_view(&task);
        Ok(Response::new(RunTaskResponse {
            task: Some(task_view),
        }))
    }

    async fn list_tasks(
        &self,
        request: Request<ListTasksRequest>,
    ) -> Result<Response<ListTasksResponse>, Status> {
        let req = request.into_inner();
        tracing::debug!(status_filter = ?req.status_filter, limit = ?req.limit, "ListTasks request");

        let mut tasks = self.store.list().await;

        // Apply status filter if provided
        if let Some(status_filter) = req.status_filter {
            let filter_status = match ProtoTaskStatus::try_from(status_filter) {
                Ok(ProtoTaskStatus::Queued) => Some(CoreTaskStatus::Queued),
                Ok(ProtoTaskStatus::Running) => Some(CoreTaskStatus::Running),
                Ok(ProtoTaskStatus::Completed) => Some(CoreTaskStatus::Completed),
                Ok(ProtoTaskStatus::Failed) => Some(CoreTaskStatus::Failed),
                Ok(ProtoTaskStatus::Canceled) => Some(CoreTaskStatus::Canceled),
                _ => None,
            };
            if let Some(status) = filter_status {
                tasks.retain(|t| t.status == status);
            }
        }

        // Sort by created_at descending (most recent first)
        tasks.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply limit if provided
        if let Some(limit) = req.limit {
            tasks.truncate(limit as usize);
        }

        let task_views = tasks.iter().map(task_to_view).collect();
        Ok(Response::new(ListTasksResponse { tasks: task_views }))
    }

    async fn get_task(
        &self,
        request: Request<GetTaskRequest>,
    ) -> Result<Response<GetTaskResponse>, Status> {
        let req = request.into_inner();
        tracing::debug!(task_id = %req.task_id, "GetTask request");

        let task_id = parse_task_id(&req.task_id)?;

        let task = self
            .store
            .get(&task_id)
            .await
            .ok_or_else(|| Status::not_found("Task not found"))?;

        let task_view = task_to_view(&task);
        Ok(Response::new(GetTaskResponse {
            task: Some(task_view),
        }))
    }

    async fn send_input(
        &self,
        request: Request<SendInputRequest>,
    ) -> Result<Response<SendInputResponse>, Status> {
        let req = request.into_inner();
        tracing::debug!(task_id = %req.task_id, bytes = req.data.len(), "SendInput request");

        let task_id = parse_task_id(&req.task_id)?;

        self.supervisor
            .send_input(&task_id, req.data)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SendInputResponse {}))
    }

    async fn stream_output(
        &self,
        request: Request<StreamOutputRequest>,
    ) -> Result<Response<Self::StreamOutputStream>, Status> {
        let req = request.into_inner();
        tracing::debug!(task_id = %req.task_id, from_offset = ?req.from_offset, "StreamOutput request");

        let task_id = parse_task_id(&req.task_id)?;

        // Verify task exists
        if self.store.get(&task_id).await.is_none() {
            return Err(Status::not_found("Task not found"));
        }

        let from_offset = req.from_offset.unwrap_or(0) as usize;

        // Subscribe FIRST to avoid race condition where output arrives
        // between fetching historical and subscribing
        let mut receiver = self
            .store
            .subscribe_output(&task_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Then get historical output - any output that arrives during this
        // call will either be in historical OR caught by the subscription
        let historical = self.store.get_output(&task_id, from_offset).await;

        let store = self.store.clone();
        let task_id_clone = task_id.clone();

        let output_stream = stream! {
            // First, yield historical chunks
            for chunk in historical {
                yield Ok(output_chunk_to_proto(&chunk));
            }

            // Then stream live output until task completes, error, or shutdown
            loop {
                // Check if daemon is shutting down
                if store.is_shutting_down() {
                    tracing::debug!(task = %task_id_clone.0, "Daemon shutting down, ending stream");
                    break;
                }

                // Check if task has completed
                if let Some(task) = store.get(&task_id_clone).await {
                    if task.status.is_terminal() {
                        tracing::debug!(task = %task_id_clone.0, status = ?task.status, "Task completed, ending stream");
                        break;
                    }
                }

                match tokio::time::timeout(tokio::time::Duration::from_millis(500), receiver.recv()).await {
                    Ok(Ok(chunk)) => {
                        yield Ok(output_chunk_to_proto(&chunk));
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(task = %task_id_clone.0, skipped = n, "Stream lagged");
                        // Continue streaming
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                        tracing::debug!(task = %task_id_clone.0, "Broadcast channel closed");
                        break;
                    }
                    Err(_) => {
                        // Timeout - loop back to check task status and shutdown flag
                        continue;
                    }
                };

            }
        };

        Ok(Response::new(Box::pin(output_stream)))
    }

    async fn cancel_task(
        &self,
        request: Request<CancelTaskRequest>,
    ) -> Result<Response<CancelTaskResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(task_id = %req.task_id, force = req.force, "CancelTask request");

        let task_id = parse_task_id(&req.task_id)?;

        // Verify task exists and is running
        let task = self
            .store
            .get(&task_id)
            .await
            .ok_or_else(|| Status::not_found("Task not found"))?;

        if task.status.is_terminal() {
            return Err(Status::failed_precondition("Task already terminated"));
        }

        // SIGTERM = 15, SIGKILL = 9
        let signum = if req.force { 9 } else { 15 };

        self.supervisor
            .send_signal(&task_id, signum)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CancelTaskResponse {}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Token { action }) => cmd_token(action).await,
        Some(Commands::Serve) | None => cmd_serve(cli.relay_no_auth).await,
    }
}

/// Handle token subcommands.
async fn cmd_token(action: TokenAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        TokenAction::Generate { label, validity } => {
            let validity_secs = parse_duration(&validity)?;

            let data_dir = dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("continuum");
            std::fs::create_dir_all(&data_dir)?;

            let key_path = data_dir.join("server_key.der");
            let server_key = if key_path.exists() {
                let key_bytes = std::fs::read(&key_path)?;
                PrivateKey::from_pkcs8_der(&key_bytes)?
            } else {
                let key = PrivateKey::generate();
                std::fs::write(&key_path, key.to_pkcs8_der())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
                }
                key
            };

            let token = SignedEnrollmentToken::generate(&server_key, validity_secs as i64);
            let token_base64 = token.to_base64();

            // Token hash stored so CompleteEnrollment can validate it
            let auth_db_path = data_dir.join("auth.db");
            let auth_pool =
                sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=rwc", auth_db_path.display()))
                    .await?;
            let (auth_store, _tls_reload_rx) = AuthStore::new(auth_pool).await?;

            let token_hash = hash_token(&token_base64);
            auth_store
                .create_enrollment_token(&token_hash, label.as_deref(), token.expires_at())
                .await?;

            let expires_at = chrono::DateTime::from_timestamp(token.expires_at(), 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "unknown".to_string());

            println!("Enrollment Token Generated");
            println!("==========================");
            println!();
            println!("Token:   {}", token);
            println!();
            println!("Expires: {}", expires_at);
            if let Some(ref l) = label {
                println!("Label:   {}", l);
            }
            println!();
            println!("Share this token with the client out-of-band.");
            println!("The token is single-use and expires in {}.", validity);

            Ok(())
        }
    }
}

/// Parse a duration string like "5m" or "1h" into seconds.
fn parse_duration(s: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(300); // Default 5 minutes
    }

    let (num_str, unit) = if s.ends_with('s') {
        (&s[..s.len() - 1], 1)
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 60)
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], 3600)
    } else {
        // Assume seconds if no unit
        (s, 1)
    };

    let num: u32 = num_str
        .parse()
        .map_err(|_| format!("Invalid duration: {}", s))?;
    let secs = num.saturating_mul(unit);

    // Clamp to valid range (1 minute to 1 hour)
    Ok(secs.clamp(60, 3600))
}

/// Start the daemon server.
async fn cmd_serve(relay_no_auth: bool) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("continuum");

    std::fs::create_dir_all(&data_dir)?;

    let db_path = data_dir.join("daemon.db");
    tracing::info!(path = %db_path.display(), "Opening database");

    let db = DbService::open(&db_path).await?;

    let orphaned = db.mark_orphaned_tasks_failed().await?;
    if orphaned > 0 {
        tracing::warn!(count = orphaned, "Marked orphaned running tasks as failed");
    }

    let auth_db_path = data_dir.join("auth.db");
    let auth_pool =
        sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=rwc", auth_db_path.display())).await?;
    let (auth_store, tls_reload_rx) = AuthStore::new(auth_pool).await?;
    let auth_store = Arc::new(auth_store);
    tracing::info!("Auth store initialized with TLS reload channel");

    let key_path = data_dir.join("server_key.der");
    let server_key = if key_path.exists() {
        let key_bytes = std::fs::read(&key_path)?;
        PrivateKey::from_pkcs8_der(&key_bytes)?
    } else {
        let key = PrivateKey::generate();
        std::fs::write(&key_path, key.to_pkcs8_der())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        key
    };
    let server_key = Arc::new(server_key);

    let cert_params = CertParams::default();
    let server_identity = Arc::new(build_self_signed(&server_key, &cert_params)?);
    tracing::info!(
        fingerprint = %continuum_auth::identity::Fingerprint::from_public_key(&server_key.public_key()),
        "Server identity initialized"
    );

    let server_fingerprint =
        continuum_auth::identity::Fingerprint::from_public_key(&server_key.public_key());
    let local_trust_manager: Option<Arc<LocalTrustManager>> = match LocalTrustManager::new() {
        Ok(manager) => {
            // Write server fingerprint for local enrollment
            if let Err(e) = manager.write_server_fingerprint(&server_fingerprint) {
                tracing::warn!(error = %e, "Failed to write server fingerprint");
            }
            tracing::info!(path = %manager.token_path().display(), "Local trust manager initialized");
            Some(Arc::new(manager))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Local trust not available (same-machine auto-approval disabled)");
            None
        }
    };

    // Extract proof for enrollment service (which only needs the expected proof)
    let local_trust_proof = local_trust_manager.as_ref().map(|m| m.expected_proof());

    let store = Arc::new(TaskStore::new(db));
    store.load_from_db().await?;

    let task_count = store.list().await.len();
    tracing::info!(tasks = task_count, "Loaded tasks from database");

    let relay_task_handle = if let Some(relay_config) = relay::RelayConfig::from_env() {
        let daemon_id = server_fingerprint.to_string();
        let store_for_relay = store.clone();
        let handle = tokio::spawn(run_relay_loop(
            relay_config,
            daemon_id,
            relay_no_auth,
            store_for_relay,
        ));
        Some(handle)
    } else {
        tracing::info!("Relay not configured (CONTINUUM_RELAY_* env vars not set)");
        None
    };

    // Dual-port architecture:
    // - Port 50051: Enrollment (server-auth only, no client cert required)
    // - Port 50052: Main API (mTLS, requires valid client certificate)
    let enrollment_addr: std::net::SocketAddr = "127.0.0.1:50051".parse()?;
    let main_addr: std::net::SocketAddr = "127.0.0.1:50052".parse()?;

    let supervisor = TaskSupervisor::new(store.clone());
    let service = ContinuumService {
        store: store.clone(),
        supervisor,
    };

    let rate_limiter = EnrollmentRateLimiter::default();
    let rate_limit_interceptor = RateLimitInterceptor::new(rate_limiter);
    let enrollment_service = EnrollmentServiceImpl::new(
        auth_store.clone(),
        server_key,
        server_identity.clone(),
        local_trust_proof,
    );

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?;
    let reflection_main = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let auth_store_for_interceptor = auth_store.clone();

    // Create auth interceptor that checks for:
    // 1. Valid same-machine proof in metadata (local trust)
    // 2. Valid mTLS client fingerprint (remote enrolled clients)
    let trust_manager_for_interceptor = local_trust_manager.clone();
    let auth_interceptor =
        move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
            // Check for valid same-machine proof in metadata (highest priority)
            if let Some(ref manager) = trust_manager_for_interceptor {
                if let Some(proof_header) = req.metadata().get_bin("x-local-trust-proof-bin") {
                    if let Ok(proof_bytes) = proof_header.to_bytes() {
                        if manager.verify_proof(proof_bytes.as_ref()) {
                            return Ok(req); // Valid local proof
                        }
                    }
                }
            }

            // Check for mTLS client certificate fingerprint
            // The TlsConnectInfo is available via request extensions when using mTLS
            if let Some(connect_info) = req.extensions().get::<tls_io::TlsConnectInfo>() {
                if let Some(ref fingerprint) = connect_info.client_fingerprint {
                    // Use cached authorization check for performance
                    if auth_store_for_interceptor.is_authorized_cached(fingerprint) {
                        return Ok(req); // Valid mTLS client
                    }
                }
            }

            Err(tonic::Status::unauthenticated(
                "Valid authentication required",
            ))
        };

    // Wrap ContinuumServer with auth interceptor
    let continuum_with_auth = ContinuumServer::with_interceptor(service, auth_interceptor);

    // Enrollment server (port 50051) - only enrollment service, no auth required
    // M3 FIX: Rate limiting applied to prevent DoS and brute-force attacks
    let enrollment_server = Server::builder().add_service(reflection).add_service(
        EnrollmentServiceServer::with_interceptor(
            enrollment_service.clone(),
            rate_limit_interceptor.clone(),
        ),
    );

    // Main API server (port 50052) - requires mTLS or local proof
    // Also includes enrollment service for authenticated operations (e.g., status check)
    let main_server = Server::builder()
        .add_service(reflection_main)
        .add_service(continuum_with_auth)
        .add_service(EnrollmentServiceServer::with_interceptor(
            enrollment_service,
            rate_limit_interceptor,
        ));

    tracing::info!(
        enrollment = %enrollment_addr,
        main = %main_addr,
        "Continuum daemon starting (dual-port TLS)"
    );

    // Run dual-port servers with graceful shutdown
    let shutdown_result = run_dual_port_servers(
        enrollment_server,
        main_server,
        enrollment_addr,
        main_addr,
        store,
        auth_store,
        server_identity,
        tls_reload_rx,
    )
    .await;

    if let Some(handle) = relay_task_handle {
        handle.abort();
    }

    match shutdown_result {
        Ok(()) => {
            tracing::info!("Daemon shutdown complete");
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = %e, "Daemon shutdown with error");
            Err(e)
        }
    }
}

/// Run the relay connection loop.
///
/// This function maintains a connection to the relay server and handles
/// incoming tunnel requests by bridging them to local services.
/// It also provides the relay handle to the store for attention forwarding.
async fn run_relay_loop(
    config: relay::RelayConfig,
    daemon_id: String,
    no_auth: bool,
    store: Arc<TaskStore>,
) {
    loop {
        tracing::info!(daemon_id = %daemon_id, endpoint = %config.endpoint, "Connecting to relay...");

        match relay::RelayClient::new(config.clone(), daemon_id.clone(), no_auth).connect().await {
            Ok(mut connection) => {
                tracing::info!(daemon_id = %daemon_id, "Registered with relay");

                // Make relay handle available to IPC handlers for attention forwarding
                store.set_relay_handle(connection.handle()).await;

                loop {
                    match connection.next_event().await {
                        Ok(relay::RelayEvent::SessionRequest(request)) => {
                            tracing::info!(
                                session_id = %request.session_id,
                                target = ?request.target,
                                "Incoming relay session"
                            );

                            // Accept session synchronously (quick), spawn bridging in background
                            match accept_and_bridge_session(&mut connection, request).await {
                                Ok(Some((session_id, bridging_task))) => {
                                    // Spawn the bridging work in background so we can
                                    // continue processing next_event() (including pings)
                                    tokio::spawn(async move {
                                        if let Err(e) = bridging_task.await {
                                            tracing::warn!(
                                                session_id = %session_id,
                                                error = %e,
                                                "Session bridging failed"
                                            );
                                        }
                                    });
                                }
                                Ok(None) => {
                                    // Session was rejected (e.g., local service unavailable)
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to accept relay session");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Relay connection error");
                            break; // Reconnect
                        }
                    }
                }

                // Connection lost, clear relay handle
                store.clear_relay_handle().await;
            }
            Err(relay::RelayError::Rpc(status)) if status.code() == tonic::Code::PermissionDenied => {
                tracing::error!(
                    "Fingerprint rejected by relay. Certificate may have changed. \
                     Check daemon logs for fingerprint and verify with relay admin."
                );
                return; // Don't retry - this is a configuration error
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to connect to relay");
            }
        }

        // Backoff before reconnect
        tracing::info!("Reconnecting to relay in 5 seconds...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Accept a relay session and prepare the bridging work.
///
/// Returns `Ok(Some((session_id, future)))` if the session was accepted successfully.
/// The returned future performs the bidirectional copy and should be spawned.
/// Returns `Ok(None)` if the session was rejected (e.g., local service unavailable).
async fn accept_and_bridge_session(
    connection: &mut relay::RelayConnection,
    request: relay::SessionRequest,
) -> Result<Option<(String, impl std::future::Future<Output = Result<(), std::io::Error>>)>, relay::RelayError>
{
    let local_addr = match request.target {
        relay::TunnelTarget::Enrollment => "127.0.0.1:50051",
        relay::TunnelTarget::Main => "127.0.0.1:50052",
    };

    let local_stream = match tokio::net::TcpStream::connect(local_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(
                session_id = %request.session_id,
                local_addr = %local_addr,
                error = %e,
                "Failed to connect to local service"
            );
            connection.reject_session(&request.session_id, "local service unavailable").await?;
            return Ok(None);
        }
    };

    // Empty client_token - daemon doesn't validate this
    let tunnel = connection.accept_session(&request, "").await?;
    let session_id = request.session_id.clone();

    let bridging_future = async move {
        let (mut tunnel_read, mut tunnel_write) = tokio::io::split(tunnel);
        let (mut local_read, mut local_write) = local_stream.into_split();

        let session_id_c2l = session_id.clone();
        let session_id_l2c = session_id.clone();

        let client_to_local = async move {
            let result = tokio::io::copy(&mut tunnel_read, &mut local_write).await;
            tracing::debug!(session_id = %session_id_c2l, bytes = ?result, "client->local copy done");
            result
        };

        let local_to_client = async move {
            let result = tokio::io::copy(&mut local_read, &mut tunnel_write).await;
            tracing::debug!(session_id = %session_id_l2c, bytes = ?result, "local->client copy done");
            result
        };

        tokio::select! {
            r = client_to_local => {
                if let Err(e) = &r {
                    tracing::debug!(session_id = %session_id, error = %e, "client->local error");
                }
                r.map(|_| ())
            }
            r = local_to_client => {
                if let Err(e) = &r {
                    tracing::debug!(session_id = %session_id, error = %e, "local->client error");
                }
                r.map(|_| ())
            }
        }
    };

    Ok(Some((request.session_id, bridging_future)))
}

// Wrapper type for TLS streams that implements tonic's Connected trait
mod tls_io {
    use continuum_auth::cert::extract_public_key_from_cert;
    use continuum_auth::identity::Fingerprint;
    use sha2::{Digest, Sha256};
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::TcpStream;
    use tokio_rustls::server::TlsStream;
    use tonic::transport::server::Connected;

    pub use crate::tls::TlsConnectInfo;

    /// Wrapper around TlsStream that implements tonic's Connected trait.
    pub struct TlsConnection {
        inner: TlsStream<TcpStream>,
        remote_addr: Option<SocketAddr>,
        client_fingerprint: Option<Fingerprint>,
    }

    impl TlsConnection {
        pub fn new(tls_stream: TlsStream<TcpStream>, remote_addr: Option<SocketAddr>) -> Self {
            // Extract client fingerprint from the first peer certificate (if any)
            let (_, session) = tls_stream.get_ref();
            let client_fingerprint = session.peer_certificates().and_then(|certs| {
                certs.first().and_then(|cert| {
                    extract_public_key_from_cert(cert.as_ref())
                        .ok()
                        .map(|pk_bytes| {
                            let hash: [u8; 32] = Sha256::digest(&pk_bytes).into();
                            Fingerprint::from_hash_bytes(hash)
                        })
                })
            });

            Self {
                inner: tls_stream,
                remote_addr,
                client_fingerprint,
            }
        }
    }

    impl Connected for TlsConnection {
        type ConnectInfo = TlsConnectInfo;

        fn connect_info(&self) -> Self::ConnectInfo {
            TlsConnectInfo::new(self.remote_addr, self.client_fingerprint.clone())
        }
    }

    impl AsyncRead for TlsConnection {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TlsConnection {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
}

/// Run dual-port servers with graceful shutdown.
///
/// - `enrollment_server` runs on port 50051 with server-auth only (for enrollment)
/// - `main_server` runs on port 50052 with mTLS (for authenticated API access)
///
/// The `tls_reload_rx` channel is used to signal when the authorized client list
/// changes (enrollment/revocation), triggering a TLS configuration reload.
async fn run_dual_port_servers(
    enrollment_server: tonic::transport::server::Router,
    main_server: tonic::transport::server::Router,
    enrollment_addr: std::net::SocketAddr,
    main_addr: std::net::SocketAddr,
    store: Arc<TaskStore>,
    auth_store: Arc<AuthStore>,
    server_identity: Arc<tls::TlsIdentity>,
    mut tls_reload_rx: tokio::sync::watch::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build server-auth-only config for enrollment port
    let enrollment_tls_config = tls::TlsServerConfig::new_server_only(
        server_identity.cert_der.clone(),
        server_identity.key_der.clone(),
    )?;
    let enrollment_acceptor = TlsAcceptor::from(enrollment_tls_config.into_rustls_config());

    // Build mTLS config for main port (with authorized client certs)
    // Use ReloadableTlsAcceptor for dynamic updates on enrollment/revocation
    let authorized_certs = auth_store.get_authorized_certs().await?;
    let main_tls_config = tls::TlsServerConfig::new_mtls(
        server_identity.cert_der.clone(),
        server_identity.key_der.clone(),
        authorized_certs,
    )?;
    let initial_acceptor = TlsAcceptor::from(main_tls_config.into_rustls_config());
    let reloadable_acceptor = tls::ReloadableTlsAcceptor::new(initial_acceptor, server_identity);

    let enrollment_listener = TcpListener::bind(enrollment_addr).await?;
    let main_listener = TcpListener::bind(main_addr).await?;
    tracing::info!("Enrollment listener bound to {}", enrollment_addr);
    tracing::info!("Main API listener bound to {} (mTLS)", main_addr);

    // Broadcast channel for shutdown (multiple receivers)
    let store_for_signal = store.clone();
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut shutdown_rx_enrollment = shutdown_tx.subscribe();
    let mut shutdown_rx_main = shutdown_tx.subscribe();

    let shutdown_tx_clone = shutdown_tx.clone();
    let signal_task = tokio::spawn(async move {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received SIGINT (Ctrl+C), initiating shutdown");
            }
            _ = terminate => {
                tracing::info!("Received SIGTERM, initiating shutdown");
            }
        }

        // Signal shutdown immediately so streams can exit
        let notified = store_for_signal.broadcast_shutdown().await;
        tracing::info!(count = notified, "Notified shims of shutdown");
        let _ = shutdown_tx_clone.send(());
    });

    // Enrollment port: server-auth only
    let enrollment_acceptor_clone = enrollment_acceptor.clone();
    let enrollment_incoming = async_stream::stream! {
        loop {
            tokio::select! {
                result = enrollment_listener.accept() => {
                    match result {
                        Ok((tcp_stream, peer_addr)) => {
                            let acceptor = enrollment_acceptor_clone.clone();
                            // M4 FIX: Apply TLS handshake timeout
                            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream)).await {
                                Ok(Ok(tls_stream)) => {
                                    tracing::debug!(peer = %peer_addr, port = "enrollment", "TLS handshake successful");
                                    yield Ok::<_, std::io::Error>(tls_io::TlsConnection::new(tls_stream, Some(peer_addr)));
                                }
                                Ok(Err(e)) => {
                                    tracing::warn!(peer = %peer_addr, port = "enrollment", error = %e, "TLS handshake failed");
                                }
                                Err(_) => {
                                    tracing::warn!(peer = %peer_addr, port = "enrollment", timeout_secs = ?TLS_HANDSHAKE_TIMEOUT, "TLS handshake timed out");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(port = "enrollment", error = %e, "TCP accept failed");
                        }
                    }
                }
                _ = shutdown_rx_enrollment.recv() => {
                    tracing::info!("Shutdown signal received, stopping enrollment accept loop");
                    break;
                }
            }
        }
    };

    // Main port: mTLS with dynamic reload support
    let acceptor_for_loop = reloadable_acceptor.clone();
    let auth_store_for_reload = auth_store.clone();
    let main_incoming = async_stream::stream! {
        loop {
            tokio::select! {
                // Handle TLS reload signal (priority: process reloads before new connections)
                biased;

                result = tls_reload_rx.changed() => {
                    if result.is_ok() {
                        match acceptor_for_loop.reload(&auth_store_for_reload).await {
                            Ok(count) => {
                                tracing::info!(
                                    authorized_clients = count,
                                    "TLS config reloaded - new clients can now connect via mTLS"
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "TLS reload failed, keeping previous config"
                                );
                            }
                        }
                    }
                }

                // Accept new connections
                result = main_listener.accept() => {
                    match result {
                        Ok((tcp_stream, peer_addr)) => {
                            // Get current acceptor (lock-free read)
                            let acceptor = acceptor_for_loop.current();
                            // M4 FIX: Apply TLS handshake timeout
                            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream)).await {
                                Ok(Ok(tls_stream)) => {
                                    tracing::debug!(peer = %peer_addr, port = "main", "mTLS handshake successful");
                                    yield Ok::<_, std::io::Error>(tls_io::TlsConnection::new(tls_stream, Some(peer_addr)));
                                }
                                Ok(Err(e)) => {
                                    // mTLS failures are expected for unenrolled clients
                                    tracing::debug!(peer = %peer_addr, port = "main", error = %e, "mTLS handshake failed");
                                }
                                Err(_) => {
                                    tracing::warn!(peer = %peer_addr, port = "main", timeout_secs = ?TLS_HANDSHAKE_TIMEOUT, "mTLS handshake timed out");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(port = "main", error = %e, "TCP accept failed");
                        }
                    }
                }

                // Handle shutdown
                _ = shutdown_rx_main.recv() => {
                    tracing::info!("Shutdown signal received, stopping main accept loop");
                    break;
                }
            }
        }
    };

    let enrollment_handle = tokio::spawn(async move {
        enrollment_server
            .serve_with_incoming(enrollment_incoming)
            .await
    });

    let main_handle =
        tokio::spawn(async move { main_server.serve_with_incoming(main_incoming).await });

    tokio::select! {
        result = enrollment_handle => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Enrollment server task panicked");
            }
        }
        result = main_handle => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Main server task panicked");
            }
        }
    }

    let _ = signal_task.await;

    tracing::info!("Dual-port servers stopped, shutdown complete");
    Ok(())
}
