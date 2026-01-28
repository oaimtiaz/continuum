//! Relay tunnel client for mTLS connections to daemons.
//!
//! The mobile app connects to daemons through a relay server:
//!
//! ```text
//! Mobile App ──gRPC──► Relay ──tunnel──► Daemon
//!            └────────mTLS (end-to-end)────────┘
//! ```
//!
//! The relay sees only encrypted bytes - it cannot decrypt the mTLS traffic.

use bytes::Bytes;
use continuum_auth::identity::Fingerprint;
use continuum_core::relay::TunnelAdapter;
use continuum_relay_proto::{
    tunnel_message, ClientRelayServiceClient, CreateSessionRequest, Data, Open, TunnelMessage,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::enrollment::DaemonEnrollment;
use crate::errors::ClientError;
use crate::tls::{build_mtls_config, ClientIdentity, EnrollmentVerifier};

/// Establish a tunnel through the relay to a daemon.
///
/// This function:
/// 1. Connects to the relay
/// 2. Creates a session targeting the daemon
/// 3. Establishes a bidirectional tunnel
/// 4. Performs mTLS handshake over the tunnel
///
/// # Arguments
///
/// * `relay_endpoint` - Relay server URL (e.g., "https://relay.continuumruntime.com")
/// * `auth_token` - OAuth token for relay authentication
/// * `daemon_id` - Daemon fingerprint (e.g., "SHA256:abc123...")
/// * `client_identity` - Client mTLS identity (cert + key)
pub async fn connect_to_daemon(
    relay_endpoint: &str,
    auth_token: &str,
    daemon_id: &str,
    client_identity: &ClientIdentity,
) -> Result<tokio_rustls::client::TlsStream<TunnelAdapter>, ClientError> {
    // Parse daemon fingerprint
    let server_fingerprint =
        Fingerprint::parse(daemon_id).map_err(|_| ClientError::MtlsFailed {
            reason: "Invalid daemon fingerprint format".to_string(),
        })?;

    // Step 1: Connect to relay
    let channel = Channel::from_shared(relay_endpoint.to_string())
        .map_err(|e| ClientError::MtlsFailed {
            reason: format!("Invalid relay endpoint: {}", e),
        })?
        .connect()
        .await
        .map_err(|_| ClientError::NetworkUnavailable)?;

    // Step 2: Create authenticated relay client
    let interceptor = AuthInterceptor::new(auth_token.to_string());
    let mut client = ClientRelayServiceClient::with_interceptor(channel, interceptor);

    // Step 3: Establish tunnel
    let tunnel = create_tunnel_with_client(&mut client, daemon_id).await?;

    // Step 4: Perform mTLS handshake over tunnel
    let tls_stream = perform_mtls_handshake(tunnel, &server_fingerprint, client_identity).await?;

    Ok(tls_stream)
}

/// Create a tunnel to the daemon through the relay.
async fn create_tunnel_with_client<T>(
    client: &mut ClientRelayServiceClient<T>,
    daemon_id: &str,
) -> Result<TunnelAdapter, ClientError>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
    // Create session with relay
    let response = client
        .create_session(CreateSessionRequest {
            daemon_id: daemon_id.to_string(),
        })
        .await
        .map_err(|e| match e.code() {
            tonic::Code::NotFound => ClientError::HostOffline,
            tonic::Code::Unauthenticated => ClientError::NotAuthenticated,
            _ => ClientError::MtlsFailed {
                reason: format!("Failed to create session: {}", e),
            },
        })?
        .into_inner();

    let session_id = response.session_id;
    let client_token = response.client_token;

    // Set up bidirectional tunnel
    let (tunnel_tx, tunnel_rx) = mpsc::channel::<TunnelMessage>(1024);
    let tunnel_stream = ReceiverStream::new(tunnel_rx);

    // Send Open message to start tunnel
    let open = TunnelMessage {
        msg: Some(tunnel_message::Msg::Open(Open {
            session_id: session_id.clone(),
            token: client_token,
        })),
    };
    tunnel_tx
        .send(open)
        .await
        .map_err(|_| ClientError::MtlsFailed {
            reason: "Failed to open tunnel".to_string(),
        })?;

    // Start tunnel stream
    let response = client
        .tunnel(tunnel_stream)
        .await
        .map_err(|e| ClientError::MtlsFailed {
            reason: format!("Failed to start tunnel: {}", e),
        })?;
    let mut tunnel_inbound = response.into_inner();

    // Set up channels for TunnelAdapter
    let (data_tx, data_rx) = mpsc::channel::<Bytes>(1024);
    let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(1024);

    // Spawn task to forward inbound data
    tokio::spawn(async move {
        while let Ok(Some(msg)) = tunnel_inbound.message().await {
            match msg.msg {
                Some(tunnel_message::Msg::Data(data)) => {
                    if data_tx.send(Bytes::from(data.data)).await.is_err() {
                        break;
                    }
                    if data.fin {
                        break;
                    }
                }
                Some(tunnel_message::Msg::Close(_)) => {
                    break;
                }
                _ => {}
            }
        }
    });

    // Spawn task to forward outbound data
    tokio::spawn(async move {
        while let Some(data) = write_rx.recv().await {
            let msg = TunnelMessage {
                msg: Some(tunnel_message::Msg::Data(Data {
                    data: data.to_vec(),
                    fin: false,
                })),
            };
            if tunnel_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    Ok(TunnelAdapter::new(data_rx, write_tx))
}

/// Perform mTLS handshake over the tunnel.
async fn perform_mtls_handshake(
    tunnel: TunnelAdapter,
    server_fingerprint: &Fingerprint,
    client_identity: &ClientIdentity,
) -> Result<tokio_rustls::client::TlsStream<TunnelAdapter>, ClientError> {
    let verifier = EnrollmentVerifier::from_fingerprint(server_fingerprint);
    let tls_config = build_mtls_config(client_identity, verifier)?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("daemon.local")
        .map_err(|e| ClientError::MtlsFailed {
            reason: format!("Invalid server name: {}", e),
        })?;

    let tls_stream = connector
        .connect(server_name.to_owned(), tunnel)
        .await
        .map_err(|e| ClientError::MtlsFailed {
            reason: format!("TLS handshake failed: {}", e),
        })?;

    Ok(tls_stream)
}

/// Auth interceptor for injecting Bearer token into requests.
#[derive(Clone)]
struct AuthInterceptor {
    token: String,
}

impl AuthInterceptor {
    fn new(token: String) -> Self {
        Self { token }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.token)
                .parse()
                .map_err(|_| tonic::Status::internal("Invalid token"))?,
        );
        Ok(req)
    }
}

/// Terminal session over mTLS tunnel.
///
/// Handles PTY data streaming between the mobile app and daemon.
#[allow(dead_code)] // Fields used in future PTY implementation
pub struct TerminalTunnel {
    /// TLS stream to daemon
    stream: tokio_rustls::client::TlsStream<TunnelAdapter>,
    /// Daemon enrollment info
    enrollment: DaemonEnrollment,
}

impl TerminalTunnel {
    /// Create a new terminal tunnel.
    pub(crate) fn new(
        stream: tokio_rustls::client::TlsStream<TunnelAdapter>,
        enrollment: DaemonEnrollment,
    ) -> Self {
        Self { stream, enrollment }
    }

    /// Get the daemon fingerprint.
    pub fn daemon_fingerprint(&self) -> &Fingerprint {
        &self.enrollment.daemon_fingerprint
    }

    /// Get the daemon label.
    pub fn label(&self) -> Option<&str> {
        self.enrollment.label.as_deref()
    }
}

// Note: Actual PTY read/write operations would be implemented here,
// but require additional protocol work (protobuf messages for PTY data).
// For now, this establishes the mTLS tunnel foundation.
