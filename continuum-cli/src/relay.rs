//! Relay connection support for the CLI.
//!
//! This module allows the CLI to connect to a daemon through a relay server
//! when direct connection is not possible (e.g., daemon behind NAT/firewall).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use continuum_auth::identity::Fingerprint;
use continuum_core::relay::{DeviceAuthClient, RelayAuthConfig, TunnelAdapter};
use continuum_proto::continuum_client::ContinuumClient;
use continuum_relay_proto::{
    tunnel_message, ClientRelayServiceClient, CreateSessionRequest, Data, Open, TunnelMessage,
};
use hyper::Uri;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tower::Service;

use crate::commands::IdentityStore;
use crate::tls::{build_mtls_config, EnrollmentVerifier};

/// Configuration for relay connectivity.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Relay server endpoint (e.g., "https://relay.continuumruntime.com")
    pub endpoint: String,
    /// Auth configuration (None for no-auth dev mode)
    pub auth: Option<RelayAuthConfig>,
    /// Skip authentication (dev mode)
    pub no_auth: bool,
}

impl RelayConfig {
    /// Load configuration from environment variables.
    ///
    /// Required:
    /// - `CONTINUUM_RELAY_ENDPOINT`
    ///
    /// Optional (for auth):
    /// - `CONTINUUM_RELAY_AUTH0_DOMAIN`
    /// - `CONTINUUM_CLI_AUTH0_CLIENT_ID` (or `CONTINUUM_RELAY_AUTH0_CLIENT_ID` as fallback)
    /// - `CONTINUUM_RELAY_AUTH0_AUDIENCE`
    pub fn from_env() -> Option<Self> {
        let data_dir = directories::ProjectDirs::from("com", "continuum", "cli")
            .map(|d| d.data_local_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        Some(Self {
            endpoint: std::env::var("CONTINUUM_RELAY_ENDPOINT").ok()?,
            auth: RelayAuthConfig::from_env_for_cli(data_dir.join("relay_token")),
            no_auth: false,
        })
    }

    /// Create config with endpoint override.
    pub fn with_endpoint(mut self, endpoint: Option<String>) -> Self {
        if let Some(ep) = endpoint {
            self.endpoint = ep;
        }
        self
    }

    /// Enable no-auth mode.
    pub fn with_no_auth(mut self, no_auth: bool) -> Self {
        self.no_auth = no_auth;
        self
    }
}

/// Connect to a daemon through the relay and return a gRPC channel.
///
/// This function:
/// 1. Authenticates with the relay (unless no_auth mode)
/// 2. Creates a session with the target daemon
/// 3. Establishes a tunnel
/// 4. Performs mTLS handshake over the tunnel
/// 5. Returns a Channel ready for any gRPC service
pub async fn connect_via_relay_channel(config: &RelayConfig, daemon_id: &str) -> Result<Channel> {
    let tunnel = establish_relay_tunnel(config, daemon_id).await?;
    let tls_stream = perform_mtls_handshake(tunnel, daemon_id).await?;
    create_channel_from_stream(tls_stream).await
}

/// Connect to a daemon through the relay and return a ContinuumClient.
///
/// Convenience wrapper around `connect_via_relay_channel` for the Continuum service.
pub async fn connect_via_relay(
    config: &RelayConfig,
    daemon_id: &str,
) -> Result<ContinuumClient<Channel>> {
    let channel = connect_via_relay_channel(config, daemon_id).await?;
    Ok(ContinuumClient::new(channel))
}

/// Establish a raw tunnel through the relay to the target daemon.
async fn establish_relay_tunnel(config: &RelayConfig, daemon_id: &str) -> Result<TunnelAdapter> {
    let token = if config.no_auth {
        eprintln!("Connecting to relay (no-auth dev mode)...");
        None
    } else {
        let auth_config = config
            .auth
            .as_ref()
            .context("Auth config required (set CONTINUUM_RELAY_AUTH0_* env vars or use --relay-no-auth)")?;
        let auth = DeviceAuthClient::new(auth_config.clone());
        let t = auth.get_token().await?;
        eprintln!("Authenticated with relay");
        Some(t)
    };

    let channel = Channel::from_shared(config.endpoint.clone())
        .context("Invalid relay endpoint")?
        .connect()
        .await
        .context("Failed to connect to relay")?;

    let tunnel = if let Some(t) = token {
        let interceptor = AuthInterceptor::new(t);
        let mut client = ClientRelayServiceClient::with_interceptor(channel, interceptor);
        create_tunnel_with_client(&mut client, daemon_id).await?
    } else {
        let mut client = ClientRelayServiceClient::new(channel);
        create_tunnel_with_client(&mut client, daemon_id).await?
    };

    Ok(tunnel)
}

/// Create session and tunnel using a relay client, returning a TunnelAdapter.
async fn create_tunnel_with_client<T>(
    client: &mut ClientRelayServiceClient<T>,
    daemon_id: &str,
) -> Result<TunnelAdapter>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone + Send + 'static,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    T::Error: Into<tonic::codegen::StdError>,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
    T::Future: Send,
{
    let response = client
        .create_session(CreateSessionRequest {
            daemon_id: daemon_id.to_string(),
        })
        .await
        .context("Failed to create relay session")?
        .into_inner();

    let session_id = response.session_id.clone();
    let client_token = response.client_token;

    eprintln!("Session created: {}", session_id);

    let (tunnel_tx, tunnel_rx) = mpsc::channel::<TunnelMessage>(1024);
    let tunnel_stream = ReceiverStream::new(tunnel_rx);

    let open = TunnelMessage {
        msg: Some(tunnel_message::Msg::Open(Open {
            session_id: session_id.clone(),
            token: client_token,
        })),
    };
    tunnel_tx
        .send(open)
        .await
        .context("Failed to send open message")?;

    let response = client.tunnel(tunnel_stream).await?;
    let mut tunnel_inbound = response.into_inner();

    let (data_tx, data_rx) = mpsc::channel::<Bytes>(1024);
    let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(1024);

    let session_id_clone = session_id.clone();
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
                Some(tunnel_message::Msg::Close(close)) => {
                    tracing::debug!(session = %session_id_clone, reason = %close.reason, "Tunnel closed");
                    break;
                }
                _ => {}
            }
        }
        tracing::debug!(session = %session_id_clone, "Tunnel inbound task ended");
    });

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

/// Perform mTLS handshake over a tunnel.
async fn perform_mtls_handshake(
    tunnel: TunnelAdapter,
    daemon_id: &str,
) -> Result<tokio_rustls::client::TlsStream<TunnelAdapter>> {
    let identity_store = IdentityStore::open()?;
    let (_private_key, identity) = identity_store.load_or_generate()?;

    let server_fp = Fingerprint::parse(daemon_id)
        .context("Invalid daemon ID format (expected SHA256:...)")?;

    let verifier = EnrollmentVerifier::from_fingerprint(&server_fp);
    let tls_config = build_mtls_config(&identity, verifier)?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("daemon.local")
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;

    let tls_stream = connector
        .connect(server_name.to_owned(), tunnel)
        .await
        .context("TLS handshake over relay failed")?;

    eprintln!("mTLS handshake complete");
    Ok(tls_stream)
}

/// Create a tonic Channel from a pre-established TLS stream.
///
/// Uses a one-shot connector that returns the pre-established stream on first call.
async fn create_channel_from_stream<S>(stream: S) -> Result<Channel>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connector = OneShotConnector::new(stream);

    // URI is arbitrary - we're providing our own pre-established connection
    let channel = Endpoint::from_static("http://relay.internal")
        .connect_with_connector(connector)
        .await
        .context("Failed to create channel from relay stream")?;

    Ok(channel)
}

/// A connector that returns a pre-established stream exactly once.
///
/// This allows us to use tonic's Channel API with a stream we've already
/// established (e.g., TLS over a relay tunnel).
struct OneShotConnector<S> {
    stream: Arc<Mutex<Option<S>>>,
}

impl<S> OneShotConnector<S> {
    fn new(stream: S) -> Self {
        Self {
            stream: Arc::new(Mutex::new(Some(stream))),
        }
    }
}

impl<S> Clone for OneShotConnector<S> {
    fn clone(&self) -> Self {
        Self {
            stream: self.stream.clone(),
        }
    }
}

impl<S> Service<Uri> for OneShotConnector<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Return the stream wrapped in TokioIo for hyper compatibility
    type Response = TokioIo<S>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let stream = self.stream.clone();
        Box::pin(async move {
            let mut guard = stream.lock().await;
            let inner = guard.take().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Relay connection already consumed (reconnection not supported)",
                )
            })?;
            Ok(TokioIo::new(inner))
        })
    }
}

/// Auth interceptor for injecting Bearer token.
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
