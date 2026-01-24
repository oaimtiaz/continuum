//! Relay client for the daemon.
//!
//! This module handles the daemon's connection to the relay server, including:
//! - Auth0 device authentication
//! - Registration with the relay
//! - Accepting incoming tunnel requests
//! - Managing tunnel data streams

use std::collections::HashMap;
use std::path::PathBuf;

use bytes::Bytes;
use continuum_core::relay::{DeviceAuthClient, RelayAuthConfig, RelayAuthError, TunnelAdapter};
use continuum_relay_proto::{
    envelope, relay::v1::AttentionRequest, tunnel_message, CloseSession,
    DaemonRelayServiceClient, Data, Envelope, Open, SessionAccepted, SessionRejected,
    TunnelMessage,
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::Streaming;

/// Configuration for relay connectivity.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Relay server endpoint (e.g., "https://relay.continuumruntime.com")
    pub endpoint: String,
    /// Auth configuration (None for no-auth dev mode)
    pub auth: Option<RelayAuthConfig>,
}

impl RelayConfig {
    /// Load configuration from environment variables.
    ///
    /// Required:
    /// - `CONTINUUM_RELAY_ENDPOINT`
    ///
    /// Optional (for auth):
    /// - `CONTINUUM_RELAY_AUTH0_DOMAIN`
    /// - `CONTINUUM_RELAY_AUTH0_CLIENT_ID`
    /// - `CONTINUUM_RELAY_AUTH0_AUDIENCE`
    pub fn from_env() -> Option<Self> {
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("continuum");

        Some(Self {
            endpoint: std::env::var("CONTINUUM_RELAY_ENDPOINT").ok()?,
            auth: RelayAuthConfig::from_env(data_dir.join("relay_token")),
        })
    }
}

/// Incoming tunnel request from a client.
#[derive(Debug)]
pub struct SessionRequest {
    /// Unique identifier for this session
    pub session_id: String,
    /// Target service (enrollment or main)
    pub target: TunnelTarget,
    /// Tunnel address to connect to
    #[allow(dead_code)]
    pub tunnel_address: String,
}

/// Which daemon service the client wants to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelTarget {
    /// Enrollment service (port 50051)
    Enrollment,
    /// Main API service (port 50052)
    Main,
}

impl From<i32> for TunnelTarget {
    fn from(value: i32) -> Self {
        match value {
            1 => TunnelTarget::Enrollment, // Target::ENROLLMENT
            2 => TunnelTarget::Main,       // Target::MAIN
            _ => TunnelTarget::Main,       // Default to main
        }
    }
}

/// Relay client for daemon registration and tunnel handling.
pub struct RelayClient {
    config: RelayConfig,
    auth: Option<DeviceAuthClient>,
    daemon_id: String,
    no_auth: bool,
}

impl RelayClient {
    /// Create a new relay client.
    ///
    /// # Arguments
    ///
    /// * `config` - Relay configuration
    /// * `daemon_id` - This daemon's fingerprint identifier
    /// * `no_auth` - Skip authentication (dev mode)
    pub fn new(config: RelayConfig, daemon_id: String, no_auth: bool) -> Self {
        let auth = config.auth.clone().map(|a| DeviceAuthClient::new(a));
        Self {
            config,
            auth,
            daemon_id,
            no_auth,
        }
    }

    /// Get the daemon ID.
    #[allow(dead_code)]
    pub fn daemon_id(&self) -> &str {
        &self.daemon_id
    }

    /// Connect to the relay and register as a daemon.
    ///
    /// Returns a channel for incoming tunnel requests and a handle for managing tunnels.
    pub async fn connect(&self) -> Result<RelayConnection, RelayError> {
        let token = if self.no_auth {
            tracing::info!("Connecting to relay (no-auth dev mode)");
            None
        } else {
            let auth = self.auth.as_ref().ok_or_else(|| {
                RelayError::Config("Auth config required (set CONTINUUM_RELAY_AUTH0_* env vars or use --relay-no-auth)".into())
            })?;
            let t = auth.get_token().await?;
            tracing::info!("Authenticated with Auth0 for relay");
            Some(t)
        };

        let channel = Channel::from_shared(self.config.endpoint.clone())
            .map_err(|e| RelayError::Config(e.to_string()))?
            .http2_keep_alive_interval(std::time::Duration::from_secs(20))
            .keep_alive_timeout(std::time::Duration::from_secs(20))
            .keep_alive_while_idle(true)
            .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
            .connect_timeout(std::time::Duration::from_secs(10))
            .connect()
            .await?;

        let (inbound_stream, outbound, client) = if let Some(t) = token {
            let interceptor = AuthInterceptor::new(t, self.daemon_id.clone());
            let mut client = DaemonRelayServiceClient::with_interceptor(channel, interceptor);
            let (cmd_tx, cmd_rx) = mpsc::channel::<Envelope>(32);
            let cmd_stream = ReceiverStream::new(cmd_rx);
            let response = client.register(cmd_stream).await?;
            (response.into_inner(), cmd_tx, RelayClientInner::WithAuth(client))
        } else {
            // No-auth mode still sends fingerprint header
            let interceptor = FingerprintInterceptor::new(self.daemon_id.clone());
            let mut client = DaemonRelayServiceClient::with_interceptor(channel, interceptor);
            let (cmd_tx, cmd_rx) = mpsc::channel::<Envelope>(32);
            let cmd_stream = ReceiverStream::new(cmd_rx);
            let response = client.register(cmd_stream).await?;
            (response.into_inner(), cmd_tx, RelayClientInner::NoAuth(client))
        };

        tracing::info!(daemon_id = %self.daemon_id, "Registered with relay");

        Ok(RelayConnection {
            client,
            inbound: inbound_stream,
            outbound,
            tunnels: HashMap::new(),
        })
    }
}

/// Wrapper for DaemonRelayServiceClient with different auth modes.
enum RelayClientInner {
    WithAuth(DaemonRelayServiceClient<tonic::service::interceptor::InterceptedService<Channel, AuthInterceptor>>),
    NoAuth(DaemonRelayServiceClient<tonic::service::interceptor::InterceptedService<Channel, FingerprintInterceptor>>),
}

impl RelayClientInner {
    /// Open a tunnel stream.
    async fn tunnel(
        &mut self,
        request: impl tonic::IntoStreamingRequest<Message = TunnelMessage>,
    ) -> Result<tonic::Response<Streaming<TunnelMessage>>, tonic::Status> {
        match self {
            RelayClientInner::WithAuth(client) => client.tunnel(request).await,
            RelayClientInner::NoAuth(client) => client.tunnel(request).await,
        }
    }
}

/// Auth interceptor for injecting Bearer token and daemon fingerprint.
#[derive(Clone)]
struct AuthInterceptor {
    token: String,
    fingerprint: String,
}

impl AuthInterceptor {
    fn new(token: String, fingerprint: String) -> Self {
        Self { token, fingerprint }
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
        req.metadata_mut().insert(
            "x-daemon-fingerprint",
            self.fingerprint
                .parse()
                .map_err(|_| tonic::Status::internal("Invalid fingerprint"))?,
        );
        Ok(req)
    }
}

/// Fingerprint-only interceptor for no-auth dev mode.
#[derive(Clone)]
struct FingerprintInterceptor {
    fingerprint: String,
}

impl FingerprintInterceptor {
    fn new(fingerprint: String) -> Self {
        Self { fingerprint }
    }
}

impl tonic::service::Interceptor for FingerprintInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.metadata_mut().insert(
            "x-daemon-fingerprint",
            self.fingerprint
                .parse()
                .map_err(|_| tonic::Status::internal("Invalid fingerprint"))?,
        );
        Ok(req)
    }
}

/// Handle for sending messages to the relay from other parts of the daemon.
///
/// This is a clonable handle that can be shared across tasks.
#[derive(Clone)]
pub struct RelayHandle {
    outbound: mpsc::Sender<Envelope>,
}

impl RelayHandle {
    /// Request user attention (triggers push notification via relay/dashboard).
    ///
    /// Use this when the daemon needs the user to take action, such as:
    /// - Stalled tasks waiting for approval
    /// - Session requests requiring attention
    /// - Time-sensitive operations
    pub async fn request_attention(
        &self,
        session_id: &str,
        message: &str,
        urgent: bool,
    ) -> Result<(), RelayError> {
        let attention = Envelope {
            msg: Some(envelope::Msg::AttentionRequest(AttentionRequest {
                session_id: session_id.to_string(),
                message: message.to_string(),
                urgent,
            })),
        };
        self.outbound
            .send(attention)
            .await
            .map_err(|_| RelayError::ChannelClosed)?;
        tracing::debug!(
            session_id = %session_id,
            urgent = urgent,
            "Sent attention request to relay"
        );
        Ok(())
    }
}

/// Active relay connection with tunnel management.
pub struct RelayConnection {
    client: RelayClientInner,
    inbound: Streaming<Envelope>,
    outbound: mpsc::Sender<Envelope>,
    tunnels: HashMap<String, TunnelState>,
}

#[allow(dead_code)]
struct TunnelState {
    data_tx: mpsc::Sender<Bytes>,
}

impl RelayConnection {
    /// Get a clonable handle for sending messages to the relay.
    ///
    /// Use this to share relay access with other parts of the daemon
    /// (e.g., IPC handlers that need to send attention requests).
    pub fn handle(&self) -> RelayHandle {
        RelayHandle {
            outbound: self.outbound.clone(),
        }
    }

    /// Wait for the next event from the relay.
    pub async fn next_event(&mut self) -> Result<RelayEvent, RelayError> {
        loop {
            // Log channel state for debugging heartbeat issues
            tracing::trace!(
                "Outbound channel capacity: {}/32",
                32 - self.outbound.capacity()
            );

            let envelope = self
                .inbound
                .message()
                .await?
                .ok_or(RelayError::StreamClosed)?;

            match envelope.msg {
                Some(envelope::Msg::StartTunnel(start)) => {
                    return Ok(RelayEvent::SessionRequest(SessionRequest {
                        session_id: start.session_id,
                        target: TunnelTarget::from(start.target),
                        tunnel_address: start.tunnel_address,
                    }));
                }
                Some(envelope::Msg::Ping(ping)) => {
                    tracing::debug!(seq = ping.seq, "Received ping from relay");
                    let pong = Envelope {
                        msg: Some(envelope::Msg::Pong(continuum_relay_proto::Pong {
                            seq: ping.seq,
                            received_unix_millis: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                        })),
                    };
                    match self.outbound.send(pong).await {
                        Ok(_) => tracing::debug!(seq = ping.seq, "Sent pong to relay"),
                        Err(e) => tracing::error!(seq = ping.seq, error = %e, "Failed to send pong"),
                    }
                }
                Some(envelope::Msg::CloseSession(close)) => {
                    self.tunnels.remove(&close.session_id);
                    tracing::debug!(session_id = %close.session_id, reason = %close.reason, "Session closed by relay");
                }
                _ => {}
            }
        }
    }

    /// Accept a session request and establish a tunnel.
    ///
    /// Returns a `TunnelAdapter` that can be used for I/O with the client.
    pub async fn accept_session(
        &mut self,
        session: &SessionRequest,
        client_token: &str,
    ) -> Result<TunnelAdapter, RelayError> {
        let (data_tx, data_rx) = mpsc::channel::<Bytes>(1024);
        let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(1024);

        self.tunnels.insert(
            session.session_id.clone(),
            TunnelState { data_tx: data_tx.clone() },
        );

        let accepted = Envelope {
            msg: Some(envelope::Msg::Accepted(SessionAccepted {
                session_id: session.session_id.clone(),
            })),
        };
        self.outbound
            .send(accepted)
            .await
            .map_err(|_| RelayError::ChannelClosed)?;

        let (tunnel_tx, tunnel_rx) = mpsc::channel::<TunnelMessage>(1024);
        let tunnel_stream = ReceiverStream::new(tunnel_rx);

        let open = TunnelMessage {
            msg: Some(tunnel_message::Msg::Open(Open {
                session_id: session.session_id.clone(),
                token: client_token.to_string(),
            })),
        };
        tunnel_tx
            .send(open)
            .await
            .map_err(|_| RelayError::ChannelClosed)?;

        let response = self.client.tunnel(tunnel_stream).await?;
        let mut tunnel_inbound = response.into_inner();

        let session_id = session.session_id.clone();
        let data_tx_clone = data_tx;
        tokio::spawn(async move {
            while let Ok(Some(msg)) = tunnel_inbound.message().await {
                match msg.msg {
                    Some(tunnel_message::Msg::Data(data)) => {
                        if data_tx_clone.send(Bytes::from(data.data)).await.is_err() {
                            break;
                        }
                        if data.fin {
                            break;
                        }
                    }
                    Some(tunnel_message::Msg::Close(close)) => {
                        tracing::debug!(session = %session_id, reason = %close.reason, "Tunnel closed");
                        break;
                    }
                    _ => {}
                }
            }
        });

        let tunnel_tx_clone = tunnel_tx;
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                let msg = TunnelMessage {
                    msg: Some(tunnel_message::Msg::Data(Data {
                        data: data.to_vec(),
                        fin: false,
                    })),
                };
                if tunnel_tx_clone.send(msg).await.is_err() {
                    break;
                }
            }
        });

        Ok(TunnelAdapter::new(data_rx, write_tx))
    }

    /// Reject a session request.
    pub async fn reject_session(
        &mut self,
        session_id: &str,
        reason: &str,
    ) -> Result<(), RelayError> {
        let rejected = Envelope {
            msg: Some(envelope::Msg::Rejected(SessionRejected {
                session_id: session_id.to_string(),
                reason: reason.to_string(),
            })),
        };
        self.outbound
            .send(rejected)
            .await
            .map_err(|_| RelayError::ChannelClosed)?;
        Ok(())
    }

    /// Close a session.
    #[allow(dead_code)]
    pub async fn close_session(&mut self, session_id: &str, reason: &str) -> Result<(), RelayError> {
        self.tunnels.remove(session_id);
        let close = Envelope {
            msg: Some(envelope::Msg::CloseSession(CloseSession {
                session_id: session_id.to_string(),
                reason: reason.to_string(),
            })),
        };
        self.outbound
            .send(close)
            .await
            .map_err(|_| RelayError::ChannelClosed)?;
        tracing::debug!(session_id = %session_id, "Session closed");
        Ok(())
    }
}

/// Events from the relay.
pub enum RelayEvent {
    /// A client wants to establish a session/tunnel
    SessionRequest(SessionRequest),
}

/// Errors from relay operations.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Authentication failed
    #[error("Auth error: {0}")]
    Auth(#[from] RelayAuthError),

    /// gRPC transport error
    #[error("Transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// gRPC status error
    #[error("RPC error: {0}")]
    Rpc(#[from] tonic::Status),

    /// Configuration error
    #[error("Config error: {0}")]
    Config(String),

    /// Internal channel closed
    #[error("Internal channel closed")]
    ChannelClosed,

    /// Stream closed unexpectedly
    #[error("Stream closed")]
    StreamClosed,
}
