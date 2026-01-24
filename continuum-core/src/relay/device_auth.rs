//! Auth0 Device Authorization Flow client.
//!
//! This module implements the [Device Authorization Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow)
//! for authenticating both daemons and CLI clients with a relay server.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;

/// Configuration for relay authentication.
#[derive(Clone, Debug)]
pub struct RelayAuthConfig {
    /// Auth0 domain (e.g., "continuumruntime.us.auth0.com")
    pub auth0_domain: String,
    /// Auth0 application client ID
    pub auth0_client_id: String,
    /// Auth0 API audience identifier
    pub auth0_audience: String,
    /// Path to store the refresh token
    pub token_storage_path: PathBuf,
}

impl RelayAuthConfig {
    /// Load configuration from environment variables (for daemon).
    ///
    /// Required environment variables:
    /// - `CONTINUUM_RELAY_AUTH0_DOMAIN`
    /// - `CONTINUUM_RELAY_AUTH0_CLIENT_ID`
    /// - `CONTINUUM_RELAY_AUTH0_AUDIENCE`
    pub fn from_env(token_storage_path: PathBuf) -> Option<Self> {
        Some(Self {
            auth0_domain: std::env::var("CONTINUUM_RELAY_AUTH0_DOMAIN").ok()?,
            auth0_client_id: std::env::var("CONTINUUM_RELAY_AUTH0_CLIENT_ID").ok()?,
            auth0_audience: std::env::var("CONTINUUM_RELAY_AUTH0_AUDIENCE").ok()?,
            token_storage_path,
        })
    }

    /// Load configuration from environment variables (for CLI).
    ///
    /// Uses `CONTINUUM_CLI_AUTH0_CLIENT_ID` if set, otherwise falls back
    /// to `CONTINUUM_RELAY_AUTH0_CLIENT_ID`.
    ///
    /// Required environment variables:
    /// - `CONTINUUM_RELAY_AUTH0_DOMAIN`
    /// - `CONTINUUM_CLI_AUTH0_CLIENT_ID` or `CONTINUUM_RELAY_AUTH0_CLIENT_ID`
    /// - `CONTINUUM_RELAY_AUTH0_AUDIENCE`
    pub fn from_env_for_cli(token_storage_path: PathBuf) -> Option<Self> {
        let client_id = std::env::var("CONTINUUM_CLI_AUTH0_CLIENT_ID")
            .or_else(|_| std::env::var("CONTINUUM_RELAY_AUTH0_CLIENT_ID"))
            .ok()?;

        Some(Self {
            auth0_domain: std::env::var("CONTINUUM_RELAY_AUTH0_DOMAIN").ok()?,
            auth0_client_id: client_id,
            auth0_audience: std::env::var("CONTINUUM_RELAY_AUTH0_AUDIENCE").ok()?,
            token_storage_path,
        })
    }
}

/// Device Authorization client for Auth0.
///
/// This client implements the Device Authorization Flow, which is suitable for
/// both CLI tools and headless daemons. On first use, it prompts the user to
/// visit a URL and enter a code, then polls for the token.
pub struct DeviceAuthClient {
    config: RelayAuthConfig,
    http: reqwest::Client,
}

impl DeviceAuthClient {
    /// Create a new device auth client.
    pub fn new(config: RelayAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Get a valid access token, prompting for device auth if needed.
    ///
    /// This method:
    /// 1. Tries to use a cached refresh token first
    /// 2. If refresh fails or no token exists, initiates device auth flow
    /// 3. Saves the new refresh token for future use (if provided)
    pub async fn get_token(&self) -> Result<String, RelayAuthError> {
        if let Some(refresh) = self.load_refresh_token()? {
            match self.refresh(&refresh).await {
                Ok(tokens) => {
                    if let Some(ref rt) = tokens.refresh_token {
                        self.save_refresh_token(rt)?;
                    }
                    return Ok(tokens.access_token);
                }
                Err(e) => {
                    tracing::debug!("Refresh failed, need re-auth: {}", e);
                }
            }
        }

        self.do_device_auth().await
    }

    /// Perform the device authorization flow.
    async fn do_device_auth(&self) -> Result<String, RelayAuthError> {
        let device = self.request_device_code().await?;

        eprintln!();
        eprintln!("Relay authentication required.");
        eprintln!("Visit: {}", device.verification_uri_complete);
        eprintln!("Code:  {}", device.user_code);
        eprintln!();
        eprintln!("Waiting for authentication...");

        let tokens = self.poll_for_token(&device).await?;
        if let Some(ref rt) = tokens.refresh_token {
            self.save_refresh_token(rt)?;
        }

        eprintln!("Authenticated successfully.");
        Ok(tokens.access_token)
    }

    /// Request a device code from Auth0.
    async fn request_device_code(&self) -> Result<DeviceCodeResponse, RelayAuthError> {
        let response = self
            .http
            .post(format!(
                "https://{}/oauth/device/code",
                self.config.auth0_domain
            ))
            .form(&[
                ("client_id", &self.config.auth0_client_id),
                ("audience", &self.config.auth0_audience),
                ("scope", &"offline_access".to_string()),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(RelayAuthError::Auth(format!(
                "Auth0 device code request failed ({}): {}",
                status, body
            )));
        }

        response.json().await.map_err(Into::into)
    }

    /// Poll for the access token after user authenticates.
    async fn poll_for_token(
        &self,
        device: &DeviceCodeResponse,
    ) -> Result<TokenSet, RelayAuthError> {
        let deadline = Instant::now() + Duration::from_secs(device.expires_in);
        let mut interval = Duration::from_secs(device.interval);

        loop {
            if Instant::now() > deadline {
                return Err(RelayAuthError::DeviceCodeExpired);
            }

            tokio::time::sleep(interval).await;

            let resp = self
                .http
                .post(format!("https://{}/oauth/token", self.config.auth0_domain))
                .form(&[
                    ("client_id", &self.config.auth0_client_id),
                    ("device_code", &device.device_code),
                    (
                        "grant_type",
                        &"urn:ietf:params:oauth:grant-type:device_code".to_string(),
                    ),
                ])
                .send()
                .await?;

            if resp.status().is_success() {
                return Ok(resp.json().await?);
            }

            let err: DeviceError = resp.json().await?;
            match err.error.as_str() {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval = (interval * 2).min(Duration::from_secs(30));
                    continue;
                }
                "expired_token" => return Err(RelayAuthError::DeviceCodeExpired),
                "access_denied" => return Err(RelayAuthError::UserDenied),
                _ => return Err(RelayAuthError::Auth(err.error)),
            }
        }
    }

    /// Refresh an access token using a refresh token.
    async fn refresh(&self, refresh_token: &str) -> Result<TokenSet, RelayAuthError> {
        self.http
            .post(format!("https://{}/oauth/token", self.config.auth0_domain))
            .form(&[
                ("client_id", &self.config.auth0_client_id),
                ("refresh_token", &refresh_token.to_string()),
                ("grant_type", &"refresh_token".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Load refresh token from storage.
    fn load_refresh_token(&self) -> Result<Option<String>, RelayAuthError> {
        match std::fs::read_to_string(&self.config.token_storage_path) {
            Ok(token) => Ok(Some(token.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Save refresh token to storage with secure permissions.
    fn save_refresh_token(&self, token: &str) -> Result<(), RelayAuthError> {
        if let Some(parent) = self.config.token_storage_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.config.token_storage_path, token)?;

        // Set permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &self.config.token_storage_path,
                std::fs::Permissions::from_mode(0o600),
            )?;
        }

        Ok(())
    }
}

/// Response from the device code request.
#[derive(Debug, Deserialize)]
pub struct DeviceCodeResponse {
    /// The device verification code
    pub device_code: String,
    /// User-facing code to enter on the verification page
    pub user_code: String,
    /// URL for user to visit for verification
    pub verification_uri: String,
    /// Complete URL including the user code
    pub verification_uri_complete: String,
    /// Seconds until the code expires
    pub expires_in: u64,
    /// Minimum seconds between polling attempts
    pub interval: u64,
}

/// Token response from Auth0.
#[derive(Debug, Deserialize)]
pub struct TokenSet {
    /// JWT access token for relay API calls
    pub access_token: String,
    /// Refresh token for obtaining new access tokens (optional - requires offline_access)
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Error response from device auth polling.
#[derive(Deserialize)]
struct DeviceError {
    error: String,
}

/// Errors that can occur during relay authentication.
#[derive(Debug, Error)]
pub enum RelayAuthError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// File I/O error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Device code expired before user authenticated
    #[error("Device code expired - please try again")]
    DeviceCodeExpired,

    /// User denied access during device auth
    #[error("User denied access")]
    UserDenied,

    /// Generic authentication error
    #[error("Auth error: {0}")]
    Auth(String),
}
