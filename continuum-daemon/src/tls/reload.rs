//! Dynamic TLS acceptor with hot-reload support.
//!
//! Uses arc-swap for lock-free atomic swapping of the TlsAcceptor when the
//! authorized client list changes.

use crate::auth::AuthStore;
use crate::tls::{TlsConfigError, TlsIdentity, TlsServerConfig};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// TLS acceptor that can be atomically reloaded when authorized clients change.
///
/// Uses `ArcSwap` for lock-free reads, ensuring that connection acceptance
/// never blocks on TLS configuration updates.
pub struct ReloadableTlsAcceptor {
    acceptor: ArcSwap<TlsAcceptor>,
    server_identity: Arc<TlsIdentity>,
}

impl ReloadableTlsAcceptor {
    /// Create a new reloadable acceptor with initial config.
    ///
    /// # Arguments
    /// * `initial_acceptor` - The initial TlsAcceptor (typically built at startup)
    /// * `server_identity` - Server's TLS identity (cert + key), retained for reloads
    pub fn new(initial_acceptor: TlsAcceptor, server_identity: Arc<TlsIdentity>) -> Arc<Self> {
        Arc::new(Self {
            acceptor: ArcSwap::from_pointee(initial_acceptor),
            server_identity,
        })
    }

    /// Get the current acceptor for accepting connections.
    ///
    /// This is lock-free and wait-free - safe to call from hot paths.
    pub fn current(&self) -> arc_swap::Guard<Arc<TlsAcceptor>> {
        self.acceptor.load()
    }

    /// Reload the TLS configuration with updated authorized clients.
    ///
    /// Fetches the current list of authorized client certificates from the
    /// AuthStore and rebuilds the TlsAcceptor. If reload fails, the previous
    /// configuration is retained.
    ///
    /// # Returns
    /// The number of authorized clients in the new configuration, or an error
    /// if the reload failed.
    pub async fn reload(&self, auth_store: &AuthStore) -> Result<usize, TlsConfigError> {
        let authorized_certs = auth_store
            .get_authorized_certs()
            .await
            .map_err(|e| TlsConfigError::Config(e.to_string()))?;

        let client_count = authorized_certs.len();

        let new_config = TlsServerConfig::new_mtls(
            self.server_identity.cert_der.clone(),
            self.server_identity.key_der.clone(),
            authorized_certs,
        )?;

        let new_acceptor = TlsAcceptor::from(new_config.into_rustls_config());
        self.acceptor.store(Arc::new(new_acceptor));

        Ok(client_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{build_self_signed, CertParams};
    use continuum_auth::identity::PrivateKey;
    use sqlx::SqlitePool;

    async fn test_auth_store() -> (AuthStore, tokio::sync::watch::Receiver<()>) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        AuthStore::new(pool).await.unwrap()
    }

    fn test_server_identity() -> Arc<TlsIdentity> {
        let key = PrivateKey::generate();
        let identity = build_self_signed(&key, &CertParams::default()).unwrap();
        Arc::new(identity)
    }

    fn test_client_identity() -> TlsIdentity {
        let key = PrivateKey::generate();
        build_self_signed(
            &key,
            &CertParams {
                common_name: "test-client".to_string(),
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_reload_updates_acceptor() {
        let (auth_store, _rx) = test_auth_store().await;
        let server_identity = test_server_identity();

        // Start with no authorized clients (server-only mode)
        let initial_config = TlsServerConfig::new_mtls(
            server_identity.cert_der.clone(),
            server_identity.key_der.clone(),
            vec![],
        )
        .unwrap();
        let initial_acceptor = TlsAcceptor::from(initial_config.into_rustls_config());

        let reloadable = ReloadableTlsAcceptor::new(initial_acceptor, server_identity);

        // Add a client
        let client = test_client_identity();
        auth_store
            .authorize_client(&client.fingerprint.to_string(), &client.cert_der, Some("test"))
            .await
            .unwrap();

        // Reload should succeed and return 1 client
        let count = reloadable.reload(&auth_store).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_current_returns_acceptor() {
        let server_identity = test_server_identity();

        let initial_config = TlsServerConfig::new_mtls(
            server_identity.cert_der.clone(),
            server_identity.key_der.clone(),
            vec![],
        )
        .unwrap();
        let initial_acceptor = TlsAcceptor::from(initial_config.into_rustls_config());

        let reloadable = ReloadableTlsAcceptor::new(initial_acceptor, server_identity);

        // Should be able to get the current acceptor
        let guard = reloadable.current();
        // Guard should dereference to TlsAcceptor
        let _acceptor: &TlsAcceptor = &**guard;
    }

    #[tokio::test]
    async fn test_reload_with_multiple_clients() {
        let (auth_store, _rx) = test_auth_store().await;
        let server_identity = test_server_identity();

        let initial_config = TlsServerConfig::new_mtls(
            server_identity.cert_der.clone(),
            server_identity.key_der.clone(),
            vec![],
        )
        .unwrap();
        let initial_acceptor = TlsAcceptor::from(initial_config.into_rustls_config());

        let reloadable = ReloadableTlsAcceptor::new(initial_acceptor, server_identity);

        // Add multiple clients
        for i in 0..5 {
            let client = test_client_identity();
            auth_store
                .authorize_client(
                    &client.fingerprint.to_string(),
                    &client.cert_der,
                    Some(&format!("client-{}", i)),
                )
                .await
                .unwrap();
        }

        let count = reloadable.reload(&auth_store).await.unwrap();
        assert_eq!(count, 5);
    }
}
