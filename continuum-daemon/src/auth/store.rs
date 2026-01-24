//! Persistent auth storage with SQLite.
//!
//! Uses atomic transactions for enrollment operations and
//! an in-memory cache for fast allowlist checks.

use arc_swap::ArcSwap;
use continuum_auth::enrollment::SignedEnrollmentToken;
use continuum_auth::Fingerprint;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::watch;

/// Crockford Base32 charset (excludes 0/O/1/I/L/U for readability)
const SHORT_CODE_CHARSET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
const SHORT_CODE_LENGTH: usize = 6;

/// Persistent storage for authorized clients and enrollment tokens.
pub struct AuthStore {
    pool: SqlitePool,
    /// M2 FIX: In-memory cache using ArcSwap for atomic swap.
    /// This eliminates the race condition in the clear-then-populate pattern.
    allowlist_cache: ArcSwap<HashSet<String>>,
    /// Signal when authorized client list changes (for TLS reload)
    tls_reload_tx: watch::Sender<()>,
}

/// Record of an authorized client.
#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub fingerprint: String,
    pub label: Option<String>,
    pub authorized_at: i64,
    pub last_seen_at: Option<i64>,
}

impl AuthStore {
    /// Create a new auth store with the given database pool.
    ///
    /// Creates tables if they don't exist and pre-populates the allowlist cache.
    /// Returns both the store and a watch receiver for TLS reload signals.
    pub async fn new(pool: SqlitePool) -> Result<(Self, watch::Receiver<()>), AuthStoreError> {
        // Create tables
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
        .execute(&pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                token_hash TEXT PRIMARY KEY,
                label TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER,
                used_by_fingerprint TEXT,
                short_code TEXT UNIQUE
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // Create TLS reload signal channel
        let (tls_reload_tx, tls_reload_rx) = watch::channel(());

        // Pre-populate allowlist cache
        let store = Self {
            pool,
            allowlist_cache: ArcSwap::from_pointee(HashSet::new()),
            tls_reload_tx,
        };
        store.refresh_allowlist_cache().await?;

        Ok((store, tls_reload_rx))
    }

    /// Check if fingerprint is authorized (fast path via cache).
    pub fn is_authorized_cached(&self, fingerprint: &Fingerprint) -> bool {
        self.allowlist_cache.load().contains(fingerprint.as_str())
    }

    /// M2 FIX: Refresh in-memory allowlist cache from database using atomic swap.
    ///
    /// Unlike the previous clear-then-populate pattern, this builds a new set
    /// and swaps it atomically, eliminating any window where the cache is empty.
    pub async fn refresh_allowlist_cache(&self) -> Result<(), AuthStoreError> {
        let rows = sqlx::query("SELECT fingerprint FROM authorized_clients")
            .fetch_all(&self.pool)
            .await?;

        // Build new set
        let new_set: HashSet<String> = rows
            .into_iter()
            .map(|row| row.get("fingerprint"))
            .collect();

        // Atomic swap - no window where cache is empty
        self.allowlist_cache.store(Arc::new(new_set));

        Ok(())
    }

    /// Create a new enrollment token and store its hash.
    ///
    /// Returns the token hash for tracking.
    pub async fn create_enrollment_token(
        &self,
        token_hash: &str,
        label: Option<&str>,
        expires_at: i64,
    ) -> Result<(), AuthStoreError> {
        let now = current_timestamp();

        sqlx::query(
            r#"
            INSERT INTO enrollment_tokens (token_hash, label, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(token_hash)
        .bind(label)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Consume a cryptographically-validated token.
    ///
    /// C4 FIX: This method takes an already-validated `SignedEnrollmentToken` to
    /// eliminate any TOCTOU race window. The caller must verify the token's
    /// cryptographic signature before calling this method.
    ///
    /// # Security
    ///
    /// This method assumes the caller has already verified:
    /// - Token signature is valid (signed by this server's key)
    /// - Token is not expired (checked cryptographically)
    ///
    /// This method ensures:
    /// - Token is consumed atomically (single UPDATE)
    /// - Replay attacks are prevented (used_at tracking)
    pub async fn consume_validated_token(
        &self,
        token: &SignedEnrollmentToken,
        used_by_fingerprint: &str,
    ) -> Result<(), AuthStoreError> {
        // Hash the token's canonical base64 representation
        let token_hash = hash_token(&token.to_base64());
        let now = current_timestamp();

        // Single atomic UPDATE - no race possible
        // The WHERE clause ensures only unused tokens are consumed
        let result = sqlx::query(
            "UPDATE enrollment_tokens
             SET used_at = ?, used_by_fingerprint = ?
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(now)
        .bind(used_by_fingerprint)
        .bind(&token_hash)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            // Token was already used or expired between validation and consumption
            // This is the race condition we're protecting against
            //
            // Note: We return TokenAlreadyUsed as the generic error here because:
            // 1. If it's expired, the cryptographic check should have caught it
            // 2. If it's not in the DB, something is very wrong
            // 3. Most likely cause is a race with another enrollment attempt
            return Err(AuthStoreError::TokenAlreadyUsed);
        }

        Ok(())
    }

    /// Authorize a client atomically (single transaction).
    ///
    /// Signals TLS reload after successful authorization.
    pub async fn authorize_client(
        &self,
        fingerprint: &str,
        cert_der: &[u8],
        label: Option<&str>,
    ) -> Result<(), AuthStoreError> {
        let now = current_timestamp();

        sqlx::query(
            r#"
            INSERT OR REPLACE INTO authorized_clients
            (fingerprint, cert_der, label, authorized_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(fingerprint)
        .bind(cert_der)
        .bind(label)
        .bind(now)
        .execute(&self.pool)
        .await?;

        // M2 FIX: Update cache atomically using rcu pattern
        let fp = fingerprint.to_string();
        self.allowlist_cache.rcu(|old| {
            let mut new_set = (**old).clone();
            new_set.insert(fp.clone());
            Arc::new(new_set)
        });

        // Signal TLS reload needed
        let _ = self.tls_reload_tx.send(());
        tracing::debug!(fingerprint = %fingerprint, "Client authorized, TLS reload signaled");

        Ok(())
    }

    /// Get all authorized client certificates (for TLS config reload).
    pub async fn get_authorized_certs(&self) -> Result<Vec<Vec<u8>>, AuthStoreError> {
        let rows = sqlx::query("SELECT cert_der FROM authorized_clients")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get("cert_der")).collect())
    }

    /// Get client status by fingerprint.
    pub async fn get_client_status(
        &self,
        fingerprint: &str,
    ) -> Result<(bool, Option<i64>), AuthStoreError> {
        let row = sqlx::query(
            "SELECT authorized_at FROM authorized_clients WHERE fingerprint = ?",
        )
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let authorized_at: i64 = r.get("authorized_at");
                Ok((true, Some(authorized_at)))
            }
            None => Ok((false, None)),
        }
    }

    /// List all authorized clients (agent-native API).
    pub async fn list_all_clients(&self) -> Result<Vec<ClientRecord>, AuthStoreError> {
        let rows = sqlx::query(
            "SELECT fingerprint, label, authorized_at, last_seen_at FROM authorized_clients",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| ClientRecord {
                fingerprint: row.get("fingerprint"),
                label: row.get("label"),
                authorized_at: row.get("authorized_at"),
                last_seen_at: row.get("last_seen_at"),
            })
            .collect())
    }

    /// Revoke a client's authorization.
    ///
    /// Signals TLS reload after successful revocation to ensure the client
    /// cannot establish new mTLS connections.
    pub async fn revoke_client(&self, fingerprint: &str) -> Result<bool, AuthStoreError> {
        let result = sqlx::query("DELETE FROM authorized_clients WHERE fingerprint = ?")
            .bind(fingerprint)
            .execute(&self.pool)
            .await?;

        let was_revoked = result.rows_affected() > 0;

        if was_revoked {
            // M2 FIX: Update cache atomically using rcu pattern
            let fp = fingerprint.to_string();
            self.allowlist_cache.rcu(|old| {
                let mut new_set = (**old).clone();
                new_set.remove(&fp);
                Arc::new(new_set)
            });

            // Signal TLS reload needed - revoked clients must not be able to connect
            let _ = self.tls_reload_tx.send(());
            tracing::info!(fingerprint = %fingerprint, "Client revoked, TLS reload signaled");
        }

        Ok(was_revoked)
    }

    /// Create enrollment token with short code.
    ///
    /// Stores both the token hash and short code for lookup.
    pub async fn create_enrollment_token_with_short_code(
        &self,
        token_hash: &str,
        short_code: &str,
        label: Option<&str>,
        expires_at: i64,
    ) -> Result<(), AuthStoreError> {
        let now = current_timestamp();
        // Store without the dash (normalized)
        let normalized_code = short_code.replace('-', "");

        sqlx::query(
            r#"
            INSERT INTO enrollment_tokens (token_hash, short_code, label, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(token_hash)
        .bind(&normalized_code)
        .bind(label)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Atomically create token with short code if under rate limit.
    pub async fn create_token_with_short_code_rate_limited(
        &self,
        token_hash: &str,
        short_code: &str,
        label: Option<&str>,
        expires_at: i64,
        max_live_tokens: i32,
    ) -> Result<(), AuthStoreError> {
        let now = current_timestamp();
        let normalized_code = short_code.replace('-', "");

        let result = sqlx::query(
            r#"
            INSERT INTO enrollment_tokens (token_hash, short_code, label, created_at, expires_at)
            SELECT ?, ?, ?, ?, ?
            WHERE (SELECT COUNT(*) FROM enrollment_tokens
                   WHERE used_at IS NULL AND expires_at > ?) < ?
            "#,
        )
        .bind(token_hash)
        .bind(&normalized_code)
        .bind(label)
        .bind(now)
        .bind(expires_at)
        .bind(now)
        .bind(max_live_tokens)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthStoreError::RateLimitExceeded);
        }
        Ok(())
    }

    /// Consume a short code atomically.
    ///
    /// Marks the token as used and returns success if it was valid.
    pub async fn consume_short_code(
        &self,
        short_code: &str,
        used_by_fingerprint: &str,
    ) -> Result<(), AuthStoreError> {
        let normalized = short_code.replace('-', "").to_uppercase();
        let now = current_timestamp();

        let result = sqlx::query(
            "UPDATE enrollment_tokens
             SET used_at = ?, used_by_fingerprint = ?
             WHERE short_code = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(now)
        .bind(used_by_fingerprint)
        .bind(&normalized)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthStoreError::TokenAlreadyUsed);
        }

        Ok(())
    }
}

/// Hash a token for storage (never store the raw token).
///
/// Normalizes the token by removing dashes (which are added for display readability).
pub fn hash_token(token: &str) -> String {
    // Remove dashes that are added for human readability in Display impl
    let normalized: String = token.chars().filter(|&c| c != '-').collect();
    let hash = Sha256::digest(normalized.as_bytes());
    hex::encode(hash)
}

/// Generate a random 6-character short code in Crockford Base32.
///
/// Format: "ABC-123" (displayed with dash for readability).
pub fn generate_short_code() -> String {
    let mut random = [0u8; SHORT_CODE_LENGTH];
    OsRng.fill_bytes(&mut random);

    let code: String = random
        .iter()
        .map(|&b| SHORT_CODE_CHARSET[b as usize % SHORT_CODE_CHARSET.len()] as char)
        .collect();

    // Format as ABC-123
    format!("{}-{}", &code[..3], &code[3..])
}

/// Normalize a short code from user input.
///
/// - Removes dashes
/// - Converts to uppercase
/// - Returns None if invalid format
pub fn normalize_short_code(input: &str) -> Option<String> {
    let normalized: String = input
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if normalized.len() != SHORT_CODE_LENGTH {
        return None;
    }

    // Validate all chars are in charset
    for c in normalized.chars() {
        if !SHORT_CODE_CHARSET.contains(&(c as u8)) {
            return None;
        }
    }

    Some(normalized)
}

/// Check if input looks like a short code (6-7 chars with optional dash).
pub fn is_short_code(input: &str) -> bool {
    normalize_short_code(input).is_some()
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs() as i64
}

/// Errors that can occur during auth store operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthStoreError {
    #[error("token already used")]
    TokenAlreadyUsed,
    #[error("rate limit exceeded: maximum live tokens reached")]
    RateLimitExceeded,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use continuum_auth::identity::PrivateKey;

    async fn test_store() -> (AuthStore, watch::Receiver<()>) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        AuthStore::new(pool).await.unwrap()
    }

    /// Generate a valid fingerprint for testing.
    fn test_fingerprint() -> Fingerprint {
        let key = PrivateKey::generate();
        Fingerprint::from_public_key(&key.public_key())
    }

    #[tokio::test]
    async fn test_authorize_client() {
        let (store, _rx) = test_store().await;

        let fp = test_fingerprint();
        let fingerprint = fp.to_string();
        let cert_der = vec![1, 2, 3, 4];

        store
            .authorize_client(&fingerprint, &cert_der, Some("test"))
            .await
            .unwrap();

        // Should be in cache
        assert!(store.is_authorized_cached(&fp));

        // Should be in database
        let (is_auth, _) = store.get_client_status(&fingerprint).await.unwrap();
        assert!(is_auth);
    }

    #[tokio::test]
    async fn test_revoke_client() {
        let (store, _rx) = test_store().await;

        let fp = test_fingerprint();
        let fingerprint = fp.to_string();
        store
            .authorize_client(&fingerprint, &[1, 2, 3], None)
            .await
            .unwrap();

        let revoked = store.revoke_client(&fingerprint).await.unwrap();
        assert!(revoked);

        assert!(!store.is_authorized_cached(&fp));
    }

    #[tokio::test]
    async fn test_tls_reload_signal_on_authorize() {
        let (store, mut rx) = test_store().await;

        let fp = test_fingerprint();
        let fingerprint = fp.to_string();

        // Mark initial value as seen
        rx.mark_changed();

        store
            .authorize_client(&fingerprint, &[1, 2, 3], None)
            .await
            .unwrap();

        // Should have received a reload signal
        assert!(rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn test_tls_reload_signal_on_revoke() {
        let (store, mut rx) = test_store().await;

        let fp = test_fingerprint();
        let fingerprint = fp.to_string();

        store
            .authorize_client(&fingerprint, &[1, 2, 3], None)
            .await
            .unwrap();

        // Mark as seen before revoke
        rx.mark_changed();

        let revoked = store.revoke_client(&fingerprint).await.unwrap();
        assert!(revoked);

        // Should have received a reload signal
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn test_generate_short_code_format() {
        let code = generate_short_code();
        // Format: ABC-123
        assert_eq!(code.len(), 7); // 6 chars + 1 dash
        assert_eq!(&code[3..4], "-");
        // All chars should be in Crockford Base32 charset
        let normalized = code.replace('-', "");
        assert_eq!(normalized.len(), 6);
        for c in normalized.chars() {
            assert!(SHORT_CODE_CHARSET.contains(&(c as u8)), "Invalid char: {}", c);
        }
    }

    #[test]
    fn test_generate_short_code_uniqueness() {
        let code1 = generate_short_code();
        let code2 = generate_short_code();
        assert_ne!(code1, code2, "Codes should be unique");
    }

    #[test]
    fn test_normalize_short_code() {
        // Valid codes (Crockford Base32: 2-9, A-H, J-N, P-T, V-Z - no 0,1,I,L,O,U)
        assert!(normalize_short_code("ABC-234").is_some());
        assert!(normalize_short_code("abc-234").is_some());
        assert!(normalize_short_code("ABC234").is_some());
        assert!(normalize_short_code("abc234").is_some());
        assert!(normalize_short_code("HJK-NRT").is_some()); // All valid chars

        // Invalid codes
        assert!(normalize_short_code("ABC-23").is_none()); // Too short
        assert!(normalize_short_code("ABC-2345").is_none()); // Too long
        assert!(normalize_short_code("ABC-23O").is_none()); // Contains O (not in charset)
        assert!(normalize_short_code("ABC-23I").is_none()); // Contains I (not in charset)
        assert!(normalize_short_code("ABC-230").is_none()); // Contains 0 (not in charset)
        assert!(normalize_short_code("ABC-231").is_none()); // Contains 1 (not in charset)
    }

    #[test]
    fn test_is_short_code() {
        assert!(is_short_code("ABC-234"));
        assert!(is_short_code("abc-234"));
        assert!(is_short_code("ABC234"));
        assert!(!is_short_code("ABC")); // Too short
        assert!(!is_short_code("ABCDEFGHIJK")); // Too long
        assert!(!is_short_code("ABC-23O")); // Contains O (not in charset)
        assert!(!is_short_code("ABC-231")); // Contains 1 (not in charset)
    }

    #[tokio::test]
    async fn test_create_and_consume_short_code() {
        let (store, _rx) = test_store().await;
        let future_time = current_timestamp() + 300;

        let short_code = "ABC-234"; // Crockford Base32 (no 0,1,I,L,O,U)

        // Create token with short code
        store
            .create_enrollment_token_with_short_code(
                "some_token_hash",
                short_code,
                Some("test"),
                future_time,
            )
            .await
            .expect("Should create token with short code");

        // Consume the short code
        store
            .consume_short_code(short_code, "client-fingerprint")
            .await
            .expect("Should consume short code");

        // Try to consume again - should fail
        let result = store.consume_short_code(short_code, "another-client").await;
        assert!(matches!(result, Err(AuthStoreError::TokenAlreadyUsed)));
    }

    #[tokio::test]
    async fn test_short_code_expired() {
        let (store, _rx) = test_store().await;
        let past_time = current_timestamp() - 100; // Already expired

        let short_code = "XYZ-789";

        // Create expired token
        store
            .create_enrollment_token_with_short_code(
                "expired_token_hash",
                short_code,
                None,
                past_time,
            )
            .await
            .expect("Should create expired token");

        // Try to consume - should fail (expired)
        let result = store.consume_short_code(short_code, "client").await;
        assert!(matches!(result, Err(AuthStoreError::TokenAlreadyUsed)));
    }

    #[tokio::test]
    async fn test_short_code_case_insensitive() {
        let (store, _rx) = test_store().await;
        let future_time = current_timestamp() + 300;

        // Create with uppercase
        store
            .create_enrollment_token_with_short_code(
                "token_hash",
                "ABC-DEF",
                None,
                future_time,
            )
            .await
            .unwrap();

        // Consume with lowercase
        store
            .consume_short_code("abc-def", "client")
            .await
            .expect("Should consume with lowercase");
    }
}
