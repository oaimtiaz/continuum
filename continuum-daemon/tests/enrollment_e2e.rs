//! End-to-end tests for the enrollment flow.
//!
//! These tests verify the complete enrollment lifecycle:
//! 1. Token generation and validation
//! 2. Client authorization
//! 3. Fingerprint consistency across all computation paths
//!
//! The tests use tonic's direct server-to-client pattern (no network)
//! for fast, reliable execution.

mod common;

use common::{EnrollmentResult, TestClient, TestDaemon};
use continuum_auth::enrollment::SignedEnrollmentToken;
use continuum_auth::identity::{Fingerprint, PrivateKey, PublicKey};

// ============================================================================
// Fingerprint Consistency Tests (Critical - prevents the original bug)
// ============================================================================

/// Regression test for fingerprint mismatch bug.
///
/// Verifies all fingerprint computation paths produce identical values.
/// This test would have caught the original bug where:
/// - `ClientIdentity::from_der()` computed fingerprint from certificate DER hash
/// - Server computed fingerprint from Ed25519 public key bytes
#[tokio::test]
async fn test_fingerprint_consistency_across_all_paths() {
    // Generate Ed25519 keypair
    let private_key = PrivateKey::generate();
    let public_key = private_key.public_key();

    // Path 1: Direct from public key (canonical)
    let fp_from_pubkey = Fingerprint::from_public_key(&public_key);

    // Path 2: From public key bytes roundtrip (what server does)
    let pubkey_bytes = public_key.to_bytes();
    let reconstructed = PublicKey::from_bytes(&pubkey_bytes).expect("Failed to reconstruct public key");
    let fp_from_roundtrip = Fingerprint::from_public_key(&reconstructed);

    // Path 3: From TestClient (which generates certificate)
    let test_client = TestClient::new();
    // Note: TestClient uses PrivateKey::generate(), so we need to verify
    // its fingerprint computation is consistent

    // Path 4: Verify the client fingerprint matches the public key fingerprint
    let client_pubkey = test_client.private_key.public_key();
    let fp_from_client_pubkey = Fingerprint::from_public_key(&client_pubkey);

    // ALL MUST BE IDENTICAL
    assert_eq!(
        fp_from_pubkey, fp_from_roundtrip,
        "Roundtrip fingerprint must match direct computation"
    );
    assert_eq!(
        fp_from_client_pubkey, test_client.fingerprint,
        "TestClient fingerprint must match its public key fingerprint"
    );
}

/// Test that token contains correct server fingerprint.
#[tokio::test]
async fn test_token_contains_correct_server_fingerprint() {
    let daemon = TestDaemon::new().await;

    // Generate token
    let token_b64 = daemon.generate_token(300).await;
    let token =
        SignedEnrollmentToken::from_base64(&token_b64).expect("Failed to parse token");

    // Token's embedded fingerprint should match daemon's fingerprint
    assert_eq!(
        token.server_fingerprint(),
        daemon.server_fingerprint,
        "Token must contain correct server fingerprint"
    );
}

/// Test that enrolled client fingerprint matches what server stores.
#[tokio::test]
async fn test_enrolled_fingerprint_matches_client() {
    let daemon = TestDaemon::new().await;
    let client = TestClient::new();
    let mut grpc_client = daemon.client();

    // Generate and use token
    let token = daemon.generate_token(300).await;
    let result = client.enroll(&mut grpc_client, &token).await.unwrap();

    // Extract fingerprint from result
    let enrolled_fp = match result {
        EnrollmentResult::Approved { client_fingerprint } => client_fingerprint,
        other => panic!("Expected Approved, got {:?}", other),
    };

    // Server-stored fingerprint must match client's fingerprint
    assert_eq!(
        enrolled_fp,
        client.fingerprint.to_string(),
        "Server-stored fingerprint must match client fingerprint"
    );
}

// ============================================================================
// Happy Path Tests
// ============================================================================

/// Complete enrollment flow from token generation to authorization.
#[tokio::test]
async fn test_full_enrollment_flow() {
    let daemon = TestDaemon::new().await;
    let client = TestClient::new();
    let mut grpc_client = daemon.client();

    // 1. Generate token
    let token = daemon.generate_token(300).await;
    assert!(!token.is_empty(), "Token should not be empty");

    // 2. Enroll
    let result = client.enroll(&mut grpc_client, &token).await.unwrap();
    assert!(
        matches!(result, EnrollmentResult::Approved { .. }),
        "Enrollment should be approved, got {:?}",
        result
    );

    // 3. Verify client is authorized in daemon
    assert!(
        daemon.is_client_authorized(&client.fingerprint).await,
        "Client should be authorized after enrollment"
    );
}

/// Test that enrolled client shows correct status.
#[tokio::test]
async fn test_enrollment_status_check() {
    let daemon = TestDaemon::new().await;
    let client = TestClient::new();
    let mut grpc_client = daemon.client();

    // Before enrollment: not authorized
    assert!(
        !daemon.is_client_authorized(&client.fingerprint).await,
        "Client should not be authorized before enrollment"
    );

    // Enroll
    let token = daemon.generate_token(300).await;
    client.enroll(&mut grpc_client, &token).await.unwrap();

    // After enrollment: authorized
    assert!(
        daemon.is_client_authorized(&client.fingerprint).await,
        "Client should be authorized after enrollment"
    );
}

// ============================================================================
// Token Validation Tests
// ============================================================================

/// Test that expired tokens are rejected.
#[tokio::test]
async fn test_token_expiration() {
    let daemon = TestDaemon::new().await;
    let client = TestClient::new();
    let mut grpc_client = daemon.client();

    // Generate token that expires in 1 second (minimum is 60s, but we manipulate DB)
    let token = SignedEnrollmentToken::generate(&daemon.server_key, 60);
    let token_b64 = token.to_base64();

    // Store token with past expiration time
    let past_time = common::harness::current_timestamp() - 10;
    let token_hash = common::harness::hash_token(&token_b64);
    sqlx::query(
        "INSERT INTO enrollment_tokens (token_hash, created_at, expires_at) VALUES (?, ?, ?)",
    )
    .bind(&token_hash)
    .bind(past_time - 100)
    .bind(past_time) // Already expired
    .execute(&daemon.pool)
    .await
    .unwrap();

    // Enrollment should fail
    let result = client.enroll(&mut grpc_client, &token_b64).await.unwrap();
    match result {
        EnrollmentResult::Rejected { reason } => {
            assert!(
                reason.contains("expired"),
                "Rejection reason should mention expiration, got: {}",
                reason
            );
        }
        other => panic!("Expected Rejected with expiration, got {:?}", other),
    }
}

/// Test that tokens can only be used once.
#[tokio::test]
async fn test_token_single_use() {
    let daemon = TestDaemon::new().await;
    let client1 = TestClient::new();
    let client2 = TestClient::new();

    // Generate token
    let token = daemon.generate_token(300).await;

    // First use succeeds
    let mut grpc_client1 = daemon.client();
    let result1 = client1.enroll(&mut grpc_client1, &token).await.unwrap();
    assert!(
        matches!(result1, EnrollmentResult::Approved { .. }),
        "First enrollment should succeed"
    );

    // Second use fails
    let mut grpc_client2 = daemon.client();
    let result2 = client2.enroll(&mut grpc_client2, &token).await.unwrap();
    match result2 {
        EnrollmentResult::Rejected { reason } => {
            assert!(
                reason.contains("already used"),
                "Rejection reason should mention already used, got: {}",
                reason
            );
        }
        other => panic!("Expected Rejected for replay, got {:?}", other),
    }
}

/// Test that invalid tokens are rejected.
#[tokio::test]
async fn test_invalid_token_rejected() {
    let daemon = TestDaemon::new().await;
    let client = TestClient::new();
    let mut grpc_client = daemon.client();

    // Try enrolling with garbage token
    let result = client.enroll(&mut grpc_client, "invalid-token").await.unwrap();
    match result {
        EnrollmentResult::Rejected { reason } => {
            assert!(
                reason.contains("Invalid"),
                "Rejection reason should mention invalid, got: {}",
                reason
            );
        }
        other => panic!("Expected Rejected for invalid token, got {:?}", other),
    }
}

/// Test concurrent token consumption - only one should succeed.
#[tokio::test]
async fn test_concurrent_token_consumption() {
    let daemon = TestDaemon::new().await;
    let token = daemon.generate_token(300).await;

    // Spawn 10 concurrent enrollment attempts
    let mut handles = Vec::new();
    for _ in 0..10 {
        let token = token.clone();
        let pool = daemon.pool.clone();

        handles.push(tokio::spawn(async move {
            let client = TestClient::new();

            // Create a new daemon view with the same pool
            let test_daemon = TestDaemon::with_pool(pool).await;
            let mut grpc_client = test_daemon.client();

            client.enroll(&mut grpc_client, &token).await
        }));
    }

    let results: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("Task panicked"))
        .collect();

    // Exactly one should succeed
    let successes = results
        .iter()
        .filter(|r| matches!(r, Ok(EnrollmentResult::Approved { .. })))
        .count();
    assert_eq!(
        successes, 1,
        "Exactly one concurrent enrollment should succeed, got {}",
        successes
    );

    // All others should fail with "already used"
    let already_used = results
        .iter()
        .filter(|r| {
            matches!(
                r,
                Ok(EnrollmentResult::Rejected { reason }) if reason.contains("already used")
            )
        })
        .count();
    assert_eq!(
        already_used, 9,
        "9 should fail with 'already used', got {}",
        already_used
    );
}

// ============================================================================
// Revocation Tests
// ============================================================================

/// Test that revoked clients are no longer authorized.
#[tokio::test]
async fn test_client_revocation() {
    let daemon = TestDaemon::new().await;
    let client = TestClient::new();
    let mut grpc_client = daemon.client();

    // Enroll
    let token = daemon.generate_token(300).await;
    client.enroll(&mut grpc_client, &token).await.unwrap();

    // Verify authorized
    assert!(daemon.is_client_authorized(&client.fingerprint).await);

    // Revoke
    daemon.revoke_client(&client.fingerprint).await;

    // Verify no longer authorized
    assert!(
        !daemon.is_client_authorized(&client.fingerprint).await,
        "Client should not be authorized after revocation"
    );
}

// ============================================================================
// Re-enrollment Tests
// ============================================================================

/// Test that a client can re-enroll with a new token.
#[tokio::test]
async fn test_re_enrollment() {
    let daemon = TestDaemon::new().await;
    let client = TestClient::new();

    // First enrollment
    let token1 = daemon.generate_token(300).await;
    let mut grpc_client1 = daemon.client();
    let result1 = client.enroll(&mut grpc_client1, &token1).await.unwrap();
    assert!(matches!(result1, EnrollmentResult::Approved { .. }));

    // Re-enrollment with new token (same client identity)
    let token2 = daemon.generate_token(300).await;
    let mut grpc_client2 = daemon.client();
    let result2 = client.enroll(&mut grpc_client2, &token2).await.unwrap();
    assert!(
        matches!(result2, EnrollmentResult::Approved { .. }),
        "Re-enrollment should succeed"
    );

    // Still authorized
    assert!(daemon.is_client_authorized(&client.fingerprint).await);
}
