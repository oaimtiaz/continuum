//! Per-request authentication proof and verification.

mod error;
mod proof;
mod replay_cache;
mod verify;

pub use error::AuthnError;
pub use proof::{AuthProof, RandomNonce};
pub use replay_cache::LruReplayCache;
pub use verify::{verify_v1, Allowlist, ReplayCache, VerifiedIdentity};

#[cfg(test)]
mod tests {
    use super::*;
    use super::verify::build_canonical_message;
    use crate::identity::{Fingerprint, PrivateKey};
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Test allowlist implementation.
    struct TestAllowlist(HashSet<String>);

    impl TestAllowlist {
        fn new() -> Self {
            Self(HashSet::new())
        }

        fn allow(&mut self, fingerprint: &Fingerprint) {
            self.0.insert(fingerprint.as_str().to_string());
        }
    }

    impl Allowlist for TestAllowlist {
        fn contains(&self, fingerprint: &Fingerprint) -> bool {
            self.0.contains(fingerprint.as_str())
        }
    }

    /// Test replay cache implementation.
    struct TestReplayCache(Mutex<HashSet<([u8; 16], i64)>>);

    impl TestReplayCache {
        fn new() -> Self {
            Self(Mutex::new(HashSet::new()))
        }
    }

    impl ReplayCache for TestReplayCache {
        fn check_and_insert(&self, _fingerprint: &Fingerprint, nonce: &[u8; 16], timestamp: i64) -> bool {
            let mut cache = self.0.lock().unwrap();
            cache.insert((*nonce, timestamp))
        }
    }

    fn create_test_proof(private_key: &PrivateKey, timestamp: i64) -> AuthProof {
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "TestMethod".to_string();
        let path = "/test/path".to_string();
        let body_hash = None;

        let message = build_canonical_message(timestamp, nonce.as_bytes(), &method, &path, body_hash)
            .expect("test message should be valid");

        let signature = private_key.sign(&message);

        AuthProof {
            public_key,
            signature,
            timestamp,
            nonce,
            method,
            path,
            body_hash: None,
        }
    }

    #[test]
    fn test_verify_valid_proof() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let proof = create_test_proof(&private_key, now);

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().fingerprint(), &fingerprint);
    }

    #[test]
    fn test_verify_expired_timestamp() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let old_timestamp = 1700000000i64;
        let now = old_timestamp + 60; // 60 seconds later, but max_skew is 30
        let proof = create_test_proof(&private_key, old_timestamp);

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::TimestampExpired);
    }

    #[test]
    fn test_verify_future_timestamp() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let future_timestamp = 1700000060i64;
        let now = 1700000000i64; // 60 seconds earlier, but max_skew is 30
        let proof = create_test_proof(&private_key, future_timestamp);

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::TimestampInFuture);
    }

    #[test]
    fn test_verify_not_allowlisted() {
        let private_key = PrivateKey::generate();
        let allowlist = TestAllowlist::new(); // Empty allowlist
        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let proof = create_test_proof(&private_key, now);

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::NotAllowlisted);
    }

    #[test]
    fn test_verify_invalid_signature() {
        let private_key = PrivateKey::generate();
        let other_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;

        // Create proof but sign with a different key
        let nonce = RandomNonce::new();
        let method = "TestMethod".to_string();
        let path = "/test/path".to_string();

        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, None)
            .expect("test message should be valid");

        // Sign with the wrong key
        let signature = other_key.sign(&message);

        let proof = AuthProof {
            public_key: private_key.public_key(),
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: None,
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::InvalidSignature);
    }

    #[test]
    fn test_verify_replay_detected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let proof = create_test_proof(&private_key, now);

        // First verification should succeed
        let result1 = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert!(result1.is_ok());

        // Second verification with same nonce should fail
        let result2 = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result2.unwrap_err(), AuthnError::ReplayDetected);
    }

    #[test]
    fn test_verify_with_body_hash() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "CreateTask".to_string();
        let path = "/api/tasks".to_string();
        let body_hash = Some([0xab; 32]);

        let message =
            build_canonical_message(now, nonce.as_bytes(), &method, &path, body_hash.as_ref())
                .expect("test message should be valid");

        let signature = private_key.sign(&message);

        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash,
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert!(result.is_ok());
    }

    #[test]
    fn test_canonical_message_format() {
        let timestamp = 0x0102030405060708i64;
        let nonce = [0x11u8; 16];
        let method = "GET";
        let path = "/api/test";

        let msg = build_canonical_message(timestamp, &nonce, method, path, None)
            .expect("test message should be valid");

        // Check magic (16 bytes)
        assert_eq!(&msg[0..14], b"CONTINUUM-AUTH");
        assert_eq!(&msg[14..16], &[0x00, 0x00]);

        // Check version (1 byte)
        assert_eq!(msg[16], 0x01);

        // Check timestamp (8 bytes, big-endian)
        assert_eq!(&msg[17..25], &timestamp.to_be_bytes());

        // Check nonce (16 bytes)
        assert_eq!(&msg[25..41], &nonce);

        // Check method length (1 byte) and method
        assert_eq!(msg[41], 3); // "GET".len()
        assert_eq!(&msg[42..45], b"GET");

        // Check path length (2 bytes, big-endian) and path
        assert_eq!(&msg[45..47], &9u16.to_be_bytes()); // "/api/test".len()
        assert_eq!(&msg[47..56], b"/api/test");

        // Check body hash flag (no body)
        assert_eq!(msg[56], 0x00);

        // Total length check
        assert_eq!(msg.len(), 57);
    }

    #[test]
    fn test_canonical_message_with_body_hash() {
        let timestamp = 1700000000i64;
        let nonce = [0x22u8; 16];
        let method = "POST";
        let path = "/api/data";
        let body_hash = [0xaa; 32];

        let msg = build_canonical_message(timestamp, &nonce, method, path, Some(&body_hash))
            .expect("test message should be valid");

        // Find the body hash flag position (after path)
        let method_len = method.len();
        let path_len = path.len();
        let body_flag_pos = 16 + 1 + 8 + 16 + 1 + method_len + 2 + path_len;

        assert_eq!(msg[body_flag_pos], 0x01);
        assert_eq!(&msg[body_flag_pos + 1..body_flag_pos + 33], &body_hash);
    }

    #[test]
    fn test_tampered_message_rejected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "GET".to_string();
        let path = "/api/secure".to_string();

        // Sign the original message
        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, None)
            .expect("test message should be valid");
        let signature = private_key.sign(&message);

        // Create proof but with tampered path
        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path: "/api/admin".to_string(), // Tampered!
            body_hash: None,
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::InvalidSignature);
    }

    // ==================== ADVERSARIAL TESTS ====================

    #[test]
    fn test_timestamp_at_exact_boundary_accepted() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let max_skew = 30i64;

        // Timestamp exactly at the past boundary (now - max_skew)
        let proof = create_test_proof(&private_key, now - max_skew);
        let result = verify_v1(&proof, now, max_skew, &allowlist, &replay_cache);
        assert!(result.is_ok(), "Timestamp at past boundary should be accepted");

        // Timestamp exactly at the future boundary (now + max_skew)
        let proof2 = create_test_proof(&private_key, now + max_skew);
        let result2 = verify_v1(&proof2, now, max_skew, &allowlist, &replay_cache);
        assert!(result2.is_ok(), "Timestamp at future boundary should be accepted");
    }

    #[test]
    fn test_timestamp_one_second_beyond_boundary_rejected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let max_skew = 30i64;

        // Timestamp one second beyond past boundary
        let proof = create_test_proof(&private_key, now - max_skew - 1);
        let result = verify_v1(&proof, now, max_skew, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::TimestampExpired);

        // Timestamp one second beyond future boundary
        let proof2 = create_test_proof(&private_key, now + max_skew + 1);
        let result2 = verify_v1(&proof2, now, max_skew, &allowlist, &replay_cache);
        assert_eq!(result2.unwrap_err(), AuthnError::TimestampInFuture);
    }

    #[test]
    fn test_extreme_timestamps_rejected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;

        // Unix epoch (0)
        let proof_epoch = create_test_proof(&private_key, 0);
        let result = verify_v1(&proof_epoch, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::TimestampExpired);

        // i64::MAX
        let proof_max = create_test_proof(&private_key, i64::MAX);
        let result_max = verify_v1(&proof_max, now, 30, &allowlist, &replay_cache);
        assert_eq!(result_max.unwrap_err(), AuthnError::TimestampInFuture);

        // i64::MIN
        let proof_min = create_test_proof(&private_key, i64::MIN);
        let result_min = verify_v1(&proof_min, now, 30, &allowlist, &replay_cache);
        assert_eq!(result_min.unwrap_err(), AuthnError::TimestampExpired);
    }

    #[test]
    fn test_body_hash_tampering_rejected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "POST".to_string();
        let path = "/api/tasks".to_string();
        let original_body_hash = [0xaa; 32];

        // Sign with original body hash
        let message =
            build_canonical_message(now, nonce.as_bytes(), &method, &path, Some(&original_body_hash))
                .expect("test message should be valid");
        let signature = private_key.sign(&message);

        // Create proof with tampered body hash
        let tampered_body_hash = [0xbb; 32];
        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: Some(tampered_body_hash), // Tampered!
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::InvalidSignature);
    }

    #[test]
    fn test_adding_body_hash_when_none_signed_rejected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "GET".to_string();
        let path = "/api/data".to_string();

        // Sign without body hash
        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, None)
            .expect("test message should be valid");
        let signature = private_key.sign(&message);

        // Create proof WITH body hash (wasn't signed)
        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: Some([0xcc; 32]), // Added body hash!
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::InvalidSignature);
    }

    #[test]
    fn test_removing_body_hash_when_one_signed_rejected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "POST".to_string();
        let path = "/api/data".to_string();
        let body_hash = [0xdd; 32];

        // Sign WITH body hash
        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, Some(&body_hash))
            .expect("test message should be valid");
        let signature = private_key.sign(&message);

        // Create proof WITHOUT body hash (was signed with one)
        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: None, // Removed body hash!
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::InvalidSignature);
    }

    #[test]
    fn test_method_tampering_rejected() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "GET".to_string();
        let path = "/api/data".to_string();

        // Sign with GET
        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, None)
            .expect("test message should be valid");
        let signature = private_key.sign(&message);

        // Create proof with DELETE
        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method: "DELETE".to_string(), // Tampered!
            path,
            body_hash: None,
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::InvalidSignature);
    }

    #[test]
    fn test_empty_method_and_path() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = String::new(); // Empty method
        let path = String::new(); // Empty path

        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, None)
            .expect("test message should be valid");
        let signature = private_key.sign(&message);

        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: None,
        };

        // Should still verify successfully (empty strings are valid)
        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert!(result.is_ok());
    }

    #[test]
    fn test_long_method_and_path() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "A".repeat(255); // Max method length (1 byte length)
        let path = "B".repeat(65535); // Max path length (2 byte length)

        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, None)
            .expect("test message should be valid");
        let signature = private_key.sign(&message);

        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: None,
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unicode_in_method_and_path() {
        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let public_key = private_key.public_key();
        let nonce = RandomNonce::new();
        let method = "方法".to_string(); // Chinese for "method"
        let path = "/api/路径/数据".to_string(); // Chinese path

        let message = build_canonical_message(now, nonce.as_bytes(), &method, &path, None)
            .expect("test message should be valid");
        let signature = private_key.sign(&message);

        let proof = AuthProof {
            public_key,
            signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: None,
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verification_order_allowlist_before_signature() {
        // This test verifies that allowlist is checked before signature verification
        // to prevent DoS attacks via expensive signature operations

        let private_key = PrivateKey::generate();
        // Don't add to allowlist!
        let allowlist = TestAllowlist::new();
        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let proof = create_test_proof(&private_key, now);

        // Should fail with NotAllowlisted, not InvalidSignature
        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(result.unwrap_err(), AuthnError::NotAllowlisted);
    }

    #[test]
    fn test_method_too_long_rejected() {
        let timestamp = 1700000000i64;
        let nonce = [0x33u8; 16];
        let method = "A".repeat(256); // Exceeds max of 255
        let path = "/api/test";

        let result = build_canonical_message(timestamp, &nonce, &method, path, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthnError::MalformedProof);
    }

    #[test]
    fn test_path_too_long_rejected() {
        let timestamp = 1700000000i64;
        let nonce = [0x44u8; 16];
        let method = "GET";
        let path = "A".repeat(65536); // Exceeds max of 65535

        let result = build_canonical_message(timestamp, &nonce, method, &path, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthnError::MalformedProof);
    }

    // ==================== DOMAIN SEPARATION TESTS ====================

    #[test]
    fn test_domain_separation_prevents_enrollment_signature_reuse() {
        // This test verifies that signatures created for enrollment tokens
        // cannot be used for authentication proofs, and vice versa.
        //
        // Attack scenario: An attacker intercepts an enrollment token and
        // tries to extract its signature to forge an authentication proof.

        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let nonce_bytes = [0x55u8; 16];
        let method = "GET".to_string();
        let path = "/api/test".to_string();

        // Create a signature using the ENROLLMENT domain prefix
        // (simulating extraction from an enrollment token)
        let enrollment_prefix = b"CONTINUUM-ENROLL-v1:";
        let mut enrollment_style_message = Vec::new();
        enrollment_style_message.extend_from_slice(enrollment_prefix);
        enrollment_style_message.extend_from_slice(&now.to_be_bytes());
        enrollment_style_message.extend_from_slice(&nonce_bytes);

        let enrollment_signature = private_key.sign(&enrollment_style_message);

        // Try to use this enrollment signature for authentication
        let proof = AuthProof {
            public_key: private_key.public_key(),
            signature: enrollment_signature,
            timestamp: now,
            nonce: RandomNonce::from_bytes(nonce_bytes),
            method: method.clone(),
            path: path.clone(),
            body_hash: None,
        };

        // The enrollment signature MUST be rejected for authentication
        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(
            result.unwrap_err(),
            AuthnError::InvalidSignature,
            "Enrollment signature should not work for authentication"
        );
    }

    #[test]
    fn test_domain_separation_auth_magic_is_required() {
        // Verify that the AUTH_MAGIC prefix is actually checked
        // by showing that a signature without it fails

        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let nonce = RandomNonce::new();
        let method = "GET".to_string();
        let path = "/api/test".to_string();

        // Sign the data WITHOUT the CONTINUUM-AUTH magic prefix
        // (simulating a signature from a different protocol)
        let mut message_without_magic = Vec::new();
        message_without_magic.push(0x01); // version
        message_without_magic.extend_from_slice(&now.to_be_bytes());
        message_without_magic.extend_from_slice(nonce.as_bytes());
        message_without_magic.push(method.len() as u8);
        message_without_magic.extend_from_slice(method.as_bytes());
        message_without_magic.extend_from_slice(&(path.len() as u16).to_be_bytes());
        message_without_magic.extend_from_slice(path.as_bytes());
        message_without_magic.push(0x00); // no body

        let bad_signature = private_key.sign(&message_without_magic);

        let proof = AuthProof {
            public_key: private_key.public_key(),
            signature: bad_signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: None,
        };

        // Must be rejected because the magic prefix was not included
        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(
            result.unwrap_err(),
            AuthnError::InvalidSignature,
            "Signature without AUTH_MAGIC prefix should be rejected"
        );
    }

    #[test]
    fn test_domain_separation_different_magic_rejected() {
        // Verify that a different magic prefix is rejected

        let private_key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&private_key.public_key());

        let mut allowlist = TestAllowlist::new();
        allowlist.allow(&fingerprint);

        let replay_cache = TestReplayCache::new();

        let now = 1700000000i64;
        let nonce = RandomNonce::new();
        let method = "POST".to_string();
        let path = "/api/data".to_string();

        // Sign with a DIFFERENT magic prefix (like a hypothetical v2 or different protocol)
        let wrong_magic = b"CONTINUUM-AUTH\x00\x01"; // Different padding byte
        let mut message = Vec::new();
        message.extend_from_slice(wrong_magic);
        message.push(0x01); // version
        message.extend_from_slice(&now.to_be_bytes());
        message.extend_from_slice(nonce.as_bytes());
        message.push(method.len() as u8);
        message.extend_from_slice(method.as_bytes());
        message.extend_from_slice(&(path.len() as u16).to_be_bytes());
        message.extend_from_slice(path.as_bytes());
        message.push(0x00); // no body

        let bad_signature = private_key.sign(&message);

        let proof = AuthProof {
            public_key: private_key.public_key(),
            signature: bad_signature,
            timestamp: now,
            nonce,
            method,
            path,
            body_hash: None,
        };

        let result = verify_v1(&proof, now, 30, &allowlist, &replay_cache);
        assert_eq!(
            result.unwrap_err(),
            AuthnError::InvalidSignature,
            "Signature with wrong magic prefix should be rejected"
        );
    }

    #[test]
    fn test_canonical_message_includes_domain_separation() {
        // Verify that build_canonical_message produces a message
        // that starts with the correct domain prefix

        let timestamp = 1700000000i64;
        let nonce = [0x66u8; 16];
        let method = "GET";
        let path = "/test";

        let message = build_canonical_message(timestamp, &nonce, method, path, None).unwrap();

        // The message MUST start with the AUTH_MAGIC
        assert_eq!(
            &message[0..14],
            b"CONTINUUM-AUTH",
            "Message should start with CONTINUUM-AUTH"
        );
        assert_eq!(
            &message[14..16],
            &[0x00, 0x00],
            "Magic should be followed by null padding"
        );

        // Version byte should follow the magic
        assert_eq!(message[16], 0x01, "Version should be 0x01");
    }
}
