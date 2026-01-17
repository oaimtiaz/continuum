//! Server pinning (known_hosts) primitives.
//!
//! Provides server identity verification against a trust store.
//! With embedded fingerprints in enrollment tokens, TOFU is no longer used.

use crate::identity::Fingerprint;

/// Result of checking a server's fingerprint against known hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustDecision {
    /// Server fingerprint matches stored value.
    Trusted,
    /// Server not in known hosts - must use enrollment token.
    Unknown,
    /// Server fingerprint changed from stored value (potential MITM).
    Mismatch {
        /// The previously pinned fingerprint.
        expected: Fingerprint,
        /// The fingerprint presented by the server.
        actual: Fingerprint,
    },
}

/// Trait for server fingerprint storage (client-side).
///
/// Implementations should persist fingerprints to disk for
/// TOFU semantics to work across sessions.
pub trait KnownHosts: Send + Sync {
    /// Look up the expected fingerprint for a server address.
    ///
    /// Returns `None` if the server is not in known hosts.
    fn lookup(&self, address: &str) -> Option<Fingerprint>;
}

/// Evaluate trust for a server connection.
///
/// # Arguments
///
/// * `known_hosts` - The known hosts store to check against.
/// * `server_address` - The server's address (e.g., "example.com:443").
/// * `server_fingerprint` - The fingerprint presented by the server.
///
/// # Returns
///
/// A `TrustDecision` indicating whether the server should be trusted.
#[must_use]
pub fn evaluate_server_trust(
    known_hosts: &impl KnownHosts,
    server_address: &str,
    server_fingerprint: &Fingerprint,
) -> TrustDecision {
    match known_hosts.lookup(server_address) {
        Some(expected) if expected == *server_fingerprint => TrustDecision::Trusted,
        Some(expected) => TrustDecision::Mismatch {
            expected,
            actual: server_fingerprint.clone(),
        },
        None => TrustDecision::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PrivateKey;
    use std::collections::HashMap;

    struct TestKnownHosts(HashMap<String, Fingerprint>);

    impl TestKnownHosts {
        fn new() -> Self {
            Self(HashMap::new())
        }

        fn pin(&mut self, address: &str, fingerprint: &Fingerprint) {
            self.0.insert(address.to_string(), fingerprint.clone());
        }
    }

    impl KnownHosts for TestKnownHosts {
        fn lookup(&self, address: &str) -> Option<Fingerprint> {
            self.0.get(address).cloned()
        }
    }

    #[test]
    fn test_trusted_server() {
        let key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&key.public_key());

        let mut known_hosts = TestKnownHosts::new();
        known_hosts.pin("server.local", &fingerprint);

        let decision = evaluate_server_trust(&known_hosts, "server.local", &fingerprint);
        assert_eq!(decision, TrustDecision::Trusted);
    }

    #[test]
    fn test_unknown_server() {
        let key = PrivateKey::generate();
        let fingerprint = Fingerprint::from_public_key(&key.public_key());

        let known_hosts = TestKnownHosts::new();

        let decision = evaluate_server_trust(&known_hosts, "new-server.local", &fingerprint);
        assert_eq!(decision, TrustDecision::Unknown);
    }

    #[test]
    fn test_mitm_detected() {
        let real_key = PrivateKey::generate();
        let attacker_key = PrivateKey::generate();
        let real_fingerprint = Fingerprint::from_public_key(&real_key.public_key());
        let attacker_fingerprint = Fingerprint::from_public_key(&attacker_key.public_key());

        let mut known_hosts = TestKnownHosts::new();
        known_hosts.pin("server.local", &real_fingerprint);

        let decision = evaluate_server_trust(&known_hosts, "server.local", &attacker_fingerprint);
        assert!(matches!(decision, TrustDecision::Mismatch { .. }));
    }
}
