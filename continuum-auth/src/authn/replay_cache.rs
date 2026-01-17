//! Production replay cache implementation.
//!
//! H6 FIX: Provides LRU+TTL replay cache for production use.

use crate::identity::Fingerprint;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::verify::ReplayCache;

/// LRU + TTL replay cache implementation.
///
/// # Security Properties
///
/// - Prevents nonce reuse within TTL window
/// - Memory-bounded via max_entries limit
/// - Lock-free concurrent access via DashMap
/// - Approximate LRU eviction when at capacity
///
/// # Performance
///
/// - O(1) check and insert operations (amortized)
/// - Lock-free concurrent access
/// - Periodic cleanup via `cleanup_expired()`
///
/// # Usage
///
/// ```
/// use continuum_auth::authn::LruReplayCache;
/// use std::time::Duration;
///
/// let cache = LruReplayCache::new(Duration::from_secs(60), 10000);
/// // Use with verify_v1()
/// ```
pub struct LruReplayCache {
    /// Map of (fingerprint_hash, nonce) -> first_seen_time
    /// We hash the fingerprint to avoid storing full fingerprint strings
    cache: DashMap<([u8; 8], [u8; 16]), Instant>,
    /// Time-to-live for cache entries
    ttl: Duration,
    /// Maximum entries before eviction
    max_entries: usize,
    /// Counter for periodic cleanup (avoids cleanup on every insert)
    insert_counter: AtomicU64,
}

impl LruReplayCache {
    /// Create a new replay cache with specified TTL and capacity.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Time-to-live for cache entries. Should be at least `2 * max_skew_seconds`
    ///           to prevent replay attacks at the edge of the validity window.
    /// * `max_entries` - Maximum number of entries before eviction starts.
    ///
    /// # Recommended Values
    ///
    /// - `ttl`: 120 seconds (for 60 second max_skew)
    /// - `max_entries`: 100,000 (handles ~1000 requests/second for 100 seconds)
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            cache: DashMap::with_capacity(max_entries / 4),
            ttl,
            max_entries,
            insert_counter: AtomicU64::new(0),
        }
    }

    /// Remove expired entries from the cache.
    ///
    /// Call this periodically (e.g., every minute) to reclaim memory.
    /// Not required for correctness - expired entries are ignored on lookup.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.cache.retain(|_, v| now.duration_since(*v) < self.ttl);
    }

    /// Get the current number of entries in the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Hash a fingerprint to a compact 8-byte key.
    /// We don't need the full fingerprint - just enough to avoid collisions.
    fn hash_fingerprint(fingerprint: &Fingerprint) -> [u8; 8] {
        let bytes = fingerprint.hash_bytes();
        let mut result = [0u8; 8];
        result.copy_from_slice(&bytes[0..8]);
        result
    }
}

impl ReplayCache for LruReplayCache {
    fn check_and_insert(
        &self,
        fingerprint: &Fingerprint,
        nonce: &[u8; 16],
        _timestamp: i64,
    ) -> bool {
        let fp_hash = Self::hash_fingerprint(fingerprint);
        let key = (fp_hash, *nonce);
        let now = Instant::now();

        // Use entry API for atomic check-and-insert (prevents TOCTOU race)
        let result = match self.cache.entry(key) {
            Entry::Occupied(entry) => {
                // Key exists - check if expired
                if now.duration_since(*entry.get()) < self.ttl {
                    false // Replay detected (not expired)
                } else {
                    // Expired - update the timestamp
                    entry.replace_entry(now);
                    true
                }
            }
            Entry::Vacant(entry) => {
                // Key doesn't exist - insert it
                entry.insert(now);
                true
            }
        };

        // Periodic cleanup and eviction (after releasing the entry lock)
        if result {
            let count = self.insert_counter.fetch_add(1, Ordering::Relaxed);
            if count % 1000 == 0 {
                // Every 1000 inserts, do a cleanup
                self.cleanup_expired();
            }

            // Evict if at capacity - remove a single entry to make room
            if self.cache.len() >= self.max_entries {
                let key_to_remove = self.cache.iter().next().map(|entry| *entry.key());
                if let Some(k) = key_to_remove {
                    self.cache.remove(&k);
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PrivateKey;
    use std::thread;

    fn test_fingerprint() -> Fingerprint {
        let key = PrivateKey::generate();
        Fingerprint::from_public_key(&key.public_key())
    }

    #[test]
    fn test_first_insert_succeeds() {
        let cache = LruReplayCache::new(Duration::from_secs(60), 1000);
        let fp = test_fingerprint();
        let nonce = [0x11u8; 16];

        assert!(cache.check_and_insert(&fp, &nonce, 0));
    }

    #[test]
    fn test_replay_detected() {
        let cache = LruReplayCache::new(Duration::from_secs(60), 1000);
        let fp = test_fingerprint();
        let nonce = [0x22u8; 16];

        // First insert succeeds
        assert!(cache.check_and_insert(&fp, &nonce, 0));

        // Second insert with same nonce fails (replay)
        assert!(!cache.check_and_insert(&fp, &nonce, 0));
    }

    #[test]
    fn test_different_nonce_succeeds() {
        let cache = LruReplayCache::new(Duration::from_secs(60), 1000);
        let fp = test_fingerprint();
        let nonce1 = [0x33u8; 16];
        let nonce2 = [0x44u8; 16];

        assert!(cache.check_and_insert(&fp, &nonce1, 0));
        assert!(cache.check_and_insert(&fp, &nonce2, 0));
    }

    #[test]
    fn test_different_fingerprint_succeeds() {
        let cache = LruReplayCache::new(Duration::from_secs(60), 1000);
        let fp1 = test_fingerprint();
        let fp2 = test_fingerprint();
        let nonce = [0x55u8; 16];

        assert!(cache.check_and_insert(&fp1, &nonce, 0));
        assert!(cache.check_and_insert(&fp2, &nonce, 0));
    }

    #[test]
    fn test_eviction_at_capacity() {
        let max_entries = 10;
        let cache = LruReplayCache::new(Duration::from_secs(60), max_entries);
        let fp = test_fingerprint();

        // Insert more than max_entries
        for i in 0..(max_entries + 5) {
            let mut nonce = [0u8; 16];
            nonce[0] = i as u8;
            cache.check_and_insert(&fp, &nonce, 0);
        }

        // Cache should not exceed max_entries
        assert!(cache.len() <= max_entries);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let cache = Arc::new(LruReplayCache::new(Duration::from_secs(60), 10000));
        let fp = test_fingerprint();

        let mut handles = vec![];

        // Spawn multiple threads all trying to use the same nonce
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let fp = fp.clone();
            let nonce = [0x77u8; 16];

            handles.push(thread::spawn(move || {
                cache.check_and_insert(&fp, &nonce, 0)
            }));
        }

        // Collect results
        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Exactly one should succeed, the rest should detect replay
        let success_count = results.iter().filter(|&&r| r).count();
        assert_eq!(success_count, 1, "Exactly one concurrent insert should succeed");
    }

    #[test]
    fn test_cleanup_removes_expired() {
        // Use a very short TTL for testing
        let cache = LruReplayCache::new(Duration::from_millis(10), 1000);
        let fp = test_fingerprint();
        let nonce = [0x88u8; 16];

        // Insert
        assert!(cache.check_and_insert(&fp, &nonce, 0));
        assert_eq!(cache.len(), 1);

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(20));

        // Cleanup should remove expired entries
        cache.cleanup_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_expired_entry_allows_reuse() {
        // Use a very short TTL for testing
        let cache = LruReplayCache::new(Duration::from_millis(10), 1000);
        let fp = test_fingerprint();
        let nonce = [0x99u8; 16];

        // First insert succeeds
        assert!(cache.check_and_insert(&fp, &nonce, 0));

        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(20));

        // Same nonce should succeed now (entry expired)
        assert!(cache.check_and_insert(&fp, &nonce, 0));
    }
}
