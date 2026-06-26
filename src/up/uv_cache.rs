use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A single cached UV proof: use-once, time-limited.
struct CachedProof {
    created: Instant,
}

/// Cache key: (CTAPHID channel ID, RP ID).
type CacheKey = (u32, String);

/// Caches a user verification proof for a single subsequent operation
/// on the same CTAPHID channel and relying party.
///
/// The proof is:
/// - **use-once**: consumed on first match, then gone
/// - **time-limited**: expires after TTL even if unconsumed (janitor)
/// - **source-bound**: only matches the exact (CID, RP ID) pair
pub struct UvCache {
    entries: Mutex<HashMap<CacheKey, CachedProof>>,
    ttl: Duration,
}

impl UvCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Store a proof after successful UV for this (cid, rp_id).
    pub fn store(&self, cid: u32, rp_id: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            // Garbage-collect expired entries while we're here
            let now = Instant::now();
            entries.retain(|_, v| now.duration_since(v.created) < self.ttl);

            let key = (cid, rp_id.to_string());
            tracing::debug!(
                cid = format!("{cid:#010x}"),
                rp_id = rp_id,
                ttl_secs = self.ttl.as_secs(),
                "UV proof cached"
            );
            entries.insert(key, CachedProof { created: now });
        }
    }

    /// Try to consume a cached proof for this (cid, rp_id).
    /// Returns true if a valid, unexpired proof was found and consumed.
    pub fn consume(&self, cid: u32, rp_id: &str) -> bool {
        if let Ok(mut entries) = self.entries.lock() {
            let key = (cid, rp_id.to_string());
            if let Some(proof) = entries.remove(&key) {
                let age = Instant::now().duration_since(proof.created);
                if age < self.ttl {
                    tracing::info!(
                        cid = format!("{cid:#010x}"),
                        rp_id = rp_id,
                        age_ms = age.as_millis() as u64,
                        "UV proof consumed from cache"
                    );
                    return true;
                }
                tracing::debug!(
                    cid = format!("{cid:#010x}"),
                    rp_id = rp_id,
                    age_ms = age.as_millis() as u64,
                    "UV proof expired, discarding"
                );
            }
        }
        false
    }
}
