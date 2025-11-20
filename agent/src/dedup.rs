//! Agent-side event deduplication
//!
//! Filters duplicate events within a configurable time window before they
//! are sent to the server.  This reduces bandwidth and prevents duplicate
//! alerts from transient collector re-reads (e.g. Windows EventLog cursor
//! replays, FIM double-fires, Suricata eve.json retries).
//!
//! # Configuration
//!
//! * `PERCEPTA_DEDUP_WINDOW_SECS`  — dedup window in seconds (default 60, 0 = disabled)
//! * `PERCEPTA_DEDUP_CAPACITY`     — max tracked hashes   (default 50 000)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::debug;

use crate::percepta::Event;

/// Tracks recently-seen event hashes to suppress duplicates.
pub struct EventDedup {
    /// hash → last-seen timestamp
    seen: HashMap<String, Instant>,
    /// How long a hash is considered "recently seen" (normal operation)
    window: std::time::Duration,
    /// Extended window used during surge/flood mode
    window_surge: std::time::Duration,
    /// Whether we are currently in flood-surge mode
    in_surge: bool,
    /// Max entries before eviction
    capacity: usize,
    /// Running count of suppressed duplicates (atomic for cheap reads from GUI)
    suppressed: AtomicU64,
    /// Enabled flag (false when window == 0)
    enabled: bool,
}

impl EventDedup {
    /// Create from environment variables / defaults.
    pub fn from_env() -> Self {
        let window_secs: u64 = std::env::var("PERCEPTA_DEDUP_WINDOW_SECS")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(60);

        // Surge multiplier: how many times longer the dedup window is during flood mode.
        // Env: PERCEPTA_DEDUP_SURGE_MULTIPLIER (default 5, so 60s → 300s)
        let surge_mult: u64 = std::env::var("PERCEPTA_DEDUP_SURGE_MULTIPLIER")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(5)
            .clamp(2, 20);

        let capacity: usize = std::env::var("PERCEPTA_DEDUP_CAPACITY")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(50_000);

        Self {
            seen: HashMap::with_capacity(capacity.min(8192)),
            window: std::time::Duration::from_secs(window_secs),
            window_surge: std::time::Duration::from_secs((window_secs * surge_mult).min(300)),
            in_surge: false,
            capacity,
            suppressed: AtomicU64::new(0),
            enabled: window_secs > 0,
        }
    }

    /// Engage flood-surge mode: extend the dedup window to suppress repeated
    /// attack-pattern events that would otherwise saturate the server pipeline.
    pub fn enter_surge(&mut self) {
        self.in_surge = true;
    }

    /// Return to normal dedup window after surge conditions subside.
    pub fn exit_surge(&mut self) {
        self.in_surge = false;
    }

    /// Returns `true` if this event has been seen within the dedup window.
    pub fn is_duplicate(&mut self, event: &Event) -> bool {
        if !self.enabled {
            return false;
        }

        let hash = &event.hash;
        if hash.is_empty() {
            return false; // can't dedup without a hash
        }

        let now = Instant::now();

        // Use extended window during flood/surge mode to aggressively suppress
        // repetitive attack-pattern events (e.g. brute-force, port-scan noise).
        let effective_window = if self.in_surge { self.window_surge } else { self.window };

        // Check if we've seen this hash recently
        if let Some(last_seen) = self.seen.get(hash) {
            if now.duration_since(*last_seen) < effective_window {
                self.suppressed.fetch_add(1, Ordering::Relaxed);
                crate::GLOBAL_DEDUP_SAVED.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        // Evict oldest entries if at capacity
        if self.seen.len() >= self.capacity {
            self.evict_expired(now);
            // If still over capacity after eviction, drop ~25% oldest
            if self.seen.len() >= self.capacity {
                self.evict_oldest_quarter(now);
            }
        }

        self.seen.insert(hash.clone(), now);
        false
    }

    /// Filter a batch of events, returning only non-duplicates.
    pub fn filter_batch(&mut self, events: Vec<Event>) -> Vec<Event> {
        if !self.enabled {
            return events;
        }

        let before = events.len();
        let result: Vec<Event> = events
            .into_iter()
            .filter(|e| !self.is_duplicate(e))
            .collect();
        let dropped = before - result.len();
        if dropped > 0 {
            debug!("Dedup: {} duplicates suppressed ({}->{} events)", dropped, before, result.len());
        }
        result
    }

    /// Total number of suppressed duplicates since agent start.
    pub fn suppressed_count(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }

    /// Current number of tracked hashes.
    #[allow(dead_code)]
    pub fn tracked_count(&self) -> usize {
        self.seen.len()
    }

    /// Remove all entries that have expired past the (effective) window.
    fn evict_expired(&mut self, now: Instant) {
        let effective_window = if self.in_surge { self.window_surge } else { self.window };
        self.seen.retain(|_, ts| now.duration_since(*ts) < effective_window);
    }

    /// Drop the oldest ~25% of entries regardless of expiry.
    fn evict_oldest_quarter(&mut self, _now: Instant) {
        let target = self.capacity / 4;
        if self.seen.len() <= target {
            return;
        }

        let mut entries: Vec<(String, Instant)> = self.seen.drain().collect();
        entries.sort_by_key(|(_, ts)| *ts);
        // Keep the newest 75%
        let keep_start = entries.len().saturating_sub(self.capacity * 3 / 4);
        self.seen = entries.into_iter().skip(keep_start).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::percepta::Event;

    fn make_event(hash: &str) -> Event {
        Event {
            hash: hash.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn duplicate_within_window_is_detected() {
        let mut dedup = EventDedup {
            seen: HashMap::new(),
            window: std::time::Duration::from_secs(60),
            window_surge: std::time::Duration::from_secs(120),
            in_surge: false,
            capacity: 1000,
            suppressed: AtomicU64::new(0),
            enabled: true,
        };

        let e1 = make_event("abc123");
        assert!(!dedup.is_duplicate(&e1), "first occurrence should NOT be dup");
        assert!(dedup.is_duplicate(&e1), "second occurrence SHOULD be dup");
        assert_eq!(dedup.suppressed_count(), 1);
    }

    #[test]
    fn different_hashes_are_not_duplicates() {
        let mut dedup = EventDedup {
            seen: HashMap::new(),
            window: std::time::Duration::from_secs(60),
            window_surge: std::time::Duration::from_secs(120),
            in_surge: false,
            capacity: 1000,
            suppressed: AtomicU64::new(0),
            enabled: true,
        };

        assert!(!dedup.is_duplicate(&make_event("aaa")));
        assert!(!dedup.is_duplicate(&make_event("bbb")));
        assert!(!dedup.is_duplicate(&make_event("ccc")));
        assert_eq!(dedup.suppressed_count(), 0);
    }

    #[test]
    fn empty_hash_is_never_duplicate() {
        let mut dedup = EventDedup {
            seen: HashMap::new(),
            window: std::time::Duration::from_secs(60),
            window_surge: std::time::Duration::from_secs(120),
            in_surge: false,
            capacity: 1000,
            suppressed: AtomicU64::new(0),
            enabled: true,
        };

        let e = make_event("");
        assert!(!dedup.is_duplicate(&e));
        assert!(!dedup.is_duplicate(&e));
    }

    #[test]
    fn disabled_dedup_passes_all() {
        let mut dedup = EventDedup {
            seen: HashMap::new(),
            window: std::time::Duration::from_secs(0),
            window_surge: std::time::Duration::from_secs(0),
            in_surge: false,
            capacity: 1000,
            suppressed: AtomicU64::new(0),
            enabled: false,
        };

        let e = make_event("abc");
        assert!(!dedup.is_duplicate(&e));
        assert!(!dedup.is_duplicate(&e));
    }

    #[test]
    fn capacity_eviction_works() {
        let mut dedup = EventDedup {
            seen: HashMap::new(),
            window: std::time::Duration::from_secs(3600),
            window_surge: std::time::Duration::from_secs(7200),
            in_surge: false,
            capacity: 10,
            suppressed: AtomicU64::new(0),
            enabled: true,
        };

        // Fill to capacity
        for i in 0..10 {
            dedup.is_duplicate(&make_event(&format!("h{}", i)));
        }
        assert_eq!(dedup.tracked_count(), 10);

        // Adding one more should trigger eviction
        dedup.is_duplicate(&make_event("overflow"));
        assert!(dedup.tracked_count() <= 10, "should have evicted");
    }

    #[test]
    fn filter_batch_removes_duplicates() {
        let mut dedup = EventDedup {
            seen: HashMap::new(),
            window: std::time::Duration::from_secs(60),
            window_surge: std::time::Duration::from_secs(120),
            in_surge: false,
            capacity: 1000,
            suppressed: AtomicU64::new(0),
            enabled: true,
        };

        let batch = vec![
            make_event("a"),
            make_event("b"),
            make_event("a"), // dup
            make_event("c"),
            make_event("b"), // dup
        ];

        let result = dedup.filter_batch(batch);
        assert_eq!(result.len(), 3);
        assert_eq!(dedup.suppressed_count(), 2);
    }
}
