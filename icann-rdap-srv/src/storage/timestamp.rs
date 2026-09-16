use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, TimeZone, Utc};

/// A lock-free, shareable record of when the store's data was last written.
///
/// The value is held as Unix-epoch nanoseconds in an [`AtomicU64`] so reads are cheap and
/// lock-free (any number of request handlers may read it concurrently), while writes happen
/// only on transaction commit. Cloning is a shallow [`Arc`] clone, so every handle — the
/// store itself and any in-flight transactions — observes the same value.
#[derive(Clone, Default)]
pub struct DbTimestamp(Arc<AtomicU64>);

impl DbTimestamp {
    /// Create a fresh timestamp that has not yet been updated.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the current time as the last data update.
    pub fn mark_now(&self) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.0.store(nanos, Ordering::Relaxed);
    }

    /// The last recorded data update time, or `None` if nothing has been committed yet.
    pub fn get(&self) -> Option<DateTime<Utc>> {
        let nanos = self.0.load(Ordering::Relaxed);
        // A zero value means "never updated"; a real 1970 timestamp is never stored.
        if nanos == 0 {
            return None;
        }
        let secs = (nanos / 1_000_000_000) as i64;
        let rem = (nanos % 1_000_000_000) as u32;
        Utc.timestamp_opt(secs, rem).single()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_timestamp_is_none_until_marked() {
        // GIVEN a fresh timestamp
        let ts = DbTimestamp::new();

        // WHEN read before any mark
        // THEN it reports no update yet
        assert!(ts.get().is_none());
    }

    #[test]
    fn mark_now_sets_a_time_visible_to_clones() {
        // GIVEN a timestamp and a clone sharing the same underlying value
        let ts = DbTimestamp::new();
        let clone = ts.clone();

        // WHEN one handle records "now"
        ts.mark_now();

        // THEN both handles observe the set value (shared, not copied)
        assert!(ts.get().is_some());
        assert!(clone.get().is_some());
    }
}
