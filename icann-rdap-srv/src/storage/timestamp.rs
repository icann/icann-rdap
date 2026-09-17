use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
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

    /// Record an explicit time as the last data update.
    pub fn mark(&self, value: DateTime<Utc>) {
        // Pre-epoch instants yield negative nanos; `.max(0)` collapses those — and any
        // out-of-range `None` from `timestamp_nanos_opt()` — to 0 = "never updated".
        let nanos = value.timestamp_nanos_opt().unwrap_or(0).max(0) as u64;
        self.0.store(nanos, Ordering::Relaxed);
    }

    /// Record the current time as the last data update.
    pub fn mark_now(&self) {
        self.mark(Utc::now());
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

    #[test]
    fn mark_stores_an_explicit_value() {
        // GIVEN a fresh timestamp
        let ts = DbTimestamp::new();

        // WHEN marked with a specific instant
        let value = Utc.with_ymd_and_hms(2026, 9, 15, 12, 30, 45).unwrap();
        ts.mark(value);

        // THEN that exact instant is read back
        assert_eq!(ts.get(), Some(value));
    }

    #[test]
    fn mark_is_visible_to_clones() {
        // GIVEN a timestamp and a clone sharing the same underlying value
        let ts = DbTimestamp::new();
        let clone = ts.clone();

        // WHEN one handle records an explicit time
        let value = Utc.with_ymd_and_hms(2026, 9, 15, 0, 0, 0).unwrap();
        ts.mark(value);

        // THEN both handles observe the same value (shared, not copied)
        assert_eq!(ts.get(), Some(value));
        assert_eq!(clone.get(), Some(value));
    }

    #[test]
    fn mark_pre_epoch_clamps_to_never() {
        // GIVEN a fresh timestamp
        let ts = DbTimestamp::new();

        // WHEN marked with a pre-epoch instant (negative nanos since epoch)
        let value = Utc.with_ymd_and_hms(1969, 12, 31, 23, 59, 59).unwrap();
        ts.mark(value);

        // THEN it clamps to the "never updated" state
        assert_eq!(ts.get(), None);
    }

    #[test]
    fn mark_exact_epoch_clamps_to_never() {
        // GIVEN a fresh timestamp
        let ts = DbTimestamp::new();

        // WHEN marked with the exact epoch (0 nanos, the "never updated" sentinel)
        let value = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        ts.mark(value);

        // THEN it is indistinguishable from "never updated"
        assert_eq!(ts.get(), None);
    }

    #[test]
    fn mark_preserves_sub_second_precision() {
        // GIVEN a fresh timestamp
        let ts = DbTimestamp::new();

        // WHEN marked with sub-second (nanosecond) precision
        let value = Utc
            .with_ymd_and_hms(2026, 9, 15, 12, 30, 45)
            .unwrap()
            .checked_add_signed(chrono::Duration::nanoseconds(123_456_789))
            .unwrap();
        ts.mark(value);

        // THEN nanosecond precision is preserved on read-back
        assert_eq!(ts.get(), Some(value));
    }
}
