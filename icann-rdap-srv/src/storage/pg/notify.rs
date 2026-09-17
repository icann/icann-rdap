//! LISTEN/NOTIFY listener for RDAP database update events.
//!
//! A trigger on the `last_rdap_update` table (see the postgres migrations) emits a
//! notification on [`CHANNEL`] whose payload is an RFC 3339 UTC timestamp string
//! (e.g. `2026-05-01T10:00:00Z`). This module consumes those notifications and
//! records them in the store's shared [`DbTimestamp`], which request handlers read
//! to stamp responses with a live "last update of RDAP database" event.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::postgres::{PgListener, PgNotification};
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::{error::RdapServerError, storage::timestamp::DbTimestamp};

/// The Postgres notification channel the `last_rdap_update` trigger emits on.
pub const CHANNEL: &str = "rdap_db_update";

const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Parse an RFC 3339 UTC timestamp payload (e.g. `2026-05-01T10:00:00Z`).
///
/// Pure and DB-free; returns `None` for anything that is not a valid RFC 3339 date-time.
pub fn parse_payload(payload: &str) -> Option<DateTime<Utc>> {
    // chrono's `FromStr` impl for `DateTime<Utc>` is its RFC 3339 parser.
    payload.parse::<DateTime<Utc>>().ok()
}

/// Run the listener forever, reconnecting with capped exponential backoff on error.
///
/// Backoff starts at 250 ms and doubles per consecutive failure, capped at 30 s; it resets
/// to 250 ms after a clean session (a `listen_once` that ended without an error).
pub async fn run(db_url: String, db_timestamp: DbTimestamp) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match listen_once(&db_url, &db_timestamp).await {
            Ok(()) => backoff = INITIAL_BACKOFF,
            Err(err) => {
                warn!(error = %err, "rdap_db_update listener failed; reconnecting");
                sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Connect a [`PgListener`], subscribe to [`CHANNEL`], and dispatch messages until the
/// connection fails. Returns `Err` on any listener error so the outer loop reconnects.
async fn listen_once(db_url: &str, ts: &DbTimestamp) -> Result<(), RdapServerError> {
    let mut listener = PgListener::connect(db_url).await?;
    listener.listen(CHANNEL).await?;
    debug!(
        channel = CHANNEL,
        "listening for rdap_db_update notifications"
    );
    loop {
        match listener.recv().await {
            Ok(msg) => on_message(&msg, ts),
            Err(err) => return Err(err.into()),
        }
    }
}

fn on_message(msg: &PgNotification, ts: &DbTimestamp) {
    match parse_payload(msg.payload()) {
        Some(dt) => {
            debug!(?dt, "rdap database update notification received");
            ts.mark(dt);
        }
        None => warn!(
            payload = msg.payload(),
            "unparseable rdap_db_update payload"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parse_payload_parses_valid_rfc3339() {
        // GIVEN a valid RFC 3339 UTC timestamp with an explicit offset
        let payload = "2026-05-01T10:00:00+00:00";

        // WHEN parsed
        let dt = parse_payload(payload);

        // THEN it matches the expected instant
        assert_eq!(
            dt,
            Some(Utc.with_ymd_and_hms(2026, 5, 1, 10, 0, 0).unwrap())
        );
    }

    #[test]
    fn parse_payload_parses_trailing_z() {
        // GIVEN a valid RFC 3339 UTC timestamp with trailing 'Z' (as emitted by the DB trigger)
        let payload = "2026-05-01T10:00:00Z";

        // WHEN parsed
        let dt = parse_payload(payload);

        // THEN it matches the expected instant
        assert_eq!(
            dt,
            Some(Utc.with_ymd_and_hms(2026, 5, 1, 10, 0, 0).unwrap())
        );
    }

    #[test]
    fn parse_payload_rejects_garbage() {
        // GIVEN a payload that is not an RFC 3339 date-time
        let payload = "not-a-timestamp";

        // WHEN parsed
        let dt = parse_payload(payload);

        // THEN it is None
        assert_eq!(dt, None);
    }
}
