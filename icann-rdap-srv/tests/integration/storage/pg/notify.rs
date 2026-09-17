use std::time::Duration;

use chrono::{TimeZone, Utc};
use icann_rdap_srv::storage::pg::notify;
use icann_rdap_srv::storage::timestamp::DbTimestamp;
use sqlx::Pool;
use sqlx::postgres::Postgres;

/// Rebuild `base_url` so it points at the named database. Only the URL path (the
/// database component) changes; scheme, credentials, host and port are preserved.
fn url_for_database(base_url: &str, db_name: &str) -> String {
    let scheme_end = base_url.find("://").expect("well-formed url has a scheme") + 3;
    let authority_end = base_url[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base_url.len());
    format!("{}/{}", &base_url[..authority_end], db_name)
}

/// Live LISTEN/NOTIFY round-trip: a background [`notify::run`] task subscribes to the
/// `rdap_db_update` channel, and updating `last_rdap_update` from another connection
/// stamps the shared [`DbTimestamp`] with the new (whole-second) UTC time.
#[sqlx::test]
async fn notify_listener_stamps_shared_timestamp_on_db_update(db: Pool<Postgres>) {
    // GIVEN a single seeded row (the trigger only fires on UPDATE, not INSERT).
    sqlx::query(
        "INSERT INTO last_rdap_update (id, last_db_update) VALUES (1, now()) \
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&db)
    .await
    .expect("seeding last_rdap_update row");

    // The `#[sqlx::test]` pool points at an isolated per-test database, while the
    // DATABASE_URL env var still names the master DB. Point the listener at the exact
    // database under test so it subscribes where we fire the trigger.
    let base_url = std::env::var("DATABASE_URL").expect("DATABASE_URL set by the test ctor");
    let db_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&db)
        .await
        .expect("current_database query");
    let listener_url = url_for_database(&base_url, &db_name);

    let ts = DbTimestamp::new();
    assert!(
        ts.get().is_none(),
        "a fresh timestamp reports no update yet"
    );
    tokio::spawn(notify::run(listener_url, ts.clone()));

    // WHEN the row is updated, the trigger emits a NOTIFY carrying the new UTC time.
    // We re-issue the update on an interval because Postgres does not queue
    // notifications for a session that has not yet LISTENed; once the listener is
    // subscribed, the next update lands.
    let expected = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        sqlx::query("UPDATE last_rdap_update SET last_db_update = $1 WHERE id = 1")
            .bind(expected)
            .execute(&db)
            .await
            .expect("updating last_rdap_update");

        if ts.get() == Some(expected) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "listener did not stamp the shared timestamp in time"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // THEN the shared handle (and every clone of it) reflects the received time.
    assert_eq!(ts.get(), Some(expected));
}
