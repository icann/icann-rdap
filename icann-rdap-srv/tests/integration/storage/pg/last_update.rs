use chrono::{DateTime, Utc};
use icann_rdap_common::response::Domain;
use icann_rdap_srv::config::CommonConfig;
use icann_rdap_srv::storage::StoreOps;
use sqlx::{Pool, Postgres};

use super::pg_store;

async fn last_db_update(db: &Pool<Postgres>) -> Option<DateTime<Utc>> {
    sqlx::query_scalar("SELECT last_db_update FROM last_rdap_update WHERE id = 1")
        .fetch_optional(db)
        .await
        .expect("querying last_rdap_update")
}

/// Committing a data transaction on a fresh database (no row yet) seeds the
/// `last_rdap_update` row, and the store's shared timestamp reflects it.
#[sqlx::test]
async fn commit_seeds_last_rdap_update_on_fresh_database(db: Pool<Postgres>) {
    // GIVEN a store over a database with no last_rdap_update row
    let store = pg_store(db.clone(), CommonConfig::default());
    assert!(store.last_data_update().is_none());
    assert!(last_db_update(&db).await.is_none());

    // WHEN a transaction built by the store commits data
    let mut tx = store.new_tx().await.expect("creating tx");
    tx.add_domain(&Domain::builder().ldh_name("upd.example").build())
        .await
        .expect("adding domain to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN the row exists with a recent timestamp...
    let stored = last_db_update(&db)
        .await
        .expect("last_rdap_update row missing after commit");
    let now = Utc::now();
    assert!(
        (stored - now).abs() < chrono::Duration::seconds(30),
        "stored timestamp {stored:?} is not recent (now: {now:?})"
    );

    // ...and the store's shared timestamp matches it exactly.
    assert_eq!(store.last_data_update(), Some(stored));
}

/// A truncate (reload) transaction updates the existing row in place instead of
/// duplicating or leaving it stale.
#[sqlx::test]
async fn truncate_commit_updates_last_rdap_update_in_place(db: Pool<Postgres>) {
    // GIVEN a row written by an earlier commit
    let store = pg_store(db.clone(), CommonConfig::default());
    let tx = store.new_tx().await.expect("creating seed tx");
    Box::new(tx).commit().await.expect("committing seed tx");
    let first = store
        .last_data_update()
        .expect("first commit recorded a timestamp");

    // WHEN a truncate (reload) transaction commits
    let mut tx = store.new_truncate_tx().await.expect("creating truncate tx");
    tx.add_domain(&Domain::builder().ldh_name("reload.example").build())
        .await
        .expect("adding domain to tx");
    Box::new(tx).commit().await.expect("committing truncate tx");

    // THEN the table still holds exactly one row, no older than the first commit
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM last_rdap_update")
        .fetch_one(&db)
        .await
        .expect("counting last_rdap_update rows");
    assert_eq!(rows, 1, "last_rdap_update must hold a single row");

    let second = store
        .last_data_update()
        .expect("second commit recorded a timestamp");
    assert!(
        second >= first,
        "timestamp regressed: {second:?} < {first:?}"
    );
    assert_eq!(last_db_update(&db).await, Some(second));
}
