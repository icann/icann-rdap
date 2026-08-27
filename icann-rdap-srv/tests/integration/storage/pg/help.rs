use icann_rdap_common::response::Help;
use icann_rdap_srv::storage::{TxHandle, pg::tx::PgTx};
use sqlx::Pool;
use sqlx::postgres::Postgres;

#[sqlx::test]
async fn add_srv_help_inserts_default_host(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_srv_help(&Help::response().build(), None)
        .await
        .expect("adding srv help to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM srv_help WHERE host = $1")
        .bind("default")
        .fetch_one(&db)
        .await
        .expect("srv help row exists");
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn add_srv_help_inserts_explicit_host(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_srv_help(&Help::response().build(), Some("bar.example"))
        .await
        .expect("adding srv help to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM srv_help WHERE host = $1")
        .bind("bar.example")
        .fetch_one(&db)
        .await
        .expect("srv help row exists");
    assert_eq!(count, 1);
}
