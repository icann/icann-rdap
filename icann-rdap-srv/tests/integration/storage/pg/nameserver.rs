use icann_rdap_common::response::{Nameserver, Rfc9083Error};
use icann_rdap_srv::storage::{TxHandle, data::NameserverId, pg::tx::PgTx};
use sqlx::Pool;
use sqlx::postgres::Postgres;

#[sqlx::test]
async fn add_nameserver_inserts_row(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns1.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .expect("building nameserver"),
    )
    .await
    .expect("adding nameserver to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let ldh: Option<String> =
        sqlx::query_scalar("SELECT content->>'ldhName' FROM nameserver WHERE ldh_name = $1")
            .bind("ns1.example")
            .fetch_one(&db)
            .await
            .expect("nameserver row exists");
    assert_eq!(ldh.as_deref(), Some("ns1.example"));
}

#[sqlx::test]
async fn add_nameserver_duplicate_is_noop(db: Pool<Postgres>) {
    // GIVEN
    let nameserver = Nameserver::builder()
        .ldh_name("ns1.example")
        .addresses(vec!["192.0.2.1".to_string()])
        .build()
        .expect("building nameserver");
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_nameserver(&nameserver)
        .await
        .expect("adding nameserver to tx (1)");
    tx.add_nameserver(&nameserver)
        .await
        .expect("adding nameserver to tx (2)");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nameserver WHERE ldh_name = $1")
        .bind("ns1.example")
        .fetch_one(&db)
        .await
        .expect("count query");
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn add_nameserver_err_stores_error_response(db: Pool<Postgres>) {
    // GIVEN
    let id = NameserverId::builder().ldh_name("ns1.example").build();
    let error = Rfc9083Error::redirect()
        .url("https://bar.example/rdap/nameserver/ns1.example")
        .build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_nameserver_err(&id, &error)
        .await
        .expect("adding nameserver error to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let code: Option<i64> = sqlx::query_scalar(
        "SELECT (content->>'errorCode')::bigint FROM nameserver WHERE ldh_name = $1",
    )
    .bind("ns1.example")
    .fetch_one(&db)
    .await
    .expect("nameserver error row exists");
    assert_eq!(code, Some(307));
}
