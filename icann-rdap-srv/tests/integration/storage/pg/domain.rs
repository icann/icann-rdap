use icann_rdap_common::response::{Domain, Rfc9083Error};
use icann_rdap_srv::storage::{TxHandle, data::DomainId, pg::tx::PgTx};
use sqlx::Pool;
use sqlx::postgres::Postgres;

#[sqlx::test]
async fn add_domain_inserts_row(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("adding domain to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let ldh: Option<String> =
        sqlx::query_scalar("SELECT content->>'ldhName' FROM domain WHERE ldh_name = $1")
            .bind("foo.example")
            .fetch_one(&db)
            .await
            .expect("domain row exists");
    assert_eq!(ldh.as_deref(), Some("foo.example"));
}

#[sqlx::test]
async fn add_domain_duplicate_is_noop(db: Pool<Postgres>) {
    // GIVEN
    let domain = Domain::builder().ldh_name("foo.example").build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_domain(&domain)
        .await
        .expect("adding domain to tx (1)");
    tx.add_domain(&domain)
        .await
        .expect("adding domain to tx (2)");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM domain WHERE ldh_name = $1")
        .bind("foo.example")
        .fetch_one(&db)
        .await
        .expect("count query");
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn add_domain_err_stores_error_response(db: Pool<Postgres>) {
    // GIVEN
    let id = DomainId::builder().ldh_name("foo.example").build();
    let error = Rfc9083Error::redirect()
        .url("https://bar.example/rdap/domain/foo.example")
        .build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_domain_err(&id, &error)
        .await
        .expect("adding domain error to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let code: Option<i64> = sqlx::query_scalar(
        "SELECT (content->>'errorCode')::bigint FROM domain WHERE ldh_name = $1",
    )
    .bind("foo.example")
    .fetch_one(&db)
    .await
    .expect("domain error row exists");
    assert_eq!(code, Some(307));
}

#[sqlx::test]
async fn rollback_discards_uncommitted_adds(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("adding domain to tx");
    Box::new(tx).rollback().await.expect("rolling back tx");

    // THEN
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM domain")
        .fetch_one(&db)
        .await
        .expect("count query");
    assert_eq!(count, 0);
}
