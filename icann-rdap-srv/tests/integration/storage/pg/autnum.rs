use icann_rdap_common::response::{Autnum, Rfc9083Error};
use icann_rdap_srv::storage::{TxHandle, data::AutnumId, pg::tx::PgTx};
use sqlx::Pool;
use sqlx::postgres::Postgres;

#[sqlx::test]
async fn add_autnum_inserts_row(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("adding autnum to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let (start, end): (i64, i64) = sqlx::query_as("SELECT start_autnum, end_autnum FROM autnum")
        .fetch_one(&db)
        .await
        .expect("autnum row exists");
    assert_eq!((start, end), (700, 710));
}

#[sqlx::test]
async fn add_autnum_duplicate_is_noop(db: Pool<Postgres>) {
    // GIVEN
    let autnum = Autnum::builder().autnum_range(700..710).build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_autnum(&autnum)
        .await
        .expect("adding autnum to tx (1)");
    tx.add_autnum(&autnum)
        .await
        .expect("adding autnum to tx (2)");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM autnum WHERE start_autnum = $1 AND end_autnum = $2",
    )
    .bind(700i64)
    .bind(710i64)
    .fetch_one(&db)
    .await
    .expect("count query");
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn add_autnum_err_stores_error_response(db: Pool<Postgres>) {
    // GIVEN
    let id = AutnumId::builder()
        .start_autnum(700)
        .end_autnum(710)
        .build();
    let error = Rfc9083Error::redirect()
        .url("https://bar.example/rdap/ip/AS700")
        .build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_autnum_err(&id, &error)
        .await
        .expect("adding autnum error to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let code: Option<i64> = sqlx::query_scalar(
        "SELECT (content->>'errorCode')::bigint FROM autnum \
         WHERE start_autnum = $1 AND end_autnum = $2",
    )
    .bind(700i64)
    .bind(710i64)
    .fetch_one(&db)
    .await
    .expect("autnum error row exists");
    assert_eq!(code, Some(307));
}
