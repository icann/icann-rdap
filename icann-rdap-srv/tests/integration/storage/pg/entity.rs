use icann_rdap_common::response::{Entity, Rfc9083Error};
use icann_rdap_srv::storage::{TxHandle, data::EntityId, pg::tx::PgTx};
use sqlx::Pool;
use sqlx::postgres::Postgres;

#[sqlx::test]
async fn add_entity_inserts_row(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_entity(&Entity::builder().handle("foo").build())
        .await
        .expect("adding entity to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let handle: Option<String> =
        sqlx::query_scalar("SELECT content->>'handle' FROM entity WHERE handle = $1")
            .bind("foo")
            .fetch_one(&db)
            .await
            .expect("entity row exists");
    assert_eq!(handle.as_deref(), Some("foo"));
}

#[sqlx::test]
async fn add_entity_duplicate_is_noop(db: Pool<Postgres>) {
    // GIVEN
    let entity = Entity::builder().handle("foo").build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_entity(&entity)
        .await
        .expect("adding entity to tx (1)");
    tx.add_entity(&entity)
        .await
        .expect("adding entity to tx (2)");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entity WHERE handle = $1")
        .bind("foo")
        .fetch_one(&db)
        .await
        .expect("count query");
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn add_entity_err_stores_error_response(db: Pool<Postgres>) {
    // GIVEN
    let id = EntityId::builder().handle("foo").build();
    let error = Rfc9083Error::redirect()
        .url("https://bar.example/rdap/entity/foo")
        .build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_entity_err(&id, &error)
        .await
        .expect("adding entity error to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let code: Option<i64> =
        sqlx::query_scalar("SELECT (content->>'errorCode')::bigint FROM entity WHERE handle = $1")
            .bind("foo")
            .fetch_one(&db)
            .await
            .expect("entity error row exists");
    assert_eq!(code, Some(307));
}
