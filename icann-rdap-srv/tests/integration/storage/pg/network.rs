use icann_rdap_common::response::{Help, Network, Rfc9083Error};
use icann_rdap_srv::{
    error::RdapServerError,
    storage::{
        TxHandle,
        data::{NetworkId, NetworkIdType},
        pg::tx::PgTx,
    },
};
use sqlx::Pool;
use sqlx::postgres::Postgres;

#[sqlx::test]
async fn add_network_inserts_row(db: Pool<Postgres>) {
    // GIVEN
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_network(
        &Network::builder()
            .cidr("10.0.0.0/8")
            .build()
            .expect("building network"),
    )
    .await
    .expect("adding network to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let (start, end): (String, String) =
        sqlx::query_as("SELECT start_address::text, end_address::text FROM network")
            .fetch_one(&db)
            .await
            .expect("network row exists");
    assert_eq!(start, "10.0.0.0/32");
    assert_eq!(end, "10.255.255.255/32");
}

#[sqlx::test]
async fn add_network_duplicate_is_noop(db: Pool<Postgres>) {
    // GIVEN
    let network = Network::builder()
        .cidr("10.0.0.0/8")
        .build()
        .expect("building network");
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_network(&network)
        .await
        .expect("adding network to tx (1)");
    tx.add_network(&network)
        .await
        .expect("adding network to tx (2)");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM network WHERE start_address = $1::inet AND end_address = $2::inet",
    )
    .bind("10.0.0.0")
    .bind("10.255.255.255")
    .fetch_one(&db)
    .await
    .expect("count query");
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn add_network_err_with_cidr_stores_error_response(db: Pool<Postgres>) {
    // GIVEN
    let id = NetworkId::builder()
        .network_id(NetworkIdType::Cidr(
            "10.0.0.0/8".parse().expect("parsing ipnet"),
        ))
        .build();
    let error = Rfc9083Error::redirect()
        .url("https://bar.example/rdap/ip/10.0.0.0/8")
        .build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_network_err(&id, &error)
        .await
        .expect("adding network error to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let (start, end, code): (String, String, Option<i64>) = sqlx::query_as(
        "SELECT start_address::text, end_address::text, (content->>'errorCode')::bigint \
         FROM network",
    )
    .fetch_one(&db)
    .await
    .expect("network error row exists");
    assert_eq!(start, "10.0.0.0/32");
    assert_eq!(end, "10.255.255.255/32");
    assert_eq!(code, Some(307));
}

#[sqlx::test]
async fn add_network_err_with_range_stores_error_response(db: Pool<Postgres>) {
    // GIVEN
    let id = NetworkId::builder()
        .network_id(NetworkIdType::Range {
            start_address: "192.0.2.0".to_string(),
            end_address: "192.0.2.255".to_string(),
        })
        .build();
    let error = Rfc9083Error::redirect()
        .url("https://bar.example/rdap/ip/192.0.2.0")
        .build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    tx.add_network_err(&id, &error)
        .await
        .expect("adding network error to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN
    let (start, end, code): (String, String, Option<i64>) = sqlx::query_as(
        "SELECT start_address::text, end_address::text, (content->>'errorCode')::bigint \
         FROM network",
    )
    .fetch_one(&db)
    .await
    .expect("network error row exists");
    assert_eq!(start, "192.0.2.0/32");
    assert_eq!(end, "192.0.2.255/32");
    assert_eq!(code, Some(307));
}

#[sqlx::test]
async fn add_network_err_with_mixed_ip_versions_fails(db: Pool<Postgres>) {
    // GIVEN
    let id = NetworkId::builder()
        .network_id(NetworkIdType::Range {
            start_address: "192.0.2.0".to_string(),
            end_address: "2001:db8::1".to_string(),
        })
        .build();
    let error = Rfc9083Error::redirect()
        .url("https://bar.example/rdap/ip/192.0.2.0")
        .build();
    let mut tx = PgTx::new(&db).await.expect("creating new pg tx");

    // WHEN
    let result = tx.add_network_err(&id, &error).await;

    // THEN
    assert!(
        matches!(result, Err(RdapServerError::EmptyIndexData(_))),
        "expected EmptyIndexData error, got {result:?}"
    );
}

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
