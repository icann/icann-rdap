use std::net::IpAddr;

use icann_rdap_common::response::{Autnum, Domain, Entity, Help, Nameserver, Network};
use icann_rdap_srv::rdap::response::NOT_FOUND;
use icann_rdap_srv::storage::pg::ops::Pg;
use icann_rdap_srv::storage::{DeleteOps, StoreOps};
use sqlx::{Pool, postgres::Postgres};

#[sqlx::test]
async fn delete_domain_existing(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(&Domain::builder().ldh_name("del.example").build())
        .await
        .expect("adding domain");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    assert!(
        store
            .delete_domain("del.example")
            .await
            .expect("deleting domain")
    );

    // THEN — the record is gone, and a second delete reports no match.
    let actual = store
        .get_domain_by_ldh("del.example")
        .await
        .expect("getting domain");
    assert_eq!(actual, *NOT_FOUND);
    assert!(
        !store
            .delete_domain("del.example")
            .await
            .expect("re-deleting domain")
    );
}

#[sqlx::test]
async fn delete_entity_existing(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(&Entity::builder().handle("DEL-ENTITY").build())
        .await
        .expect("adding entity");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    assert!(
        store
            .delete_entity("DEL-ENTITY")
            .await
            .expect("deleting entity")
    );

    // THEN
    let actual = store
        .get_entity_by_handle("DEL-ENTITY")
        .await
        .expect("getting entity");
    assert_eq!(actual, *NOT_FOUND);
    assert!(
        !store
            .delete_entity("DEL-ENTITY")
            .await
            .expect("re-deleting entity")
    );
}

#[sqlx::test]
async fn delete_nameserver_existing(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns-del.example")
            .addresses(vec!["192.0.2.9".to_string()])
            .build()
            .expect("building nameserver"),
    )
    .await
    .expect("adding nameserver");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    assert!(
        store
            .delete_nameserver("ns-del.example")
            .await
            .expect("deleting nameserver")
    );

    // THEN
    let actual = store
        .get_nameserver_by_ldh("ns-del.example")
        .await
        .expect("getting nameserver");
    assert_eq!(actual, *NOT_FOUND);
    assert!(
        !store
            .delete_nameserver("ns-del.example")
            .await
            .expect("re-deleting nameserver")
    );
}

#[sqlx::test]
async fn delete_autnum_existing(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(&Autnum::builder().autnum_range(900..910).build())
        .await
        .expect("adding autnum");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — a partial range is not the stored key, even with the row present.
    assert!(
        !store
            .delete_autnum(900, 909)
            .await
            .expect("deleting wrong autnum range")
    );
    // The full (start, end) key matches.
    assert!(
        store
            .delete_autnum(900, 910)
            .await
            .expect("deleting autnum")
    );

    // THEN
    let actual = store.get_autnum_by_num(905).await.expect("getting autnum");
    assert_eq!(actual, *NOT_FOUND);
}

#[sqlx::test]
async fn delete_network_existing(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("198.51.100.0/24")
            .handle("NET-DEL")
            .build()
            .expect("building network"),
    )
    .await
    .expect("adding network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — a non-matching composite key does not delete while the row exists.
    let start: IpAddr = "198.51.100.0".parse().unwrap();
    let end: IpAddr = "198.51.100.255".parse().unwrap();
    let wrong_end: IpAddr = "198.51.100.254".parse().unwrap();
    assert!(
        !store
            .delete_network(start, wrong_end)
            .await
            .expect("deleting wrong network range")
    );
    // The full (start, end) key matches.
    assert!(
        store
            .delete_network(start, end)
            .await
            .expect("deleting network")
    );

    // THEN
    let actual = store
        .get_network_by_ipaddr("198.51.100.7")
        .await
        .expect("getting network");
    assert_eq!(actual, *NOT_FOUND);
    assert!(
        !store
            .delete_network(start, end)
            .await
            .expect("re-deleting network")
    );
}

#[sqlx::test]
async fn delete_srv_help_existing(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_srv_help(&Help::response().build(), Some("del.example"))
        .await
        .expect("adding srv help");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    assert!(
        store
            .delete_srv_help("del.example")
            .await
            .expect("deleting srv help")
    );

    // THEN
    let actual = store
        .get_srv_help(Some("del.example"))
        .await
        .expect("getting srv help");
    assert_eq!(actual, *NOT_FOUND);
    assert!(
        !store
            .delete_srv_help("del.example")
            .await
            .expect("re-deleting srv help")
    );
}

#[sqlx::test]
async fn delete_ops_through_trait_object(db: Pool<Postgres>) {
    // GIVEN — the store is only reachable through a trait object.
    let mut tx = Pg::from_pool(db.clone()).new_tx().await.expect("new tx");
    tx.add_domain(&Domain::builder().ldh_name("dyn-del.example").build())
        .await
        .expect("adding domain");
    Box::new(tx).commit().await.expect("committing tx");
    let store: Box<dyn DeleteOps> = Box::new(Pg::from_pool(db));

    // WHEN
    assert!(
        store
            .delete_domain("dyn-del.example")
            .await
            .expect("deleting domain via trait object")
    );
}
