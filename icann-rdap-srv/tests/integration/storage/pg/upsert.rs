//! Upsert behavior of `PgTx`: adding an object whose primary key already exists
//! must update the stored row (last write wins), including generated columns.

use std::net::IpAddr;

use icann_rdap_common::contact::Contact;
use icann_rdap_common::response::{
    Autnum, Domain, Entity, Help, Nameserver, Network, Notice, RdapResponse, Rfc9083Error,
};
use icann_rdap_srv::storage::StoreOps;
use icann_rdap_srv::storage::data::EntityId;
use icann_rdap_srv::storage::pg::ops::Pg;
use sqlx::{Pool, postgres::Postgres};

fn nameserver(ldh_name: &str, addresses: &[&str]) -> Nameserver {
    Nameserver::builder()
        .ldh_name(ldh_name)
        .addresses(addresses.iter().map(|s| s.to_string()).collect())
        .build()
        .expect("building nameserver")
}

#[sqlx::test]
async fn upsert_domain_updates_content_and_generated_columns(db: Pool<Postgres>) {
    // GIVEN — a domain with one network and one nameserver IP.
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("ups-domain.example")
            .network(
                Network::builder()
                    .cidr("203.0.113.0/24")
                    .build()
                    .expect("building network"),
            )
            .nameservers(vec![nameserver("ns1.ups-domain.example", &["192.0.2.1"])])
            .build(),
    )
    .await
    .expect("adding domain");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — the same ldhName is added again with a different network and nameserver IP.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("ups-domain.example")
            .network(
                Network::builder()
                    .cidr("198.51.100.0/24")
                    .build()
                    .expect("building network"),
            )
            .nameservers(vec![nameserver(
                "ns1.ups-domain.example",
                &["198.51.100.53"],
            )])
            .build(),
    )
    .await
    .expect("re-adding domain");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the stored content is the new one, and generated columns are recomputed.
    let actual = store
        .get_domain_by_ldh("ups-domain.example")
        .await
        .expect("getting domain");
    let RdapResponse::Domain(domain) = actual else {
        panic!("expected a domain response, got {actual:?}");
    };
    assert_eq!(
        domain.network().and_then(|n| n.start_address()),
        Some("198.51.100.0")
    );

    let net_start: IpAddr =
        sqlx::query_scalar("SELECT net_start_address FROM domain WHERE ldh_name = $1")
            .bind("ups-domain.example")
            .fetch_one(&db)
            .await
            .expect("reading generated net_start_address");
    assert_eq!(net_start, "198.51.100.0".parse::<IpAddr>().unwrap());

    let ns_v4: Vec<IpAddr> = sqlx::query_scalar("SELECT ns_v4 FROM domain WHERE ldh_name = $1")
        .bind("ups-domain.example")
        .fetch_one(&db)
        .await
        .expect("reading generated ns_v4");
    assert_eq!(ns_v4, vec!["198.51.100.53".parse::<IpAddr>().unwrap()]);
}

#[sqlx::test]
async fn upsert_nameserver_recomputes_ip_columns(db: Pool<Postgres>) {
    // GIVEN — a nameserver with one v4 address.
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_nameserver(&nameserver("ns-ups.example", &["192.0.2.1"]))
        .await
        .expect("adding nameserver");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — the same ldhName is added again with different v4 and v6 addresses.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_nameserver(&nameserver(
        "ns-ups.example",
        &["198.51.100.53", "2001:db8::53"],
    ))
    .await
    .expect("re-adding nameserver");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the generated v4/v6 columns reflect the new content.
    let actual = store
        .get_nameserver_by_ldh("ns-ups.example")
        .await
        .expect("getting nameserver");
    assert!(matches!(actual, RdapResponse::Nameserver(_)));

    let v4: Vec<IpAddr> = sqlx::query_scalar("SELECT v4 FROM nameserver WHERE ldh_name = $1")
        .bind("ns-ups.example")
        .fetch_one(&db)
        .await
        .expect("reading generated v4");
    assert_eq!(v4, vec!["198.51.100.53".parse::<IpAddr>().unwrap()]);

    let v6: Vec<IpAddr> = sqlx::query_scalar("SELECT v6 FROM nameserver WHERE ldh_name = $1")
        .bind("ns-ups.example")
        .fetch_one(&db)
        .await
        .expect("reading generated v6");
    assert_eq!(v6, vec!["2001:db8::53".parse::<IpAddr>().unwrap()]);
}

#[sqlx::test]
async fn upsert_entity_updates_fn_and_content(db: Pool<Postgres>) {
    // GIVEN — an entity whose contact has a full name.
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(
        &Entity::builder()
            .handle("UPS-ENTITY")
            .contact(Contact::builder().full_name("First Name").build())
            .build(),
    )
    .await
    .expect("adding entity");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — the same handle is added again with a different full name.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(
        &Entity::builder()
            .handle("UPS-ENTITY")
            .contact(Contact::builder().full_name("Second Name").build())
            .build(),
    )
    .await
    .expect("re-adding entity");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the fn column and the content both reflect the new entity.
    let actual = store
        .get_entity_by_handle("UPS-ENTITY")
        .await
        .expect("getting entity");
    let RdapResponse::Entity(entity) = actual else {
        panic!("expected an entity response, got {:?}", actual);
    };
    assert_eq!(
        entity
            .contact()
            .and_then(|c| c.full_name().map(String::from)),
        Some("Second Name".to_string())
    );

    let fn_: Option<String> = sqlx::query_scalar("SELECT fn FROM entity WHERE handle = $1")
        .bind("UPS-ENTITY")
        .fetch_one(&db)
        .await
        .expect("reading fn column");
    assert_eq!(fn_, Some("Second Name".to_string()));
}

#[sqlx::test]
async fn upsert_entity_err_replaces_content_and_nulls_fn(db: Pool<Postgres>) {
    // GIVEN — an entity whose contact has a full name.
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(
        &Entity::builder()
            .handle("UPS-ERR-ENTITY")
            .contact(Contact::builder().full_name("Old Name").build())
            .build(),
    )
    .await
    .expect("adding entity");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — an error response is stored under the same handle.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity_err(
        &EntityId {
            handle: "UPS-ERR-ENTITY".to_string(),
        },
        &Rfc9083Error::response_obj()
            .error_code(404)
            .title("Not Found")
            .build(),
    )
    .await
    .expect("adding entity error");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the content is the error response and fn is NULLed, so fn-based searches skip it.
    let actual = store
        .get_entity_by_handle("UPS-ERR-ENTITY")
        .await
        .expect("getting entity");
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected an error response, got {actual:?}");
    };
    assert_eq!(error.error_code(), 404);

    let fn_: Option<String> = sqlx::query_scalar("SELECT fn FROM entity WHERE handle = $1")
        .bind("UPS-ERR-ENTITY")
        .fetch_one(&db)
        .await
        .expect("reading fn column");
    assert_eq!(fn_, None);
}

#[sqlx::test]
async fn upsert_autnum_updates_content_and_generated_columns(db: Pool<Postgres>) {
    // GIVEN — an autnum with a name.
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(800..810)
            .name("Old Name")
            .build(),
    )
    .await
    .expect("adding autnum");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — the same (start, end) range is added again with a different name.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(800..810)
            .name("New Name")
            .build(),
    )
    .await
    .expect("re-adding autnum");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the stored content and the generated name column reflect the new autnum.
    let actual = store.get_autnum_by_num(805).await.expect("getting autnum");
    let RdapResponse::Autnum(autnum) = actual else {
        panic!("expected an autnum response, got {actual:?}");
    };
    assert_eq!(autnum.name(), Some("New Name"));

    let name: Option<String> =
        sqlx::query_scalar("SELECT name FROM autnum WHERE start_autnum = $1 AND end_autnum = $2")
            .bind(800i64)
            .bind(810i64)
            .fetch_one(&db)
            .await
            .expect("reading generated name");
    assert_eq!(name, Some("New Name".to_string()));

    // A range sharing only start_autnum must coexist, not overwrite the existing row.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(
        &Autnum::builder()
            .autnum_range(800..820)
            .name("Other")
            .build(),
    )
    .await
    .expect("adding overlapping autnum");
    Box::new(tx).commit().await.expect("committing tx");

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM autnum WHERE start_autnum = $1")
        .bind(800i64)
        .fetch_one(&db)
        .await
        .expect("counting autnums");
    assert_eq!(count, 2);
}

#[sqlx::test]
async fn upsert_network_updates_content_and_generated_columns(db: Pool<Postgres>) {
    // GIVEN — a network with a handle.
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("203.0.113.0/24")
            .handle("NET-OLD")
            .build()
            .expect("building network"),
    )
    .await
    .expect("adding network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — the same address range is added again with a different handle.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("203.0.113.0/24")
            .handle("NET-NEW")
            .build()
            .expect("building network"),
    )
    .await
    .expect("re-adding network");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the stored content and the generated handle column reflect the new network.
    let actual = store
        .get_network_by_cidr("203.0.113.0/24")
        .await
        .expect("getting network");
    assert!(matches!(actual, RdapResponse::Network(_)));

    let handle: Option<String> = sqlx::query_scalar(
        "SELECT handle FROM network WHERE start_address = $1::inet AND end_address = $2::inet",
    )
    .bind("203.0.113.0".parse::<IpAddr>().unwrap())
    .bind("203.0.113.255".parse::<IpAddr>().unwrap())
    .fetch_one(&db)
    .await
    .expect("reading generated handle");
    assert_eq!(handle, Some("NET-NEW".to_string()));
}

#[sqlx::test]
async fn upsert_srv_help_updates_content(db: Pool<Postgres>) {
    // GIVEN — a help record for a host.
    let store = Pg::from_pool(db.clone());
    let old_help = Help::response()
        .notices(vec![Notice::builder().title("Old Help").build()])
        .build();
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_srv_help(&old_help, Some("ups.example"))
        .await
        .expect("adding srv help");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — a different help record is stored under the same host.
    let new_help = Help::response()
        .notices(vec![Notice::builder().title("New Help").build()])
        .build();
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_srv_help(&new_help, Some("ups.example"))
        .await
        .expect("re-adding srv help");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the stored content is exactly the new help record.
    let actual = store
        .get_srv_help(Some("ups.example"))
        .await
        .expect("getting srv help");
    assert!(matches!(actual, RdapResponse::Help(_)));

    let content: serde_json::Value =
        sqlx::query_scalar("SELECT content FROM srv_help WHERE host = $1")
            .bind("ups.example")
            .fetch_one(&db)
            .await
            .expect("reading stored help content");
    assert_eq!(content, serde_json::to_value(&new_help).unwrap());
}

#[sqlx::test]
async fn upsert_entity_without_full_name_nulls_fn(db: Pool<Postgres>) {
    // GIVEN — an entity with a full name.
    let store = Pg::from_pool(db.clone());
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(
        &Entity::builder()
            .handle("UPS-NULLFN")
            .contact(Contact::builder().full_name("First Name").build())
            .build(),
    )
    .await
    .expect("adding entity");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — the same handle is added again without a contact.
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(&Entity::builder().handle("UPS-NULLFN").build())
        .await
        .expect("re-adding entity");
    Box::new(tx).commit().await.expect("committing tx");

    // THEN — the content is updated and fn follows it to NULL.
    let actual = store
        .get_entity_by_handle("UPS-NULLFN")
        .await
        .expect("getting entity");
    assert!(matches!(actual, RdapResponse::Entity(_)));

    let fn_: Option<String> = sqlx::query_scalar("SELECT fn FROM entity WHERE handle = $1")
        .bind("UPS-NULLFN")
        .fetch_one(&db)
        .await
        .expect("reading fn column");
    assert_eq!(fn_, None);
}
