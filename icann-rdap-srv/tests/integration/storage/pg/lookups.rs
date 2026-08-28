use icann_rdap_common::response::{
    Autnum, Domain, Entity, Help, Nameserver, Network, Notice, NoticeOrRemark, RdapResponse,
};
use icann_rdap_srv::storage::StoreOps;

use super::pg_store;

fn help_with_notice() -> Help {
    Help::response()
        .notice(Notice(
            NoticeOrRemark::builder()
                .description_entry("foo".to_string())
                .build(),
        ))
        .build()
}

#[tokio::test]
async fn get_domain_by_ldh_returns_stored_domain() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(&Domain::builder().ldh_name("ldh-lookup.example").build())
        .await
        .expect("adding domain to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_domain_by_ldh("LDH-LOOKUP.EXAMPLE")
        .await
        .expect("looking up domain");

    // THEN
    let RdapResponse::Domain(domain) = actual else {
        panic!("expected domain response, got {actual:?}")
    };
    assert_eq!(domain.ldh_name.as_deref(), Some("ldh-lookup.example"));
}

#[tokio::test]
async fn get_domain_by_ldh_not_found() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .get_domain_by_ldh("no-such-domain-xyz.example")
        .await
        .expect("looking up domain");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected error response, got {actual:?}")
    };
    assert_eq!(error.error_code(), 404);
}

#[tokio::test]
async fn get_domain_by_unicode_returns_stored_domain() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("unicode-lookup.example")
            .unicode_name("ünïcode-lookup.example")
            .build(),
    )
    .await
    .expect("adding domain to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_domain_by_unicode("ünïcode-lookup.example")
        .await
        .expect("looking up domain by unicode name");

    // THEN
    let RdapResponse::Domain(domain) = actual else {
        panic!("expected domain response, got {actual:?}")
    };
    assert_eq!(domain.ldh_name.as_deref(), Some("unicode-lookup.example"));
}

#[tokio::test]
async fn get_entity_by_handle_returns_stored_entity() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_entity(&Entity::builder().handle("ENTITY-LOOKUP").build())
        .await
        .expect("adding entity to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_entity_by_handle("ENTITY-LOOKUP")
        .await
        .expect("looking up entity");

    // THEN
    let RdapResponse::Entity(entity) = actual else {
        panic!("expected entity response, got {actual:?}")
    };
    assert_eq!(
        entity
            .object_common
            .handle
            .as_ref()
            .expect("no handle on entity")
            .to_string(),
        "ENTITY-LOOKUP"
    );
}

#[tokio::test]
async fn get_entity_by_handle_not_found() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .get_entity_by_handle("NO-SUCH-ENTITY-XYZ")
        .await
        .expect("looking up entity");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected error response, got {actual:?}")
    };
    assert_eq!(error.error_code(), 404);
}

#[tokio::test]
async fn get_nameserver_by_ldh_returns_stored_nameserver() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns-lookup.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .expect("building nameserver"),
    )
    .await
    .expect("adding nameserver to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_nameserver_by_ldh("NS-LOOKUP.EXAMPLE")
        .await
        .expect("looking up nameserver");

    // THEN
    let RdapResponse::Nameserver(nameserver) = actual else {
        panic!("expected nameserver response, got {actual:?}")
    };
    assert_eq!(nameserver.ldh_name.as_deref(), Some("ns-lookup.example"));
}

#[tokio::test]
async fn get_nameserver_by_ldh_not_found() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .get_nameserver_by_ldh("no-such-ns-xyz.example")
        .await
        .expect("looking up nameserver");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected error response, got {actual:?}")
    };
    assert_eq!(error.error_code(), 404);
}

#[tokio::test]
async fn get_autnum_by_num_returns_stored_autnum() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("adding autnum to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_autnum_by_num(705)
        .await
        .expect("looking up autnum");

    // THEN
    let RdapResponse::Autnum(autnum) = actual else {
        panic!("expected autnum response, got {actual:?}")
    };
    assert_eq!(autnum.start_autnum(), Some(700));
}

#[tokio::test]
async fn get_autnum_by_num_not_found() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .get_autnum_by_num(999_999)
        .await
        .expect("looking up autnum");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected error response, got {actual:?}")
    };
    assert_eq!(error.error_code(), 404);
}

#[tokio::test]
async fn get_network_by_ipaddr_returns_most_specific_network() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("10.0.0.0/8")
            .handle("NET-10-WIDE")
            .build()
            .expect("building wide network"),
    )
    .await
    .expect("adding wide network to tx");
    tx.add_network(
        &Network::builder()
            .cidr("10.5.0.0/24")
            .handle("NET-10-5-NARROW")
            .build()
            .expect("building narrow network"),
    )
    .await
    .expect("adding narrow network to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_network_by_ipaddr("10.5.0.42")
        .await
        .expect("looking up network");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!("expected network response, got {actual:?}")
    };
    assert_eq!(
        network.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("NET-10-5-NARROW".to_string())
    );
}

#[tokio::test]
async fn get_network_by_ipaddr_falls_back_to_wider_network() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("172.16.0.0/12")
            .handle("NET-FALLBACK-WIDE")
            .build()
            .expect("building fallback network"),
    )
    .await
    .expect("adding fallback network to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_network_by_ipaddr("172.20.1.1")
        .await
        .expect("looking up network");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!("expected network response, got {actual:?}")
    };
    assert_eq!(
        network.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("NET-FALLBACK-WIDE".to_string())
    );
}

#[tokio::test]
async fn get_network_by_ipaddr_not_found() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .get_network_by_ipaddr("192.0.2.250")
        .await
        .expect("looking up network");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected error response, got {actual:?}")
    };
    assert_eq!(error.error_code(), 404);
}

#[tokio::test]
async fn get_network_by_cidr_returns_containing_network() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("192.88.0.0/16")
            .handle("NET-CIDR-SUPER")
            .build()
            .expect("building containing network"),
    )
    .await
    .expect("adding containing network to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_network_by_cidr("192.88.77.0/24")
        .await
        .expect("looking up network");

    // THEN
    let RdapResponse::Network(network) = actual else {
        panic!("expected network response, got {actual:?}")
    };
    assert_eq!(
        network.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("NET-CIDR-SUPER".to_string())
    );
}

#[tokio::test]
async fn get_network_by_cidr_not_found() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .get_network_by_cidr("192.0.2.0/24")
        .await
        .expect("looking up network");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected error response, got {actual:?}")
    };
    assert_eq!(error.error_code(), 404);
}

#[tokio::test]
async fn get_srv_help_returns_default_help() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_srv_help(&help_with_notice(), None)
        .await
        .expect("adding srv help to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store.get_srv_help(None).await.expect("looking up srv help");

    // THEN
    assert!(
        matches!(actual, RdapResponse::Help(_)),
        "expected help, got {actual:?}"
    );
}

#[tokio::test]
async fn get_srv_help_returns_host_help() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_srv_help(&help_with_notice(), Some("lookup-host.example"))
        .await
        .expect("adding srv help to tx");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .get_srv_help(Some("lookup-host.example"))
        .await
        .expect("looking up srv help");

    // THEN
    assert!(
        matches!(actual, RdapResponse::Help(_)),
        "expected help, got {actual:?}"
    );
}

#[tokio::test]
async fn get_srv_help_not_found() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .get_srv_help(Some("no-such-host-xyz.example"))
        .await
        .expect("looking up srv help");

    // THEN
    let RdapResponse::ErrorResponse(error) = actual else {
        panic!("expected error response, got {actual:?}")
    };
    assert_eq!(error.error_code(), 404);
}
