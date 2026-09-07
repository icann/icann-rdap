use icann_rdap_common::response::{Network, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use super::pg_store;

#[tokio::test]
async fn search_networks_by_handle_finds_match() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("198.51.100.0/24")
            .handle("NET-HANDLE-A")
            .build()
            .expect("building network A"),
    )
    .await
    .expect("adding network A");
    tx.add_network(
        &Network::builder()
            .cidr("198.51.101.0/24")
            .handle("NET-HANDLE-B")
            .build()
            .expect("building network B"),
    )
    .await
    .expect("adding network B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_networks_by_handle("NET-HANDLE-A*")
        .await
        .expect("searching networks by handle");

    // THEN
    let RdapResponse::IpSearchResults(results) = actual else {
        panic!("expected ip search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0]
            .object_common
            .handle
            .as_ref()
            .map(|h| h.to_string()),
        Some("NET-HANDLE-A".to_string())
    );
}

#[tokio::test]
async fn search_networks_by_handle_no_match() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .search_networks_by_handle("NO-SUCH-NET*")
        .await
        .expect("searching networks by handle");

    // THEN
    let RdapResponse::IpSearchResults(results) = actual else {
        panic!("expected ip search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}

#[tokio::test]
async fn search_networks_by_name_finds_match() {
    // GIVEN
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("203.0.113.0/24")
            .name("Test Network A")
            .build()
            .expect("building network A"),
    )
    .await
    .expect("adding network A");
    tx.add_network(
        &Network::builder()
            .cidr("203.0.114.0/24")
            .name("Test Network B")
            .build()
            .expect("building network B"),
    )
    .await
    .expect("adding network B");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN
    let actual = store
        .search_networks_by_name("Test Network A*")
        .await
        .expect("searching networks by name");

    // THEN
    let RdapResponse::IpSearchResults(results) = actual else {
        panic!("expected ip search results, got {actual:?}");
    };
    assert_eq!(results.results().len(), 1);
    assert_eq!(
        results.results()[0].name.as_ref().map(|n| n.to_string()),
        Some("Test Network A".to_string())
    );
}

#[tokio::test]
async fn search_networks_by_name_no_match() {
    // GIVEN
    let store = pg_store().await;

    // WHEN
    let actual = store
        .search_networks_by_name("No Such Network*")
        .await
        .expect("searching networks by name");

    // THEN
    let RdapResponse::IpSearchResults(results) = actual else {
        panic!("expected ip search results, got {actual:?}");
    };
    assert!(results.results().is_empty());
}

#[tokio::test]
async fn search_ip_rdap_up_by_ipaddr_finds_supernet() {
    // GIVEN — a /24 (the top for the queried IP) and its parent /23, both stored
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("10.1.2.0/24")
            .handle("NSUP-24")
            .build()
            .expect("building /24 network"),
    )
    .await
    .expect("adding /24 network");
    tx.add_network(
        &Network::builder()
            .cidr("10.1.2.0/23")
            .handle("NSUP-23")
            .build()
            .expect("building /23 network"),
    )
    .await
    .expect("adding /23 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-up for an IP inside the /24
    let actual = store
        .search_ip_rdap_up_by_ipaddr("10.1.2.3")
        .await
        .expect("searching ip rdap up by ipaddr");

    // THEN — returns the immediate supernet (/23), not the /24
    let RdapResponse::Network(net) = actual else {
        panic!("expected network, got {actual:?}");
    };
    assert_eq!(
        net.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("NSUP-23".to_string())
    );
}

#[tokio::test]
async fn search_ip_rdap_up_by_ipaddr_supernet_not_stored() {
    // GIVEN — a /24 whose parent /23 is NOT stored
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.3.0/24")
            .handle("NSUP-LONELY")
            .build()
            .expect("building lonely /24"),
    )
    .await
    .expect("adding lonely /24");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-up for an IP inside the lonely /24
    let actual = store
        .search_ip_rdap_up_by_ipaddr("192.0.3.5")
        .await
        .expect("searching ip rdap up by ipaddr");

    // THEN — no stored supernet → not a network (404)
    assert!(!matches!(actual, RdapResponse::Network(_)));
}

#[tokio::test]
async fn search_ip_rdap_up_by_cidr_finds_supernet() {
    // GIVEN — a /24 and its parent /23, both stored
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("10.1.2.0/24")
            .handle("NSUP-24")
            .build()
            .expect("building /24 network"),
    )
    .await
    .expect("adding /24 network");
    tx.add_network(
        &Network::builder()
            .cidr("10.1.2.0/23")
            .handle("NSUP-23")
            .build()
            .expect("building /23 network"),
    )
    .await
    .expect("adding /23 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-up for a CIDR matching the stored /24
    let actual = store
        .search_ip_rdap_up_by_cidr("10.1.2.0/24")
        .await
        .expect("searching ip rdap up by cidr");

    // THEN — returns the immediate supernet (/23), not the /24
    let RdapResponse::Network(net) = actual else {
        panic!("expected network, got {actual:?}");
    };
    assert_eq!(
        net.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("NSUP-23".to_string())
    );
}

#[tokio::test]
async fn search_ip_rdap_up_by_cidr_supernet_not_stored() {
    // GIVEN — a /24 whose parent /23 is NOT stored
    let store = pg_store().await;
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle("NSUP-LONELY-CIDR")
            .build()
            .expect("building lonely /24"),
    )
    .await
    .expect("adding lonely /24");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-up for a CIDR whose supernet is not stored
    let actual = store
        .search_ip_rdap_up_by_cidr("192.0.2.0/24")
        .await
        .expect("searching ip rdap up by cidr");

    // THEN — no stored supernet → not a network (404)
    assert!(!matches!(actual, RdapResponse::Network(_)));
}
