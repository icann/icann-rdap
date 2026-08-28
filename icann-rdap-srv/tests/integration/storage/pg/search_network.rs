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
