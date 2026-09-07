use icann_rdap_common::response::{Network, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use icann_rdap_srv::storage::pg::ops::Pg;
use sqlx::{Pool, postgres::Postgres};

#[sqlx::test]
async fn search_networks_by_handle_finds_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_networks_by_handle_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

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

#[sqlx::test]
async fn search_networks_by_name_finds_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_networks_by_name_no_match(db: Pool<Postgres>) {
    // GIVEN
    let store = Pg::from_pool(db);

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

#[sqlx::test]
async fn search_ip_rdap_up_by_ipaddr_finds_supernet(db: Pool<Postgres>) {
    // GIVEN — a /24 (the top for the queried IP) and its parent /23, both stored
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_ip_rdap_up_by_ipaddr_supernet_not_stored(db: Pool<Postgres>) {
    // GIVEN — a /24 whose parent /23 is NOT stored
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_ip_rdap_up_by_cidr_finds_supernet(db: Pool<Postgres>) {
    // GIVEN — a /24 and its parent /23, both stored
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_ip_rdap_up_by_cidr_supernet_not_stored(db: Pool<Postgres>) {
    // GIVEN — a /24 whose parent /23 is NOT stored
    let store = Pg::from_pool(db);
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

#[sqlx::test]
async fn search_ip_rdap_top_by_cidr_returns_widest_containing(db: Pool<Postgres>) {
    // GIVEN — a /16 and a narrower /24 inside it, both stored
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("196.0.0.0/16")
            .handle("TOP-CIDR-WIDE")
            .build()
            .expect("building wide /16 network"),
    )
    .await
    .expect("adding wide /16 network");
    tx.add_network(
        &Network::builder()
            .cidr("196.0.8.0/24")
            .handle("TOP-CIDR-NARROW")
            .build()
            .expect("building narrow /24 network"),
    )
    .await
    .expect("adding narrow /24 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-top for the stored /24
    let actual = store
        .search_ip_rdap_top_by_cidr("196.0.8.0/24")
        .await
        .expect("searching ip rdap top by cidr");

    // THEN — returns the widest containing network (/16), not the /24
    let RdapResponse::Network(net) = actual else {
        panic!("expected network, got {actual:?}");
    };
    assert_eq!(
        net.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("TOP-CIDR-WIDE".to_string())
    );
}

#[sqlx::test]
async fn search_ip_rdap_top_by_cidr_returns_self_when_only_match(db: Pool<Postgres>) {
    // GIVEN — a /24 with no wider stored ancestor
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("197.0.0.0/24")
            .handle("TOP-CIDR-SELF")
            .build()
            .expect("building /24 network"),
    )
    .await
    .expect("adding /24 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-top for the stored /24
    let actual = store
        .search_ip_rdap_top_by_cidr("197.0.0.0/24")
        .await
        .expect("searching ip rdap top by cidr");

    // THEN — no wider ancestor, so the network is its own top
    let RdapResponse::Network(net) = actual else {
        panic!("expected network, got {actual:?}");
    };
    assert_eq!(
        net.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("TOP-CIDR-SELF".to_string())
    );
}

#[sqlx::test]
async fn search_ip_rdap_top_by_cidr_not_found_when_no_containing(db: Pool<Postgres>) {
    // GIVEN — a /24 that does not contain the queried block
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("202.0.0.0/24")
            .handle("TOP-CIDR-NF")
            .build()
            .expect("building /24 network"),
    )
    .await
    .expect("adding /24 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-top for a block nothing stored contains
    let actual = store
        .search_ip_rdap_top_by_cidr("202.1.0.0/24")
        .await
        .expect("searching ip rdap top by cidr");

    // THEN — no containing network → not a network (404)
    assert!(!matches!(actual, RdapResponse::Network(_)));
}

#[sqlx::test]
async fn search_ip_rdap_top_by_ipaddr_returns_widest_containing(db: Pool<Postgres>) {
    // GIVEN — a /16 and a narrower /24 inside it, both stored
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("204.0.0.0/16")
            .handle("TOP-IP-WIDE")
            .build()
            .expect("building wide /16 network"),
    )
    .await
    .expect("adding wide /16 network");
    tx.add_network(
        &Network::builder()
            .cidr("204.0.8.0/24")
            .handle("TOP-IP-NARROW")
            .build()
            .expect("building narrow /24 network"),
    )
    .await
    .expect("adding narrow /24 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-top for an IP inside the stored /24
    let actual = store
        .search_ip_rdap_top_by_ipaddr("204.0.8.5")
        .await
        .expect("searching ip rdap top by ipaddr");

    // THEN — returns the widest containing network (/16), not the /24
    let RdapResponse::Network(net) = actual else {
        panic!("expected network, got {actual:?}");
    };
    assert_eq!(
        net.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("TOP-IP-WIDE".to_string())
    );
}

#[sqlx::test]
async fn search_ip_rdap_top_by_ipaddr_returns_self_when_only_match(db: Pool<Postgres>) {
    // GIVEN — a /24 with no wider stored ancestor
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("205.0.0.0/24")
            .handle("TOP-IP-SELF")
            .build()
            .expect("building /24 network"),
    )
    .await
    .expect("adding /24 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-top for an IP inside the stored /24
    let actual = store
        .search_ip_rdap_top_by_ipaddr("205.0.0.9")
        .await
        .expect("searching ip rdap top by ipaddr");

    // THEN — no wider ancestor, so the network is its own top
    let RdapResponse::Network(net) = actual else {
        panic!("expected network, got {actual:?}");
    };
    assert_eq!(
        net.object_common.handle.as_ref().map(|h| h.to_string()),
        Some("TOP-IP-SELF".to_string())
    );
}

#[sqlx::test]
async fn search_ip_rdap_top_by_ipaddr_not_found_when_no_containing(db: Pool<Postgres>) {
    // GIVEN — a /24 that does not contain the queried IP
    let store = Pg::from_pool(db);
    let mut tx = store.new_tx().await.expect("new tx");
    tx.add_network(
        &Network::builder()
            .cidr("206.0.0.0/24")
            .handle("TOP-IP-NF")
            .build()
            .expect("building /24 network"),
    )
    .await
    .expect("adding /24 network");
    Box::new(tx).commit().await.expect("committing tx");

    // WHEN — rdap-top for an IP nothing stored contains
    let actual = store
        .search_ip_rdap_top_by_ipaddr("206.1.0.7")
        .await
        .expect("searching ip rdap top by ipaddr");

    // THEN — no containing network → not a network (404)
    assert!(!matches!(actual, RdapResponse::Network(_)));
}
