use {
    icann_rdap_common::response::{Network, RdapResponse},
    icann_rdap_srv::{
        config::CommonConfig,
        storage::{
            StoreOps,
            mem::{config::MemConfig, ops::Mem},
        },
    },
};

#[tokio::test]
async fn search_one_match() {
    // GIVEN
    let mem_config = MemConfig::builder()
        .common_config(
            CommonConfig::builder()
                .network_search_by_name_enable(true)
                .build(),
        )
        .build();
    let mem = Mem::new(mem_config);
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .search_networks_by_name("ARIN-*")
        .await
        .expect("searching networks by name");

    // THEN
    let RdapResponse::IpSearchResults(results) = actual else {
        panic!("not ip search results")
    };
    assert_eq!(results.results.len(), 1);
}

#[tokio::test]
async fn search_multiple_matches() {
    // GIVEN
    let mem_config = MemConfig::builder()
        .common_config(
            CommonConfig::builder()
                .network_search_by_name_enable(true)
                .build(),
        )
        .build();
    let mem = Mem::new(mem_config);
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.add_network(
        &Network::builder()
            .cidr("198.51.100.0/24")
            .name("ARIN-002")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .search_networks_by_name("ARIN-*")
        .await
        .expect("searching networks by name");

    // THEN
    let RdapResponse::IpSearchResults(results) = actual else {
        panic!("not ip search results")
    };
    assert_eq!(results.results.len(), 2);
}

#[tokio::test]
async fn search_no_match() {
    // GIVEN
    let mem_config = MemConfig::builder()
        .common_config(
            CommonConfig::builder()
                .network_search_by_name_enable(true)
                .build(),
        )
        .build();
    let mem = Mem::new(mem_config);
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .search_networks_by_name("LACNIC-*")
        .await
        .expect("searching networks by name");

    // THEN
    let RdapResponse::IpSearchResults(results) = actual else {
        panic!("not ip search results")
    };
    assert_eq!(results.results.len(), 0);
}

#[tokio::test]
async fn search_disabled() {
    // GIVEN
    let mem_config = MemConfig::builder()
        .common_config(
            CommonConfig::builder()
                .network_search_by_name_enable(false)
                .build(),
        )
        .build();
    let mem = Mem::new(mem_config);
    let mut tx = mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let actual = mem
        .search_networks_by_name("ARIN-*")
        .await
        .expect("searching networks by name");

    // THEN
    let RdapResponse::ErrorResponse(_e) = actual else {
        panic!("not error response")
    };
}
