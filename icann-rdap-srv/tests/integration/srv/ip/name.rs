use {
    icann_rdap_client::{
        http::{ClientConfig, create_client},
        rdap::{QueryType, rdap_request},
    },
    icann_rdap_common::{
        prelude::{ObjectCommonFields, RdapResponse::IpSearchResults},
        response::Network,
    },
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn name_disabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
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
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NetworkNameSearch("ARIN-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn name_enabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let handle = "TEST-NET-1".to_string();
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle(handle.clone())
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NetworkNameSearch("ARIN-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let IpSearchResults(ips) = response.rdap else {
        panic!("not search results")
    };
    assert_eq!(
        ips.results()
            .first()
            .expect("one result")
            .handle()
            .expect("handle"),
        handle
    );
}

#[tokio::test]
async fn name_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
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
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NetworkNameSearch("LACNIC-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let IpSearchResults(ips) = response.rdap else {
        panic!("not search results")
    };
    assert!(ips.results().is_empty());
}

#[tokio::test]
async fn name_multiple() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
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
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NetworkNameSearch("ARIN-*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let IpSearchResults(ips) = response.rdap else {
        panic!("not search results")
    };
    assert_eq!(ips.results().len(), 2);
}

#[tokio::test]
async fn name_space_sep() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .name("Network Allocation")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NetworkNameSearch("Network*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let IpSearchResults(ips) = response.rdap else {
        panic!("not search results")
    };
    assert_eq!(ips.results().len(), 1);
}

#[tokio::test]
async fn name_missing_param() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 400);
}
