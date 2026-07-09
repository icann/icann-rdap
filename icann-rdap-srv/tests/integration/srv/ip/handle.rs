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
async fn test_search_networks_by_handle_success() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let handle = "TEST-HANDLE".to_string();
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle(handle.clone())
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
    let query = QueryType::NetworkHandleSearch("TEST-*".to_string());
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
async fn test_search_networks_by_handle_missing_param() {
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

#[tokio::test]
async fn test_search_networks_by_handle_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_handle_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NetworkHandleSearch("NONEXISTENT".to_string());
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
