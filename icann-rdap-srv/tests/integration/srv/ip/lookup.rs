use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::{prelude::RdapResponse, response::Network},
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_ipv4_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
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
    let query = QueryType::IpV4Addr("192.0.2.1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv6_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("2001:db8::/32")
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
    let query = QueryType::IpV6Addr("2001:db8::1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv4_cidr_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
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
    let query = QueryType::IpV4Cidr("192.0.2.0/24".parse().expect("cidr"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv6_cidr_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("2001:db8::/32")
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
    let query = QueryType::IpV6Cidr("2001:db8::/32".parse().expect("cidr"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv4_lookup_not_found() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
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
    let query = QueryType::IpV4Addr("203.0.113.1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 404);
}

#[tokio::test]
async fn test_server_ipv6_lookup_not_found() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("2001:db8::/32")
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
    let query = QueryType::IpV6Addr("2001:db9::1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 404);
}

#[tokio::test]
async fn test_server_ipv4_cidr_prefix_too_long() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ip/192.0.2.0/33", test_srv.rdap_base);
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
async fn test_server_ipv6_cidr_prefix_too_long() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ip/2001:db8::/129", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 400);
}
