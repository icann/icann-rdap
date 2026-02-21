use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::{prelude::RdapResponse, response::Nameserver},
    icann_rdap_srv::storage::{CommonConfig, StoreOps},
    std::net::{IpAddr, Ipv4Addr},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_nameserver_ip_search_enabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .nameserver_search_by_ip_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .addresses(vec![ip.to_string()])
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NameserverIpSearch(ip);
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::NameserverSearchResults(results) = response.rdap else {
        panic!("not nameserver search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_nameserver_ip_search_disabled() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .nameserver_search_by_ip_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .addresses(vec![ip.to_string()])
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NameserverIpSearch(ip);
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_nameserver_invalid_ip_bad_request() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/nameservers?ip=not_an_ip", test_srv.rdap_base);
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
async fn test_server_nameserver_query() {
    // GIVEN
    let test_srv = SrvTestJig::new_common_config(
        CommonConfig::builder()
            .nameserver_search_by_name_enable(true)
            .build(),
    )
    .await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NameserverNameSearch("ns.foo.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::NameserverSearchResults(results) = response.rdap else {
        panic!("not nameserver search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_search_disabled_for_query_nameserver() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .nameserver_search_by_name_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NameserverNameSearch("ns.foo.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_search_enabled_for_query_nameserver() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .nameserver_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::NameserverNameSearch("ns.foo.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::NameserverSearchResults(results) = response.rdap else {
        panic!("not nameserver search results")
    };
    assert_eq!(results.results().len(), 1);
}
