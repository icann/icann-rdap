use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::response::{Domain, Nameserver},
    icann_rdap_srv::storage::{CommonConfig, StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_domain_query() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_server_idn_query() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::idn()
            .unicode_name("café.example")
            .ldh_name("cafe.example")
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("café.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_server_search_disabled_for_query_domain() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_name_enable(false)
        .nameserver_search_by_name_enable(true)
        .nameserver_search_by_ip_enable(true)
        .domain_search_by_ns_ip_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNameSearch("foo.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_search_enabled_for_query_domain() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_name_enable(true)
        .nameserver_search_by_name_enable(true)
        .nameserver_search_by_ip_enable(true)
        .domain_search_by_ns_ip_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNameSearch("foo.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_server_search_disabled_for_query_domain_by_ns_ip() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_name_enable(true)
        .nameserver_search_by_name_enable(true)
        .nameserver_search_by_ip_enable(true)
        .domain_search_by_ns_ip_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsIpSearch("192.0.2.1".parse().unwrap());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_search_enabled_for_query_domain_by_ns_ip() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ip_enable(true)
        .nameserver_search_by_ip_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsIpSearch("192.0.2.1".parse().unwrap());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_server_search_domain_by_ns_ip_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ip_enable(true)
        .nameserver_search_by_ip_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for IP that doesn't exist
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsIpSearch("192.0.2.99".parse().unwrap());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns 200 with empty results (RFC 9082)
    assert_eq!(response.http_data.status_code, 200);
}
