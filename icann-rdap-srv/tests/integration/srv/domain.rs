#![allow(non_snake_case)]

use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
        RdapClientError,
    },
    icann_rdap_common::response::Domain,
    icann_rdap_srv::storage::{CommonConfig, StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn GIVEN_server_with_domain_WHEN_query_domain_THEN_status_code_200() {
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
async fn GIVEN_server_with_idn_WHEN_query_domain_THEN_status_code_200() {
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
async fn GIVEN_server_with_domain_and_search_disabled_WHEN_query_domain_THEN_status_code_501() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_name_enable(false)
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
    let response = rdap_request(&test_srv.rdap_base, &query, &client).await;

    // THEN
    let RdapClientError::Client(error) = response.expect_err("not an error response") else {
        panic!("the error was not an HTTP error")
    };
    assert_eq!(error.status().expect("no status code"), 501);
}

#[tokio::test]
async fn GIVEN_server_with_domain_and_search_enabled_WHEN_query_domain_THEN_status_code_200() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_name_enable(true)
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
