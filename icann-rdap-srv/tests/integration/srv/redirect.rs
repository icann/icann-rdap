#![allow(non_snake_case)]

use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::response::{Link, Notice, NoticeOrRemark, Rfc9083Error},
    icann_rdap_srv::storage::{
        data::{AutnumId, DomainId, EntityId, NameserverId, NetworkId, NetworkIdType},
        StoreOps,
    },
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn GIVEN_domain_error_with_first_link_href_WHEN_query_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId {
            ldh_name: "foo.example".to_string(),
            unicode_name: None,
        },
        &Rfc9083Error::response_obj()
            .error_code(307)
            .notice(Notice(
                NoticeOrRemark::builder()
                    .links(vec![Link::builder()
                        .href("https://other.example.com")
                        .value("https://other.example.com")
                        .rel("about")
                        .build()])
                    .build(),
            ))
            .build(),
    )
    .await
    .expect("add redirect in tx");
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
    assert_eq!(response.http_data.status_code, 307);
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://other.example.com"
    );
}

#[tokio::test]
async fn GIVEN_nameserver_error_with_first_link_href_WHEN_query_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver_err(
        &NameserverId {
            ldh_name: "ns.foo.example".to_string(),
            unicode_name: None,
        },
        &Rfc9083Error::response_obj()
            .error_code(307)
            .notice(Notice(
                NoticeOrRemark::builder()
                    .links(vec![Link::builder()
                        .href("https://other.example.com")
                        .value("https://other.example.com")
                        .rel("about")
                        .build()])
                    .build(),
            ))
            .build(),
    )
    .await
    .expect("add redirect in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::ns("ns.foo.example").expect("invalid nameserver");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 307);
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://other.example.com"
    );
}

#[tokio::test]
async fn GIVEN_entity_error_with_first_link_href_WHEN_query_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity_err(
        &EntityId {
            handle: "foo".to_string(),
        },
        &Rfc9083Error::response_obj()
            .error_code(307)
            .notice(Notice(
                NoticeOrRemark::builder()
                    .links(vec![Link::builder()
                        .href("https://other.example.com")
                        .value("https://other.example.com")
                        .rel("about")
                        .build()])
                    .build(),
            ))
            .build(),
    )
    .await
    .expect("add redirect in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Entity("foo".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 307);
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://other.example.com"
    );
}

#[tokio::test]
async fn GIVEN_autnum_error_with_first_link_href_WHEN_query_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum_err(
        &AutnumId {
            start_autnum: 700,
            end_autnum: 710,
        },
        &Rfc9083Error::response_obj()
            .error_code(307)
            .notice(Notice(
                NoticeOrRemark::builder()
                    .links(vec![Link::builder()
                        .href("https://other.example.com")
                        .value("https://other.example.com")
                        .rel("about")
                        .build()])
                    .build(),
            ))
            .build(),
    )
    .await
    .expect("add redirect in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::autnum("700").expect("invalid autnum");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 307);
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://other.example.com"
    );
}

#[tokio::test]
async fn GIVEN_network_cidr_error_with_first_link_href_WHEN_query_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network_err(
        &NetworkId {
            network_id: NetworkIdType::Cidr("10.0.0.0/16".parse().expect("parsing cidr")),
        },
        &Rfc9083Error::response_obj()
            .error_code(307)
            .notice(Notice(
                NoticeOrRemark::builder()
                    .links(vec![Link::builder()
                        .href("https://other.example.com")
                        .value("https://other.example.com")
                        .rel("about")
                        .build()])
                    .build(),
            ))
            .build(),
    )
    .await
    .expect("add redirect in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::ipv4("10.0.0.1").expect("invalid IP address");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 307);
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://other.example.com"
    );
}

#[tokio::test]
async fn GIVEN_network_addrs_error_with_first_link_href_WHEN_query_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network_err(
        &NetworkId {
            network_id: NetworkIdType::Range {
                start_address: "10.0.0.0".to_string(),
                end_address: "10.0.0.255".to_string(),
            },
        },
        &Rfc9083Error::response_obj()
            .error_code(307)
            .notice(Notice(
                NoticeOrRemark::builder()
                    .links(vec![Link::builder()
                        .href("https://other.example.com")
                        .value("https://other.example.com")
                        .rel("about")
                        .build()])
                    .build(),
            ))
            .build(),
    )
    .await
    .expect("add redirect in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::ipv4("10.0.0.1").expect("invalid IP address");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 307);
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://other.example.com"
    );
}
