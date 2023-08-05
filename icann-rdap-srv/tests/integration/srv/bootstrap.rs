#![allow(non_snake_case)]

use icann_rdap_client::query::{qtype::QueryType, request::rdap_request};
use icann_rdap_common::client::{create_client, ClientConfig};
use icann_rdap_srv::storage::{
    data::{AutnumId, DomainId, EntityId, NetworkId, NetworkIdType},
    StoreOps,
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn GIVEN_bootstrap_with_less_specific_domain_WHEN_query_domain_THEN_status_code_is_redirect()
{
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("example").build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net/")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Domain("foo.example".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://example.net/domain/foo.example"
    );
}

#[tokio::test]
#[should_panic]
async fn GIVEN_bootstrap_with_no_less_specific_domain_WHEN_query_domain_THEN_should_panic() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("no_example").build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Domain("foo.example".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client).await;

    // THEN
    response.expect("this should be a 404"); // SHOULD PANIC
}

#[tokio::test]
async fn GIVEN_bootstrap_with_less_specific_ns_WHEN_query_ns_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("example").build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net/")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Nameserver("ns.foo.example".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://example.net/nameserver/ns.foo.example"
    );
}

#[tokio::test]
#[should_panic]
async fn GIVEN_bootstrap_with_no_less_specific_ns_WHEN_query_ns_THEN_should_panic() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("no_example").build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Nameserver("ns.foo.example".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client).await;

    // THEN
    response.expect("this should be a 404"); // SHOULD PANIC
}

#[tokio::test]
async fn GIVEN_bootstrap_with_less_specific_ip_WHEN_query_ip_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network_err(
        &NetworkId::builder()
            .network_id(NetworkIdType::Cidr(ipnet::IpNet::V4(
                "10.0.0.0/8".parse().expect("parsing ipnet"),
            )))
            .build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net/")
            .build(),
    )
    .await
    .expect("adding network redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV4Cidr("10.0.0.0/24".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://example.net/ip/10.0.0.0/24"
    );
}

#[tokio::test]
#[should_panic]
async fn GIVEN_bootstrap_with_no_less_specific_ip_WHEN_query_ip_THEN_should_panic() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network_err(
        &NetworkId::builder()
            .network_id(NetworkIdType::Cidr(ipnet::IpNet::V4(
                "10.0.0.0/8".parse().expect("parsing ipnet"),
            )))
            .build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net")
            .build(),
    )
    .await
    .expect("adding network redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV4Cidr("11.0.0.0/24".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client).await;

    // THEN
    response.expect("this should be 404"); // SHOLD PANIC
}

#[tokio::test]
async fn GIVEN_bootstrap_with_less_specific_autnum_WHEN_query_autnum_THEN_status_code_is_redirect()
{
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum_err(
        &AutnumId::builder()
            .start_autnum(700)
            .end_autnum(800)
            .build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net/")
            .build(),
    )
    .await
    .expect("adding autnum redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AsNumber("AS710".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://example.net/autnum/710"
    );
}

#[tokio::test]
#[should_panic]
async fn GIVEN_bootstrap_with_no_less_specific_autnum_WHEN_query_autnum_THEN_should_panic() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum_err(
        &AutnumId::builder()
            .start_autnum(700)
            .end_autnum(800)
            .build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net")
            .build(),
    )
    .await
    .expect("adding autnum redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::AsNumber("AS1000".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client).await;

    // THEN
    response.expect("this should be 404"); // SHOLD PANIC
}

#[tokio::test]
async fn GIVEN_bootstrap_with_specific_tag_WHEN_query_entity_THEN_status_code_is_redirect() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity_err(
        &EntityId::builder().handle("-ARIN").build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net/")
            .build(),
    )
    .await
    .expect("adding entity redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Entity("foo-ARIN".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://example.net/entity/foo-ARIN"
    );
}

#[tokio::test]
async fn GIVEN_bootstrap_with_specific_tag_lowercase_WHEN_query_entity_THEN_status_code_is_redirect(
) {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity_err(
        &EntityId::builder().handle("-ARIN").build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net/")
            .build(),
    )
    .await
    .expect("adding entity redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Entity("foo-arin".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://example.net/entity/foo-arin"
    );
}

#[tokio::test]
#[should_panic]
async fn GIVEN_bootstrap_with_no_specific_tag_WHEN_query_entity_THEN_should_panic() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity_err(
        &EntityId::builder().handle("-CLAUCA").build(),
        &icann_rdap_common::response::error::Error::redirect()
            .url("https://example.net")
            .build(),
    )
    .await
    .expect("adding entity redirect");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Entity("foo-arin".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client).await;

    // THEN
    response.expect("this should be 404"); // SHOLD PANIC
}
