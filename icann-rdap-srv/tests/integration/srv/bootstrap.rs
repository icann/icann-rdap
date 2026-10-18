use {
    icann_rdap_client::{
        http::{ClientConfig, create_client},
        rdap::{QueryType, rdap_request},
    },
    icann_rdap_common::response::Rfc9083Error,
    icann_rdap_srv::{
        config::CommonConfig,
        storage::{
            StoreOps,
            data::{AutnumId, DomainId, EntityId, NetworkId, NetworkIdType},
        },
    },
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_bootstrap_with_less_specific_domain() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("example").build(),
        &Rfc9083Error::redirect().url("https://example.net/").build(),
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
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

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
async fn test_bootstrap_with_no_less_specific_domain() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("no_example").build(),
        &Rfc9083Error::redirect().url("https://example.net").build(),
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
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("http response");

    // THEN
    assert_eq!(response.http_data.status_code(), 404);
}

#[tokio::test]
async fn test_bootstrap_with_less_specific_ns() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("example").build(),
        &Rfc9083Error::redirect().url("https://example.net/").build(),
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
    let query = QueryType::ns("ns.foo.example").expect("invalid nameserver");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

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
async fn test_bootstrap_with_no_less_specific_ns() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("no_example").build(),
        &Rfc9083Error::redirect().url("https://example.net").build(),
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
    let query = QueryType::ns("ns.foo.example").expect("invalid nameserver");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("http response");

    // THEN
    assert_eq!(response.http_data.status_code(), 404);
}

#[tokio::test]
async fn test_bootstrap_with_less_specific_ip() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network_err(
        &NetworkId::builder()
            .network_id(NetworkIdType::Cidr(ipnet::IpNet::V4(
                "10.0.0.0/8".parse().expect("parsing ipnet"),
            )))
            .build(),
        &Rfc9083Error::redirect().url("https://example.net/").build(),
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
    let query = QueryType::ipv4cidr("10.0.0.0/24").expect("invalid CIDR");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

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
async fn test_bootstrap_with_no_less_specific_ip() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network_err(
        &NetworkId::builder()
            .network_id(NetworkIdType::Cidr(ipnet::IpNet::V4(
                "10.0.0.0/8".parse().expect("parsing ipnet"),
            )))
            .build(),
        &Rfc9083Error::redirect().url("https://example.net").build(),
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
    let query = QueryType::ipv4cidr("11.0.0.0/24").expect("invalid CIDR");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("http response");

    // THEN
    assert_eq!(response.http_data.status_code(), 404);
}

#[tokio::test]
async fn test_bootstrap_with_less_specific_autnum() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum_err(
        &AutnumId::builder()
            .start_autnum(700)
            .end_autnum(800)
            .build(),
        &Rfc9083Error::redirect().url("https://example.net/").build(),
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
    let query = QueryType::autnum("AS710").expect("invalid autnum");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

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
async fn test_bootstrap_with_no_less_specific_autnum() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum_err(
        &AutnumId::builder()
            .start_autnum(700)
            .end_autnum(800)
            .build(),
        &Rfc9083Error::redirect().url("https://example.net").build(),
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
    let query = QueryType::autnum("AS1000").expect("invalid autnum");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("http response");

    // THEN
    assert_eq!(response.http_data.status_code(), 404);
}

#[tokio::test]
async fn test_bootstrap_with_specific_tag() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity_err(
        &EntityId::builder().handle("-ARIN").build(),
        &Rfc9083Error::redirect().url("https://example.net/").build(),
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
        .expect("querying server");

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
async fn test_bootstrap_with_specific_tag_lowercase() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity_err(
        &EntityId::builder().handle("-ARIN").build(),
        &Rfc9083Error::redirect().url("https://example.net/").build(),
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
        .expect("querying server");

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
async fn test_bootstrap_with_no_specific_tag() {
    // GIVEN
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_entity_err(
        &EntityId::builder().handle("-CLAUCA").build(),
        &Rfc9083Error::redirect().url("https://example.net").build(),
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
        .expect("http response");

    // THEN
    assert_eq!(response.http_data.status_code(), 404);
}

#[tokio::test]
async fn test_tld_bootstrap_known_tld_redirects_to_iana() {
    // GIVEN a bootstrap server (tld_bootstrap on by default) with a DNS bootstrap redirect
    // stub for the TLD "com" pointing at the registry operator.
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("com").build(),
        &Rfc9083Error::redirect()
            .url("https://registry.example/")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN a bare TLD query is made
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("com").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN it is redirected to the configured IANA TLD bootstrap server, not the registry.
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://rdap.iana.org/domain/com"
    );
}

#[tokio::test]
async fn test_tld_bootstrap_disabled_returns_registry_stub() {
    // GIVEN a bootstrap server with tld_bootstrap explicitly disabled and a stub for "com".
    let test_srv = SrvTestJig::new_common_config(CommonConfig {
        bootstrap: true,
        tld_bootstrap: false,
        ..Default::default()
    })
    .await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("com").build(),
        &Rfc9083Error::redirect()
            .url("https://registry.example/")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN a bare TLD query is made
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("com").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN the original registry-operator stub is returned unchanged.
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://registry.example/"
    );
}

#[tokio::test]
async fn test_tld_bootstrap_unknown_single_label_is_not_found() {
    // GIVEN a bootstrap server with a stub only for "com".
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("com").build(),
        &Rfc9083Error::redirect()
            .url("https://registry.example/")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN a single-label query that is not a known TLD is made
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("notatld").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN it is a plain not-found (no IANA redirect for unknown single labels).
    assert_eq!(response.http_data.status_code(), 404);
}

#[tokio::test]
async fn test_tld_bootstrap_subdomain_still_goes_to_registry() {
    // GIVEN a bootstrap server with a stub for the TLD "com".
    let test_srv = SrvTestJig::new_bootstrap().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain_err(
        &DomainId::builder().ldh_name("com").build(),
        &Rfc9083Error::redirect()
            .url("https://registry.example/")
            .build(),
    )
    .await
    .expect("add domain redirect");
    tx.commit().await.expect("tx commit");

    // WHEN a subdomain within the TLD is queried
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("foo.com").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN it still walks up to the registry operator (regression guard).
    assert!(response.rdap.is_redirect());
    assert_eq!(
        response
            .http_data
            .location
            .as_ref()
            .expect("no location header information"),
        "https://registry.example/domain/foo.com"
    );
}
