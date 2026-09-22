use super::*;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::response::{Link, Notice, NoticeOrRemark};

fn domain_with_tos_notice() -> Domain {
    let mut domain = Domain::builder().ldh_name("foo.example").build();
    domain.common.notices = Some(vec![Notice(
        NoticeOrRemark::builder()
            .description_entry("terms of service")
            .link(
                Link::builder()
                    .value("https://old/tos")
                    .rel("terms-of-service")
                    .href("https://tos.example/tos")
                    .build(),
            )
            .build(),
    )]);
    domain
}

async fn seeded_srv(common_config: CommonConfig) -> SrvTestJig {
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&domain_with_tos_notice())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");
    test_srv
}

fn served_tos_value(response: ResponseData) -> Option<String> {
    let RdapResponse::Domain(d) = response.rdap else {
        panic!("expected a domain response")
    };
    d.common.notices.as_ref().expect("notices present")[0]
        .0
        .links
        .as_ref()
        .expect("links present")
        .iter()
        .find(|l| l.rel.as_deref() == Some("terms-of-service"))
        .expect("tos link present")
        .value
        .clone()
}

#[tokio::test]
async fn tos_link_value_unchanged_when_flag_disabled() {
    // GIVEN a server with the ToS link feature disabled (default) and a ToS notice
    let test_srv = seeded_srv(CommonConfig::default()).await;

    // WHEN a domain query is served
    let client = create_client(
        &ClientConfig::builder()
            .https_only(false)
            .follow_redirects(false)
            .build(),
    )
    .expect("client");
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN the ToS link value is unchanged from the stored data
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_tos_value(response).as_deref(),
        Some("https://old/tos")
    );
}

#[tokio::test]
async fn tos_link_value_replaced_with_request_uri_when_enabled() {
    // GIVEN a server with the ToS link feature enabled and a ToS notice
    let test_srv = seeded_srv(CommonConfig {
        notice_tos_link_enable: true,
        ..Default::default()
    })
    .await;

    // WHEN a domain query is served
    let client = create_client(
        &ClientConfig::builder()
            .https_only(false)
            .follow_redirects(false)
            .build(),
    )
    .expect("client");
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN the ToS link value is replaced with the request URI (no base URL or forwarded
    // headers in the test env, so it degrades to the relative path)
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_tos_value(response).as_deref(),
        Some("/domain/foo.example")
    );
}
