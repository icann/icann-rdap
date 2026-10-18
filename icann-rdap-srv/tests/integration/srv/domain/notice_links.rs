use super::*;
use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::response::{Link, Notice, NoticeOrRemark};

fn domain_with_rel_notice(rel: &str) -> Domain {
    let mut domain = Domain::builder().ldh_name("foo.example").build();
    domain.common.notices = Some(vec![Notice(
        NoticeOrRemark::builder()
            .description_entry("notice")
            .link(
                Link::builder()
                    .value(format!("https://old/{rel}"))
                    .rel(rel)
                    .href(format!("https://example.com/{rel}"))
                    .build(),
            )
            .build(),
    )]);
    domain
}

async fn seeded_srv(common_config: CommonConfig, rel: &str) -> SrvTestJig {
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&domain_with_rel_notice(rel))
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");
    test_srv
}

fn served_link_value(response: ResponseData, rel: &str) -> Option<String> {
    let RdapResponse::Domain(d) = response.rdap else {
        panic!("expected a domain response")
    };
    d.common.notices.as_ref().expect("notices present")[0]
        .0
        .links
        .as_ref()
        .expect("links present")
        .iter()
        .find(|l| l.rel.as_deref() == Some(rel))
        .expect("matching link present")
        .value
        .clone()
}

async fn query_domain(test_srv: &SrvTestJig) -> ResponseData {
    let client = create_client(
        &ClientConfig::builder()
            .https_only(false)
            .follow_redirects(false)
            .build(),
    )
    .expect("client");
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server")
}

#[tokio::test]
async fn tos_link_value_unchanged_when_flag_disabled() {
    // GIVEN a ToS notice and the ToS flag disabled (default)
    let test_srv = seeded_srv(CommonConfig::default(), "terms-of-service").await;

    // WHEN a domain query is served, THEN the ToS link value is unchanged
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_link_value(response, "terms-of-service").as_deref(),
        Some("https://old/terms-of-service")
    );
}

#[tokio::test]
async fn tos_link_value_replaced_with_request_uri_when_enabled() {
    // GIVEN a ToS notice and the ToS flag enabled
    let test_srv = seeded_srv(
        CommonConfig {
            notice_tos_link_enable: true,
            ..Default::default()
        },
        "terms-of-service",
    )
    .await;

    // WHEN a domain query is served, THEN the ToS link value becomes the request URI.
    // axum's `.nest("/rdap", ..)` strips the mount prefix before handlers run, so `Uri`
    // yields the de-prefixed path; with no base URL or forwarded headers it degrades to that.
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_link_value(response, "terms-of-service").as_deref(),
        Some("/domain/foo.example")
    );
}

#[tokio::test]
async fn help_link_value_unchanged_when_flag_disabled() {
    // GIVEN a help notice and the help flag disabled (default)
    let test_srv = seeded_srv(CommonConfig::default(), "help").await;

    // WHEN a domain query is served, THEN the help link value is unchanged
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_link_value(response, "help").as_deref(),
        Some("https://old/help")
    );
}

#[tokio::test]
async fn help_link_value_replaced_with_request_uri_when_enabled() {
    // GIVEN a help notice and the help flag enabled (ToS flag left off)
    let test_srv = seeded_srv(
        CommonConfig {
            notice_help_link_enable: true,
            ..Default::default()
        },
        "help",
    )
    .await;

    // WHEN a domain query is served, THEN the help link value becomes the request URI
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_link_value(response, "help").as_deref(),
        Some("/domain/foo.example")
    );
}

#[tokio::test]
async fn glossary_link_value_unchanged_when_flag_disabled() {
    // GIVEN a glossary notice and the glossary flag disabled (default)
    let test_srv = seeded_srv(CommonConfig::default(), "glossary").await;

    // WHEN a domain query is served, THEN the glossary link value is unchanged
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_link_value(response, "glossary").as_deref(),
        Some("https://old/glossary")
    );
}

#[tokio::test]
async fn glossary_link_value_replaced_with_request_uri_when_enabled() {
    // GIVEN a glossary notice and the glossary flag enabled (other flags left off)
    let test_srv = seeded_srv(
        CommonConfig {
            notice_glossary_link_enable: true,
            ..Default::default()
        },
        "glossary",
    )
    .await;

    // WHEN a domain query is served, THEN the glossary link value becomes the request URI
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_link_value(response, "glossary").as_deref(),
        Some("/domain/foo.example")
    );
}

fn domain_with_related_link() -> Domain {
    let mut domain = Domain::builder().ldh_name("foo.example").build();
    domain.object_common.links = Some(vec![
        Link::builder()
            .value("https://old/related")
            .rel("related")
            .href("https://example.com/related")
            .build(),
    ]);
    domain
}

async fn seeded_object_srv(common_config: CommonConfig) -> SrvTestJig {
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&domain_with_related_link())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");
    test_srv
}

fn served_object_link_value(response: ResponseData) -> Option<String> {
    let RdapResponse::Domain(d) = response.rdap else {
        panic!("expected a domain response")
    };
    d.object_common
        .links
        .as_ref()
        .expect("links present")
        .iter()
        .find(|l| l.rel.as_deref() == Some("related"))
        .expect("related link present")
        .value
        .clone()
}

#[tokio::test]
async fn related_link_value_unchanged_when_flag_disabled() {
    // GIVEN an object-level related link and the related flag disabled (default)
    let test_srv = seeded_object_srv(CommonConfig::default()).await;

    // WHEN a domain query is served, THEN the related link value is unchanged
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_object_link_value(response).as_deref(),
        Some("https://old/related")
    );
}

#[tokio::test]
async fn related_link_value_replaced_with_request_uri_when_enabled() {
    // GIVEN an object-level related link and the related flag enabled (other flags off)
    let test_srv = seeded_object_srv(CommonConfig {
        related_link_enable: true,
        ..Default::default()
    })
    .await;

    // WHEN a domain query is served, THEN the related link value becomes the request URI
    let response = query_domain(&test_srv).await;
    assert_eq!(response.http_data.status_code, 200);
    assert_eq!(
        served_object_link_value(response).as_deref(),
        Some("/domain/foo.example")
    );
}
