#![allow(non_snake_case)]

use http::HeaderValue;
use icann_rdap_client::query::{qtype::QueryType, request::rdap_request};
use icann_rdap_common::{
    client::{create_client, ClientConfig},
    response::{
        help::Help,
        types::{Notice, NoticeOrRemark},
    },
};
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn GIVEN_server_with_default_help_WHEN_query_help_THEN_status_code_200() {
    // GIVEN
    let test_srv = SrvTestJig::new();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let srvhelp = Help::basic()
        .notice(Notice(
            NoticeOrRemark::builder()
                .description_entry("foo".to_string())
                .build(),
        ))
        .build()
        .expect("building help");
    tx.add_srv_help(&srvhelp, None)
        .await
        .expect("adding srv help");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Help;
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn GIVEN_server_with_host_help_WHEN_query_help_THEN_status_code_200() {
    // GIVEN
    let test_srv = SrvTestJig::new();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let srvhelp = Help::basic()
        .notice(Notice(
            NoticeOrRemark::builder()
                .description_entry("foo".to_string())
                .build(),
        ))
        .build()
        .expect("building help");
    tx.add_srv_help(&srvhelp, Some("foo.example.com"))
        .await
        .expect("adding srv help");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .host(HeaderValue::from_str("foo.example.com").expect("host header value"))
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Help;
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}
