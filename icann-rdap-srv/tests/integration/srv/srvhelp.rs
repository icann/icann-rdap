#![allow(non_snake_case)]

use icann_rdap_client::{
    http::{create_client, ClientConfig},
    rdap::{rdap_request, QueryType},
};
use icann_rdap_common::response::{Help, Notice, NoticeOrRemark};
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn GIVEN_server_with_default_help_WHEN_query_help_THEN_status_code_200() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let srvhelp = Help::builder()
        .notice(Notice(
            NoticeOrRemark::builder()
                .description_entry("foo".to_string())
                .build(),
        ))
        .build();
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
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let srvhelp = Help::builder()
        .notice(Notice(
            NoticeOrRemark::builder()
                .description_entry("foo".to_string())
                .build(),
        ))
        .build();
    tx.add_srv_help(&srvhelp, Some("foo.example.com"))
        .await
        .expect("adding srv help");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .host(reqwest::header::HeaderValue::from_static("foo.example.com"))
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::Help;
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("quering server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}
