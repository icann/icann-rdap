#![allow(non_snake_case)]

use icann_rdap_client::query::{qtype::QueryType, request::rdap_request};
use icann_rdap_common::{
    client::{create_client, ClientConfig},
    response::domain::Domain,
};
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn GIVEN_server_with_domain_WHEN_query_domain_THEN_status_code_200() {
    // GIVEN
    let test_srv = SrvTestJig::new();
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
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
    assert_eq!(response.http_data.status_code, 200);
}
