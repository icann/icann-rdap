#![allow(non_snake_case)]

use icann_rdap_client::rdap::RequestResponseOwned;
use icann_rdap_common::response::{Domain, Entity, RdapResponse};
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_domain_with_entity_WHEN_retreived_from_cache_THEN_is_domain() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .entity(Entity::basic().handle("bob").build())
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    test_jig.cmd.arg("foo.example");
    let output = test_jig.cmd.output().expect("executing domain query");
    let responses: Vec<RequestResponseOwned> =
        serde_json::from_slice(&output.stdout).expect("parsing stdout");
    let rdap = &responses.first().expect("response is empty").res_data.rdap;
    println!("response type is {rdap}");

    // WHEN
    let mut test_jig = test_jig.new_cmd();
    test_jig.cmd.arg("foo.example");

    // THEN
    let output = test_jig.cmd.output().expect("executing domain query");
    let responses: Vec<RequestResponseOwned> =
        serde_json::from_slice(&output.stdout).expect("parsing stdout");
    let rdap = &responses.first().expect("response is empty").res_data.rdap;
    println!("response type is {rdap}");
    assert!(matches!(rdap, RdapResponse::Domain(_)));
    let rdap_type = &responses
        .first()
        .expect("response is empty")
        .res_data
        .rdap_type;
    assert_eq!(rdap_type, "Domain");
}
