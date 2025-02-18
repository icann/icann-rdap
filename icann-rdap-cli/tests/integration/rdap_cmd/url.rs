#![allow(non_snake_case)]

use icann_rdap_common::response::Network;
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_url_used_with_base_url_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("10.0.0.0/24")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let url = format!("{}/ip/10.0.0.1", test_jig.rdap_base);
    test_jig.cmd.arg(url);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_url_used_with_no_base_url_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap().await;
    test_jig.cmd.env_remove("RDAP_BASE_URL");
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("10.0.0.0/24")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let url = format!("{}/ip/10.0.0.1", test_jig.rdap_base);
    test_jig.cmd.arg(url);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}
