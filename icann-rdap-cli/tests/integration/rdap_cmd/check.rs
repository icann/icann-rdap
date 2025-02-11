#![allow(non_snake_case)]

use icann_rdap_common::response::Domain;
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_domain_with_check_WHEN_query_THEN_failure() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("--error-on-check").arg("foo.example");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.failure();
}
