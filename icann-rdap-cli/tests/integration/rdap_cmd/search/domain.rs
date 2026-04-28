use {icann_rdap_common::response::Domain, icann_rdap_srv::storage::StoreOps};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_search() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the domain
    test_jig.cmd.arg("-t").arg("domain-name").arg("foo.*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
