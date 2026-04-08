use {
    icann_rdap_common::response::Nameserver,
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_nameserver_query() {
    // GIVEN nameserver
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg("ns.foo.example");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_nameserver_query_with_rpsl() {
    // GIVEN nameserver
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg("-O").arg("rpsl").arg("ns.foo.example");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}