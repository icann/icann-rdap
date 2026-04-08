use {
    icann_rdap_common::response::Entity,
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_entity_query() {
    // GIVEN entity
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("foo").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg("foo");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_entity_query_with_rpsl() {
    // GIVEN entity
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::builder().handle("foo").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg("-O").arg("rpsl").arg("foo");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}