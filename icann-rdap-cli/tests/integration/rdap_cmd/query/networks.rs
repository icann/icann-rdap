use {icann_rdap_common::response::Network, icann_rdap_srv::storage::StoreOps, rstest::rstest};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ip_query() {
    // GIVEN network
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

    // WHEN query ip address
    test_jig.cmd.arg("10.0.0.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ip_query_with_rpsl() {
    // GIVEN network
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

    // WHEN query ip address
    test_jig.cmd.arg("-O").arg("rpsl").arg("10.0.0.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[rstest]
#[case("10.0.0.0/24", "10.0.0.0/24")]
#[case("10.0.0.0/24", "10.0.0/24")]
#[tokio::test(flavor = "multi_thread")]
async fn test_network_cidr_query(#[case] db_cidr: &str, #[case] q_cidr: &str) {
    // GIVEN network
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr(db_cidr)
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query by CIDR
    test_jig.cmd.arg(q_cidr);

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
