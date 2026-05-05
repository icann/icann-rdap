use {
    icann_rdap_common::response::Network,
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_net_handle_search() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_handle_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle("TEST-NET-1")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the network by handle
    test_jig.cmd.arg("-t").arg("net-handle").arg("TEST-*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_net_handle_search_wildcard() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_handle_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle("ARIN-HOSTMASTER-1")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.add_network(
        &Network::builder()
            .cidr("198.51.100.0/24")
            .handle("ARIN-HOSTMASTER-2")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for networks by handle with wildcard
    test_jig
        .cmd
        .arg("-t")
        .arg("net-handle")
        .arg("ARIN-HOSTMASTER-*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_net_handle_search_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_handle_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;

    // WHEN search for a non-existent handle
    test_jig
        .cmd
        .arg("-t")
        .arg("net-handle")
        .arg("NONEXISTENT-*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
