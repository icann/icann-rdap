use {
    icann_rdap_common::response::Network,
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
    serde_json::Value,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_net_name_search() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle("TEST-NET-1")
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the network by name
    test_jig.cmd.arg("-t").arg("net-name").arg("ARIN-*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_net_name_search_wildcard() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
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

    // WHEN search for networks by name with wildcard
    test_jig
        .cmd
        .arg("-t")
        .arg("net-name")
        .arg("ARIN-HOSTMASTER-*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_net_name_search_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;

    // WHEN search for a non-existent name
    test_jig.cmd.arg("-t").arg("net-name").arg("NONEXISTENT-*");

    // THEN success (empty results, not error)
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_net_name_search_space_sep() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle("TEST-NET-1")
            .name("Network Allocation")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search with space-separated label
    test_jig.cmd.arg("-t").arg("net-name").arg("Network*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_net_name_search_output_json() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle("TEST-NET-1")
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with json output type
    test_jig
        .cmd
        .arg("-t")
        .arg("net-name")
        .arg("ARIN-*")
        .arg("-O")
        .arg("json");

    // THEN output contains ipSearchResults object
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    assert!(json.is_object());
    let search_results = json.get("ipSearchResults").expect("ipSearchResults field");
    let first = search_results.get(0).expect("first result");
    assert!(
        first.get("handle").is_some(),
        "result should have handle field"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_net_name_search_output_rpsl() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .network_search_by_name_enable(true)
        .build();
    let mut test_jig =
        TestJig::new_common_config(common_config, crate::test_jig::CommandType::Rdap).await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .handle("TEST-NET-1")
            .name("ARIN-001")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rpsl output type
    test_jig
        .cmd
        .arg("-t")
        .arg("net-name")
        .arg("ARIN-*")
        .arg("-O")
        .arg("rpsl");

    // THEN output contains RPSL-formatted text
    let assert = test_jig.cmd.assert();
    assert.success();
}
