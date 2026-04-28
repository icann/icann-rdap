use {icann_rdap_common::response::Network, icann_rdap_srv::storage::StoreOps};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_down_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.1.2.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-down type - query IP within /8 to get all subnets
    test_jig.cmd.arg("-t").arg("v4-down").arg("10.1.0.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_down_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:2::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-down type - query IP within /32 to get all subnets
    test_jig.cmd.arg("-t").arg("v6-down").arg("2001:db8:1::1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_cidr_down_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-down type - query /16 to get immediate subnets (/24)
    test_jig
        .cmd
        .arg("-t")
        .arg("v4-cidr-down")
        .arg("10.1.0.0/16");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_cidr_down_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-down type - query /32 to get immediate subnets (/48)
    test_jig
        .cmd
        .arg("-t")
        .arg("v6-cidr-down")
        .arg("2001:db8::/32");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
