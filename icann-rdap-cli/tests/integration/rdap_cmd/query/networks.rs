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

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_up_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-up type
    test_jig.cmd.arg("-t").arg("v4-up").arg("10.1.0.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_up_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-up type
    test_jig.cmd.arg("-t").arg("v6-up").arg("2001:db8:1::1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_cidr_up_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-up type - query the /24 to get its supernet (/16)
    test_jig.cmd.arg("-t").arg("v4-cidr-up").arg("10.1.0.0/24");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_cidr_up_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-up type - query the /48 to get its supernet (/32)
    test_jig
        .cmd
        .arg("-t")
        .arg("v6-cidr-up")
        .arg("2001:db8:1::/48");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_top_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-top type - query for most specific network containing IP
    test_jig.cmd.arg("-t").arg("v4-top").arg("10.1.0.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_top_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-top type - query for most specific network containing IP
    test_jig.cmd.arg("-t").arg("v6-top").arg("2001:db8:1::1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_cidr_top_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-top type - query the /24 to get itself (most specific)
    test_jig.cmd.arg("-t").arg("v4-cidr-top").arg("10.1.0.0/24");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_cidr_top_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-top type - query the /48 to get itself (most specific)
    test_jig
        .cmd
        .arg("-t")
        .arg("v6-cidr-top")
        .arg("2001:db8:1::/48");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

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

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_bottom_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-bottom type - query IP within /24 to get all supernets
    test_jig.cmd.arg("-t").arg("v4-bottom").arg("10.1.0.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_bottom_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-bottom type - query IP within /48 to get all supernets
    test_jig.cmd.arg("-t").arg("v6-bottom").arg("2001:db8:1::1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv4_cidr_bottom_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-bottom type - query /24 to get all supernets
    test_jig
        .cmd
        .arg("-t")
        .arg("v4-cidr-bottom")
        .arg("10.1.0.0/24");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_network_ipv6_cidr_bottom_query() {
    // GIVEN networks with different sizes
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN query with rdap-bottom type - query /48 to get all supernets
    test_jig
        .cmd
        .arg("-t")
        .arg("v6-cidr-bottom")
        .arg("2001:db8:1::/48");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
