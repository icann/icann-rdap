use {
    icann_rdap_common::response::{Domain, Network},
    icann_rdap_srv::storage::StoreOps,
    rstest::rstest,
};

use crate::test_jig::TestJig;

#[rstest]
#[case("foo.example", "foo.example")]
#[case("foo.example", "foo.example.")]
#[case("foo.example", "FOO.EXAMPLE")]
#[case("foó.example", "foó.example")] // unicode
#[tokio::test(flavor = "multi_thread")]
async fn test_domain_queries(#[case] db_domain: &str, #[case] q_domain: &str) {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name(db_domain).build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg(q_domain);

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[rstest]
#[case("foo.example", "foo.example")]
#[case("foo.example", "foo.example.")]
#[case("foo.example", "FOO.EXAMPLE")]
#[case("foó.example", "foó.example")] // unicode
#[tokio::test(flavor = "multi_thread")]
async fn test_domain_queries_with_rpsl(#[case] db_domain: &str, #[case] q_domain: &str) {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name(db_domain).build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query
    test_jig.cmd.arg("-O").arg("rpsl").arg(q_domain);

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tld_query() {
    // GIVEN tld to query
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN queried
    // without "--tld-lookup=none" then this attempts to query IANA instead of the test server
    test_jig.cmd.arg("--tld-lookup=none").arg(".example");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_idn_query_a_label() {
    // GIVEN idn
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("xn--caf-dma.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query alabel
    test_jig.cmd.arg("-t").arg("a-label").arg("café.example");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_rdns_up_query() {
    // GIVEN domains with reverse DNS names and networks in hierarchy
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/16")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdns-ipv4-up type - query the /24 to get its parent (/16)
    test_jig
        .cmd
        .arg("-t")
        .arg("rdns-ipv4-up")
        .arg("0.0.10.in-addr.arpa");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_rdns_down_query() {
    // GIVEN domains with reverse DNS names and networks in hierarchy
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/16")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdns-ipv4-down type - query the /16 to get its children (/24)
    test_jig
        .cmd
        .arg("-t")
        .arg("rdns-ipv4-down")
        .arg("0.10.in-addr.arpa");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_rdns_top_query() {
    // GIVEN domains with reverse DNS names and networks in hierarchy
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/16")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdns-ipv4-top type - query the /24 to get the topmost (/16)
    test_jig
        .cmd
        .arg("-t")
        .arg("rdns-ipv4-top")
        .arg("0.0.10.in-addr.arpa");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_rdns_bottom_query() {
    // GIVEN domains with reverse DNS names and networks in hierarchy
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/16")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with rdns-ipv4-bottom type - query the /16 to get bottom-most networks
    test_jig
        .cmd
        .arg("-t")
        .arg("rdns-ipv4-bottom")
        .arg("0.10.in-addr.arpa");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
