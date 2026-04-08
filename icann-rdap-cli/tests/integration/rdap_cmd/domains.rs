use {icann_rdap_common::response::Domain, icann_rdap_srv::storage::StoreOps, rstest::rstest};

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
