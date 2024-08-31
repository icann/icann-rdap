#![allow(non_snake_case)]

use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
};
use icann_rdap_srv::storage::StoreOps;
use rstest::rstest;

use crate::test_jig::TestJig;

#[rstest]
#[case("foo.example", "foo.example")]
#[case("foo.example", "foo.example.")]
#[case("foo.example", "FOO.EXAMPLE")]
#[case("foó.example", "foó.example")] // unicode
#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_domain_WHEN_query_THEN_success(#[case] db_domain: &str, #[case] q_domain: &str) {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name(db_domain).build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg(q_domain);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_entity_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_entity(&Entity::basic().handle("foo").build())
        .await
        .expect("add entity in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("foo");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_nameserver_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::basic()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("ns.foo.example");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_autnum_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::basic().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("700");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_network_ip_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::basic()
            .cidr("10.0.0.0/24")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("10.0.0.1");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[rstest]
#[case("10.0.0.0/24", "10.0.0.0/24")]
#[case("10.0.0.0/24", "10.0.0/24")]
#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_network_cidr_WHEN_query_THEN_success(#[case] db_cidr: &str, #[case] q_cidr: &str) {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::basic()
            .cidr(db_cidr)
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg(q_cidr);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_url_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let url = format!("{}/domain/foo.example", test_jig.rdap_base);
    test_jig.cmd.arg(url);

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_idn_WHEN_query_a_label_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("xn--caf-dma.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("-t").arg("a-label").arg("café.example");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_domain_WHEN_search_domain_names_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new_with_enable_domain_name_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("-t").arg("domain-name").arg("foo.*");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}
