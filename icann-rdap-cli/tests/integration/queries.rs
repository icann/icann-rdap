#![allow(non_snake_case)]

use cidr_utils::cidr::IpCidr;
use icann_rdap_common::response::{
    autnum::Autnum, domain::Domain, entity::Entity, nameserver::Nameserver, network::Network,
};
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_domain_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new();
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::basic().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("foo.example");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_entity_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new();
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
    let mut test_jig = TestJig::new();
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(&Nameserver::basic().ldh_name("ns.foo.example").build())
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
    let mut test_jig = TestJig::new();
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(
        &Autnum::basic_nums()
            .start_autnum(700)
            .end_autnum(710)
            .build(),
    )
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
    let mut test_jig = TestJig::new();
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::basic()
            .cidr(IpCidr::from_str("10.0.0.0/24").expect("cidr parsing"))
            .build(),
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

#[tokio::test(flavor = "multi_thread")]
async fn GIVEN_network_cidr_WHEN_query_THEN_success() {
    // GIVEN
    let mut test_jig = TestJig::new();
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::basic()
            .cidr(IpCidr::from_str("10.0.0.0/24").expect("cidr parsing"))
            .build(),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    test_jig.cmd.arg("10.0.0.0/24");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.success();
}
