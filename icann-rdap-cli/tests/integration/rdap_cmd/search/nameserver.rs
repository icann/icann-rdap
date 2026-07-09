use {
    icann_rdap_common::response::{Domain, Nameserver},
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_nameserver_search() {
    // GIVEN nameserver
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the nameserver
    test_jig.cmd.arg("-t").arg("ns-name").arg("ns.foo.*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_nameserver_ip_search() {
    // GIVEN nameserver with IP address
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_nameserver(
        &Nameserver::builder()
            .ldh_name("ns.foo.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .unwrap(),
    )
    .await
    .expect("add nameserver in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the nameserver by IP
    test_jig.cmd.arg("-t").arg("ns-ip").arg("192.0.2.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_search_by_nameserver_ip() {
    // GIVEN domain with nameserver IP address
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .nameservers(vec![
                Nameserver::builder()
                    .ldh_name("ns.foo.example")
                    .addresses(vec!["192.0.2.1".to_string()])
                    .build()
                    .unwrap(),
            ])
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for domains by nameserver IP
    test_jig.cmd.arg("-t").arg("ns-ip").arg("192.0.2.1");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
