use {
    icann_rdap_common::{response::Domain, response::Nameserver},
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_search() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for the domain
    test_jig.cmd.arg("-t").arg("domain-name").arg("foo.*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_search_by_nameserver_ldh_name() {
    // GIVEN domain with nameserver
    let mut test_jig = TestJig::new_rdap_with_search().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .nameservers(vec![Nameserver::builder()
                .ldh_name("ns.foo.example")
                .build()
                .unwrap()])
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN search for domains by nameserver ldhName
    test_jig.cmd.arg("-t").arg("domain-ns-name").arg("ns.foo.*");

    // THEN success
    let assert = test_jig.cmd.assert();
    assert.success();
}
