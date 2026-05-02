#![allow(non_snake_case)]

use icann_rdap_common::prelude::{Domain, Link};
use icann_rdap_srv::storage::StoreOps;

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_not_found() {
    // GIVEN
    let mut test_jig = TestJig::new_rdap().await;

    // WHEN
    test_jig.cmd.arg("foo.example");

    // THEN
    let assert = test_jig.cmd.assert();
    assert.code(106);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_not_found() {
    // GIVEN domain that refers to another domain (e.g. registry -> registrar)
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .link(
                Link::builder()
                    .rel("related")
                    // note that in real life this would be a foo.example referring to a foo.example
                    // in another server.
                    .href(format!("{}/domain/bar.example", test_jig.rdap_base))
                    .value(format!("{}/domain/foo.example", test_jig.rdap_base))
                    .build(),
            )
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.commit().await.expect("tx commit");
    // bar.example does not exist.

    // WHEN query with url output type
    test_jig.cmd.arg("foo.example").arg("-O").arg("url");

    // THEN output type is the urls
    let assert = test_jig.cmd.assert();
    assert.code(106);
}
