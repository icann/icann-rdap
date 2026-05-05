use {
    icann_rdap_common::prelude::Link, icann_rdap_common::response::Domain,
    icann_rdap_srv::storage::StoreOps,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_url_output() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("bar.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with url output type
    test_jig.cmd.arg("bar.example").arg("-O").arg("url");

    // THEN output type is the urls
    let assert = test_jig.cmd.assert();
    assert
        .success()
        .stdout(format!("{}/domain/bar.example\n", test_jig.rdap_base));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_url_output() {
    // GIVEN domain that refers to another domain (e.g. registry -> registrar)
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .link(
                Link::builder()
                    .rel("related")
                    .href(format!("{}/domain/bar.example", test_jig.rdap_base))
                    .value(format!("{}/domain/foo.example", test_jig.rdap_base))
                    .build(),
            )
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.add_domain(&Domain::builder().ldh_name("bar.example").build())
        .await
        .expect("add bar domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with url output type
    test_jig.cmd.arg("foo.example").arg("-O").arg("url");

    // THEN output type is the urls
    let assert = test_jig.cmd.assert();
    assert.success().stdout(format!(
        "{}/domain/foo.example\n{}/domain/bar.example\n",
        test_jig.rdap_base, test_jig.rdap_base
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_url_output_for_registry() {
    // GIVEN domain that refers to another domain (e.g. registry -> registrar)
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .link(
                Link::builder()
                    .rel("related")
                    .href(format!("{}/domain/bar.example", test_jig.rdap_base))
                    .value(format!("{}/domain/foo.example", test_jig.rdap_base))
                    .build(),
            )
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.add_domain(&Domain::builder().ldh_name("bar.example").build())
        .await
        .expect("add bar domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with url output type for registry
    test_jig
        .cmd
        .arg("foo.example")
        .arg("-O")
        .arg("url")
        .arg("--registry");

    // THEN output type is the urls
    let assert = test_jig.cmd.assert();
    assert
        .success()
        .stdout(format!("{}/domain/foo.example\n", test_jig.rdap_base));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_url_output_for_registrar() {
    // GIVEN domain that refers to another domain (e.g. registry -> registrar)
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .link(
                Link::builder()
                    .rel("related")
                    .href(format!("{}/domain/bar.example", test_jig.rdap_base))
                    .value(format!("{}/domain/foo.example", test_jig.rdap_base))
                    .build(),
            )
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.add_domain(&Domain::builder().ldh_name("bar.example").build())
        .await
        .expect("add bar domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with url output type for registrar
    test_jig
        .cmd
        .arg("foo.example")
        .arg("-O")
        .arg("url")
        .arg("--registrar");

    // THEN output type is the urls
    let assert = test_jig.cmd.assert();
    assert
        .success()
        .stdout(format!("{}/domain/bar.example\n", test_jig.rdap_base));
}
