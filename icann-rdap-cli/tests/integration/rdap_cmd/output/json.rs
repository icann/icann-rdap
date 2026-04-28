use {
    icann_rdap_common::prelude::Link, icann_rdap_common::response::Domain,
    icann_rdap_srv::storage::StoreOps, serde_json::Value,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_json_output() {
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

    // WHEN query with json output type
    test_jig.cmd.arg("foo.example").arg("-O").arg("json");

    // THEN output type is json array
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    assert!(json.is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_json_output_for_registrar() {
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

    // WHEN query with json output type for registrar
    test_jig
        .cmd
        .arg("foo.example")
        .arg("-O")
        .arg("json")
        .arg("--registrar");

    // THEN output type is json object
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    assert!(json.is_object());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_pretty_json_output() {
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

    // WHEN query with pretty json output type
    test_jig.cmd.arg("foo.example").arg("-O").arg("pretty-json");

    // THEN output type is json array
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    assert!(json.is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_pretty_json_output_for_registrar() {
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

    // WHEN query with pretty json output type for registrar
    test_jig
        .cmd
        .arg("foo.example")
        .arg("-O")
        .arg("pretty-json")
        .arg("--registrar");

    // THEN output type is json object
    let assert = test_jig.cmd.assert();
    let assert = assert.success();
    let output = &assert.get_output().stdout;
    let json: Value = serde_json::from_slice(output).expect("valid json");
    assert!(json.is_object());
}
