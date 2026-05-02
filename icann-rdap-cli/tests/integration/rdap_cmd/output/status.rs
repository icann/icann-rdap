use {
    icann_rdap_common::{prelude::Link, response::Domain},
    icann_rdap_srv::storage::StoreOps,
    serde_json::json,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_status_output_text() {
    // GIVEN domain with status
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("foo.example")
            .status("client delete prohibited")
            .status("client transfer prohibited")
            .status("client update prohibited")
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with status-text output type
    test_jig.cmd.arg("foo.example").arg("-O").arg("status-text");

    // THEN output is text of status
    let assert = test_jig.cmd.assert();
    assert
        .success()
        .stdout("client delete prohibited\nclient transfer prohibited\nclient update prohibited\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_status_output_text() {
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
            .status("client delete prohibited")
            .status("client transfer prohibited")
            .status("client update prohibited")
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .status("server delete prohibited")
            .status("server transfer prohibited")
            .status("server update prohibited")
            .build(),
    )
    .await
    .expect("add bar domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with status-text output type
    test_jig.cmd.arg("foo.example").arg("-O").arg("status-text");

    // THEN output is text of status
    let assert = test_jig.cmd.assert();
    assert.success().stdout(
        r#"client delete prohibited
client transfer prohibited
client update prohibited
server delete prohibited
server transfer prohibited
server update prohibited
"#,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_status_output_json() {
    // GIVEN domain with status
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .status("client delete prohibited")
            .status("client transfer prohibited")
            .status("client update prohibited")
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with status-json output type
    test_jig.cmd.arg("bar.example").arg("-O").arg("status-json");

    // THEN output type is json with status
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"]
    });
    assert.success().stdout(format!("{}\n", expected_json));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_referral_with_status_output_json() {
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
            .status("client delete prohibited")
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .status("server delete prohibited")
            .build(),
    )
    .await
    .expect("add bar domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with status-json output type
    test_jig.cmd.arg("foo.example").arg("-O").arg("status-json");

    // THEN output type is json with status
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "status": ["client delete prohibited", "server delete prohibited"]
    });
    assert.success().stdout(format!("{}\n", expected_json));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_referral_for_only_registry_with_status_output_json() {
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
            .status("client delete prohibited")
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .status("server delete prohibited")
            .build(),
    )
    .await
    .expect("add bar domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with status-json output type and ask for registry only
    test_jig
        .cmd
        .arg("foo.example")
        .arg("-O")
        .arg("status-json")
        .arg("--registry");

    // THEN output type is json with status
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "status": ["client delete prohibited"]
    });
    assert.success().stdout(format!("{}\n", expected_json));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_referral_for_only_registrar_with_status_output_json() {
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
            .status("client delete prohibited")
            .build(),
    )
    .await
    .expect("add foo domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .status("server delete prohibited")
            .build(),
    )
    .await
    .expect("add bar domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with status-json output type and ask for registry only
    test_jig
        .cmd
        .arg("foo.example")
        .arg("-O")
        .arg("status-json")
        .arg("--registrar");

    // THEN output type is json with status
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "status": ["server delete prohibited"]
    });
    assert.success().stdout(format!("{}\n", expected_json));
}
