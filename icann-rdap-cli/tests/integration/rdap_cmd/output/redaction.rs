use {
    icann_rdap_common::prelude::{
        redacted::{Method, Name, Redacted},
        Domain,
    },
    icann_rdap_srv::storage::StoreOps,
    serde_json::json,
};

use crate::test_jig::TestJig;

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_redaction_env() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    let redactions = vec![Redacted::builder()
        .name(Name::builder().type_field("Domain ID").build())
        .method(Method::Removal)
        .build()];
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .redacted(redactions)
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with event json output type
    test_jig.cmd.arg("bar.example").arg("-O").arg("json");
    test_jig.cmd.env(
        "RDAP_REDACTION_FLAGS",
        "show-rfc9537,do-not-simplify-rfc9537",
    );

    // THEN
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "rdapConformance":["redacted"],
        "objectClassName": "domain",
        "redacted": [{
            "name": {"type": "Domain ID"},
            "method": "removal"
        }],
        "ldhName": "bar.example"
    });
    assert.success().stdout(format!("{}\n", expected_json));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_redaction_flags() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    let redactions = vec![Redacted::builder()
        .name(Name::builder().type_field("Domain ID").build())
        .method(Method::Removal)
        .build()];
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .redacted(redactions)
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with event json output type
    test_jig
        .cmd
        .arg("bar.example")
        .arg("-O")
        .arg("json")
        .arg("--redaction-flag")
        .arg("show-rfc9537")
        .arg("--redaction-flag")
        .arg("do-not-simplify-rfc9537");

    // THEN
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "rdapConformance":["redacted"],
        "objectClassName": "domain",
        "redacted": [{
            "name": {"type": "Domain ID"},
            "method": "removal"
        }],
        "ldhName": "bar.example"
    });
    assert.success().stdout(format!("{}\n", expected_json));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_simple_redaction_flags() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    let redactions = vec![Redacted::builder()
        .name(Name::builder().type_field("Registry Domain ID").build())
        .method(Method::Removal)
        .build()];
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .redacted(redactions)
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with event json output type
    test_jig
        .cmd
        .arg("bar.example")
        .arg("-O")
        .arg("json")
        .arg("--redaction-flag")
        .arg("show-rfc9537");

    // THEN
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "rdapConformance":["redacted"],
        "objectClassName": "domain",
        "handle": "////REDACTED_ID////",
        "remarks": [{
            "title": "RFC9537 to Simple Redactions",
            "description": ["ID redacted."],
            "simpleRedaction_keys": ["////REDACTED_ID////"]
        }],
        "redacted": [{
            "name": {"type": "Registry Domain ID"},
            "method": "removal"
        }],
        "ldhName": "bar.example"
    });
    assert.success().stdout(format!("{}\n", expected_json));
}
