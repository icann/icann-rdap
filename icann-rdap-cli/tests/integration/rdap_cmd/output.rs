use {
    icann_rdap_common::{
        prelude::{
            redacted::{Method, Name, Redacted},
            Event, Link,
        },
        response::Domain,
    },
    icann_rdap_srv::storage::StoreOps,
    serde_json::{json, Value},
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

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_event_text_output() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .event(
                Event::builder()
                    .event_action("expiration")
                    .event_date("1990-12-31T23:59:59Z")
                    .build(),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with event text output type
    test_jig.cmd.arg("bar.example").arg("-O").arg("event-text");

    // THEN output type is the urls
    let assert = test_jig.cmd.assert();
    assert
        .success()
        .stdout("expiration = Mon, 31-Dec-1990 23:59:59 +00:00\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_with_event_json_output() {
    // GIVEN domain
    let mut test_jig = TestJig::new_rdap().await;
    let mut tx = test_jig.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("bar.example")
            .event(
                Event::builder()
                    .event_action("expiration")
                    .event_date("1990-12-31T23:59:59Z")
                    .build(),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN query with event json output type
    test_jig.cmd.arg("bar.example").arg("-O").arg("event-json");

    // THEN output type is the urls
    let assert = test_jig.cmd.assert();
    let expected_json = json!({
        "events": [{
            "eventAction": "expiration",
            "eventDate": "1990-12-31T23:59:59Z"
        }]
    });
    assert.success().stdout(format!("{}\n", expected_json));
}

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

    // THEN output type is the urls
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

    // THEN output type is the urls
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

    // THEN output type is the urls
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