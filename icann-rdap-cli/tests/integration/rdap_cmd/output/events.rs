use {
    icann_rdap_common::prelude::Event, icann_rdap_common::response::Domain,
    icann_rdap_srv::storage::StoreOps, serde_json::json,
};

use crate::test_jig::TestJig;

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
