use {icann_rdap_common::prelude::Autnum, icann_rdap_srv::storage::StoreOps};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_autnum_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnum/705", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["startAutnum"].as_i64(), Some(700));
    assert_eq!(body["endAutnum"].as_i64(), Some(710));
}

#[tokio::test]
async fn test_server_autnum_lookup_not_found() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnum/800", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn test_server_autnum_lookup_at_range_boundary() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnum/700", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["startAutnum"].as_i64(), Some(700));
    assert_eq!(body["endAutnum"].as_i64(), Some(710));
}

#[tokio::test]
async fn test_server_autnum_lookup_at_range_end() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnum/709", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["startAutnum"].as_i64(), Some(700));
    assert_eq!(body["endAutnum"].as_i64(), Some(710));
}
