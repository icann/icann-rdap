use {
    icann_rdap_common::prelude::Autnum,
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

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

#[tokio::test]
async fn test_server_autnum_rdap_up() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_up_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-up/705", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 1);
    let autnum = results.first().expect("autnum");
    assert_eq!(autnum["startAutnum"].as_i64(), Some(700));
    assert_eq!(autnum["endAutnum"].as_i64(), Some(710));
}

#[tokio::test]
async fn test_server_autnum_rdap_up_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-up/705", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 501);
}

#[tokio::test]
async fn test_server_autnum_rdap_top() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_top_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-top/705", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 1);
    let autnum = results.first().expect("autnum");
    assert_eq!(autnum["startAutnum"].as_i64(), Some(700));
    assert_eq!(autnum["endAutnum"].as_i64(), Some(710));
}

#[tokio::test]
async fn test_server_autnum_rdap_top_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-top/705", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 501);
}

#[tokio::test]
async fn test_server_autnum_rdap_top_range() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_top_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/autnums/rirSearch1/rdap-top/700-710",
        test_srv.rdap_base
    );
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 1);
    let autnum = results.first().expect("autnum");
    assert_eq!(autnum["startAutnum"].as_i64(), Some(700));
    assert_eq!(autnum["endAutnum"].as_i64(), Some(710));
}

#[tokio::test]
async fn test_server_autnum_rdap_down() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_down_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..709).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(710..719).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-down/700-720", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_server_autnum_rdap_down_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-down/700", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 501);
}

#[tokio::test]
async fn test_server_autnum_rdap_down_no_children() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_down_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-down/800", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_server_autnum_rdap_down_range() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_down_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/autnums/rirSearch1/rdap-down/699-720",
        test_srv.rdap_base
    );
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_server_autnum_rdap_bottom() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_bottom_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-bottom/705", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 1);
    let autnum = results.first().expect("autnum");
    assert_eq!(autnum["startAutnum"].as_i64(), Some(700));
    assert_eq!(autnum["endAutnum"].as_i64(), Some(710));
}

#[tokio::test]
async fn test_server_autnum_rdap_bottom_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-bottom/700", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 501);
}

#[tokio::test]
async fn test_server_autnum_rdap_bottom_no_descendants() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_bottom_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-bottom/800", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_server_autnum_rdap_bottom_range() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_bottom_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/autnums/rirSearch1/rdap-bottom/800-900",
        test_srv.rdap_base
    );
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_server_autnum_rdap_up_no_supernet() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_up_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-up/800", test_srv.rdap_base);
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
async fn test_server_autnum_rdap_up_empty() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_up_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/autnums/rirSearch1/rdap-up/700", test_srv.rdap_base);
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
async fn test_server_autnum_rdap_up_range() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_up_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/autnums/rirSearch1/rdap-up/700-710",
        test_srv.rdap_base
    );
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["autnumSearchResults"].as_array().expect("autnumSearchResults");
    assert_eq!(results.len(), 1);
    let autnum = results.first().expect("autnum");
    assert_eq!(autnum["startAutnum"].as_i64(), Some(700));
    assert_eq!(autnum["endAutnum"].as_i64(), Some(710));
}

#[tokio::test]
async fn test_server_autnum_rdap_up_range_not_exact() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_up_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_autnum(&Autnum::builder().autnum_range(700..720).build())
        .await
        .expect("add autnum in tx");
    tx.add_autnum(&Autnum::builder().autnum_range(700..710).build())
        .await
        .expect("add autnum in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/autnums/rirSearch1/rdap-up/700-715",
        test_srv.rdap_base
    );
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
async fn test_server_autnum_rdap_up_invalid_asn() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_up_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/autnums/rirSearch1/rdap-up/notanumber",
        test_srv.rdap_base
    );
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn test_server_autnum_rdap_up_invalid_range() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .autnum_rdap_up_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/autnums/rirSearch1/rdap-up/abc-def",
        test_srv.rdap_base
    );
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 400);
}
