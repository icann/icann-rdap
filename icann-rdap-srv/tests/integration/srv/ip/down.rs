use {
    icann_rdap_common::response::Network,
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_rdap_down_ipv4() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_down_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.1.2.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-down/10.0.0.0/8", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["ipSearchResults"].as_array().expect("ipSearchResults");
    assert_eq!(results.len(), 1);
    let network = results.first().expect("network");
    let cidr0_cidrs = network["cidr0_cidrs"].as_array().expect("cidr0_cidrs");
    let cidr = cidr0_cidrs.first().expect("cidr");
    assert_eq!(cidr["v4prefix"].as_str(), Some("10.1.0.0"));
    assert_eq!(cidr["length"].as_u64(), Some(16));
}

#[tokio::test]
async fn test_server_rdap_down_ipv6() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_down_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:2::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/ips/rirSearch1/rdap-down/2001:db8::/32",
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
    let results = body["ipSearchResults"].as_array().expect("ipSearchResults");
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_server_rdap_down_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-down/10.0.0.0/8", test_srv.rdap_base);
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
async fn test_server_rdap_down_no_children() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_down_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("10.0.0.0/24")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/ips/rirSearch1/rdap-down/10.0.0.0/24",
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
    let results = body["ipSearchResults"].as_array().expect("ipSearchResults");
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_server_rdap_down_cidr() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_down_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.1.2.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-down/10.0.0.0/8", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let results = body["ipSearchResults"].as_array().expect("ipSearchResults");
    assert_eq!(results.len(), 1);
}
