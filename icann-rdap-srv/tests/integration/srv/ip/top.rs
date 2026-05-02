use {
    icann_rdap_common::response::Network,
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_rdap_top_ipv4() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_top_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-top/10.1.0.1", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let cidr0_cidrs = body["cidr0_cidrs"].as_array().expect("cidr0_cidrs");
    let cidr = cidr0_cidrs.first().expect("cidr");
    assert_eq!(cidr["v4prefix"].as_str(), Some("10.0.0.0"));
    assert_eq!(cidr["length"].as_u64(), Some(8));
}

#[tokio::test]
async fn test_server_rdap_top_disabled() {
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
    let url = format!("{}/ips/rirSearch1/rdap-top/10.1.0.1", test_srv.rdap_base);
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
async fn test_server_rdap_top_no_network() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_top_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("10.1.0.0/32")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-top/192.168.1.1", test_srv.rdap_base);
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
async fn test_server_rdap_top_cidr() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_top_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-top/10.1.0.0/24", test_srv.rdap_base);
    let response = client
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await
        .expect("request");

    // THEN
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    let cidr0_cidrs = body["cidr0_cidrs"].as_array().expect("cidr0_cidrs");
    let cidr = cidr0_cidrs.first().expect("cidr");
    assert_eq!(cidr["v4prefix"].as_str(), Some("10.0.0.0"));
    assert_eq!(cidr["length"].as_u64(), Some(8));
}

#[tokio::test]
async fn test_server_rdap_top_ipv6() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_top_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::/64"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/ips/rirSearch1/rdap-top/2001:db8:1::1",
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
    let cidr0_cidrs = body["cidr0_cidrs"].as_array().expect("cidr0_cidrs");
    let cidr = cidr0_cidrs.first().expect("cidr");
    assert_eq!(cidr["v6prefix"].as_str(), Some("2001:db8::"));
    assert_eq!(cidr["length"].as_u64(), Some(32));
}
