use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::{prelude::RdapResponse, response::Network},
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_ipv4_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV4Addr("192.0.2.1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv6_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("2001:db8::/32")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV6Addr("2001:db8::1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv4_cidr_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV4Cidr("192.0.2.0/24".parse().expect("cidr"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv6_cidr_lookup() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("2001:db8::/32")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV6Cidr("2001:db8::/32".parse().expect("cidr"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::Network(_) = response.rdap else {
        panic!("not network")
    };
}

#[tokio::test]
async fn test_server_ipv4_lookup_not_found() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("192.0.2.0/24")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV4Addr("203.0.113.1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 404);
}

#[tokio::test]
async fn test_server_ipv6_lookup_not_found() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_network(
        &Network::builder()
            .cidr("2001:db8::/32")
            .build()
            .expect("cidr parsing"),
    )
    .await
    .expect("add network in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::IpV6Addr("2001:db9::1".parse().expect("ip"));
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 404);
}

#[tokio::test]
async fn test_server_ipv4_cidr_prefix_too_long() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ip/192.0.2.0/33", test_srv.rdap_base);
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
async fn test_server_ipv6_cidr_prefix_too_long() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ip/2001:db8::/129", test_srv.rdap_base);
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
async fn test_server_rdap_up_ipv4() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_up_enable(true).build();
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
    let url = format!("{}/ips/rirSearch1/rdap-up/10.1.0.1", test_srv.rdap_base);
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
    assert_eq!(cidr["v4prefix"].as_str(), Some("10.1.0.0"));
    assert_eq!(cidr["length"].as_u64(), Some(16));
}

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
    let url = format!("{}/ips/rirSearch1/rdap-down/2001:db8::/32", test_srv.rdap_base);
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
    let url = format!("{}/ips/rirSearch1/rdap-down/10.0.0.0/24", test_srv.rdap_base);
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

#[tokio::test]
async fn test_server_rdap_up_ipv6() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_up_enable(true).build();
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
        "{}/ips/rirSearch1/rdap-up/2001:db8:1::1",
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
    assert_eq!(cidr["v6prefix"].as_str(), Some("2001:db8:1::"));
    assert_eq!(cidr["length"].as_u64(), Some(48));
}

#[tokio::test]
async fn test_server_rdap_bottom_ipv4() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_bottom_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-bottom/10.0.0.0/8", test_srv.rdap_base);
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
    assert_eq!(cidr["v4prefix"].as_str(), Some("10.1.2.128"));
    assert_eq!(cidr["length"].as_u64(), Some(25));
}

#[tokio::test]
async fn test_server_rdap_bottom_ipv6() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_bottom_enable(true).build();
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
    let url = format!("{}/ips/rirSearch1/rdap-bottom/2001:db8::/32", test_srv.rdap_base);
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

#[tokio::test]
async fn test_server_rdap_bottom_disabled() {
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
    let url = format!("{}/ips/rirSearch1/rdap-bottom/10.0.0.0/8", test_srv.rdap_base);
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
async fn test_server_rdap_bottom_no_descendants() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_bottom_enable(true).build();
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
    let url = format!("{}/ips/rirSearch1/rdap-bottom/10.0.0.0/24", test_srv.rdap_base);
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
async fn test_server_rdap_bottom_cidr() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_bottom_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-bottom/10.0.0.0/8", test_srv.rdap_base);
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

#[tokio::test]
async fn test_server_rdap_up_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.1.0.0/8", "10.1.0.0/16"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-up/10.1.0.1", test_srv.rdap_base);
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
async fn test_server_rdap_up_no_supernet() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_up_enable(true).build();
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
    let url = format!("{}/ips/rirSearch1/rdap-up/10.1.0.1", test_srv.rdap_base);
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
async fn test_server_rdap_up_ipv4_at_boundary() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_up_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.0.0.0/8", "10.1.0.0/16"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-up/10.1.0.0", test_srv.rdap_base);
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
async fn test_server_rdap_up_ipv6_at_boundary() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_up_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["2001:db8::/32", "2001:db8:1::/48"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-up/2001:db8:1::", test_srv.rdap_base);
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

#[tokio::test]
async fn test_server_rdap_up_cidr() {
    // GIVEN
    let common_config = CommonConfig::builder().ip_rdap_up_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for cidr in ["10.1.0.0/16", "10.1.0.0/24"] {
        tx.add_network(&Network::builder().cidr(cidr).build().expect("cidr parsing"))
            .await
            .expect("add network in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!("{}/ips/rirSearch1/rdap-up/10.1.0.0/24", test_srv.rdap_base);
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
    assert_eq!(cidr["v4prefix"].as_str(), Some("10.1.0.0"));
    assert_eq!(cidr["length"].as_u64(), Some(16));
}

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
