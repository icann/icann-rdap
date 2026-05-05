use super::*;

#[tokio::test]
async fn test_server_rdap_bottom_domain_ipv6() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_rdap_bottom_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("1.0.0.0.d.8.0.0.ip6.arpa")
            .network(
                Network::builder()
                    .cidr("2001:db8:1000::/48")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("1.0.0.0.0.0.0.0.d.8.0.0.ip6.arpa")
            .network(
                Network::builder()
                    .cidr("2001:db8:1000::/64")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-bottom/1.0.0.0.d.8.0.0.ip6.arpa",
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
}

#[tokio::test]
async fn test_server_rdap_bottom_domain() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_rdap_bottom_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/16")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.add_domain(
        &Domain::builder()
            .ldh_name("0.0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.0/24")
                    .build()
                    .expect("cidr parsing"),
            )
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-bottom/10.in-addr.arpa",
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
    let results = body["domainSearchResults"]
        .as_array()
        .expect("domainSearchResults");
    assert_eq!(results.len(), 1);
    let domain = results.first().expect("domain");
    assert_eq!(domain["ldhName"].as_str(), Some("0.0.10.in-addr.arpa"));
}

#[tokio::test]
async fn test_server_rdap_bottom_domain_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for ldh in [
        "10.in-addr.arpa",
        "0.10.in-addr.arpa",
        "0.0.10.in-addr.arpa",
    ] {
        tx.add_domain(&Domain::builder().ldh_name(ldh).build())
            .await
            .expect("add domain in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-bottom/10.in-addr.arpa",
        test_srv.rdap_base
    );
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
async fn test_server_rdap_bottom_domain_no_descendants() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_rdap_bottom_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("0.0.10.in-addr.arpa").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-bottom/0.0.10.in-addr.arpa",
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
    let results = body["domainSearchResults"]
        .as_array()
        .expect("domainSearchResults");
    assert_eq!(results.len(), 0);
}
