use {
    icann_rdap_client::{
        http::{create_client, ClientConfig},
        rdap::{rdap_request, QueryType},
    },
    icann_rdap_common::{
        prelude::RdapResponse,
        response::{Domain, Nameserver, Network},
    },
    icann_rdap_srv::{config::CommonConfig, storage::StoreOps},
};

use crate::test_jig::SrvTestJig;

#[tokio::test]
async fn test_server_domain_query() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("foo.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_server_idn_query() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(
        &Domain::idn()
            .unicode_name("café.example")
            .ldh_name("cafe.example")
            .build(),
    )
    .await
    .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::domain("café.example").expect("invalid domain name");
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_server_search_disabled_for_query_domain() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_name_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNameSearch("foo.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_search_enabled_for_query_domain() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("foo.example").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNameSearch("foo.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::DomainSearchResults(results) = response.rdap else {
        panic!("not domain search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_search_disabled_for_query_domain_by_ns_ip() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ip_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsIpSearch("192.0.2.1".parse().unwrap());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_search_enabled_for_query_domain_by_ns_ip() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ip_enable(true)
        .nameserver_search_by_ip_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsIpSearch("192.0.2.1".parse().unwrap());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::DomainSearchResults(results) = response.rdap else {
        panic!("not domain search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_search_domain_by_ns_ip_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ip_enable(true)
        .nameserver_search_by_ip_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .addresses(vec!["192.0.2.1".to_string()])
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for IP that doesn't exist
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsIpSearch("192.0.2.99".parse().unwrap());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns 200 with empty results (RFC 9082)
    assert_eq!(response.http_data.status_code, 200);
}

#[tokio::test]
async fn test_server_search_disabled_for_query_domain_by_ns_ldh_name() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ldh_name_enable(false)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsNameSearch("ns1.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("valid response");

    // THEN
    assert_eq!(response.http_data.status_code(), 501);
}

#[tokio::test]
async fn test_server_search_enabled_for_query_domain_by_ns_ldh_name() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ldh_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsNameSearch("ns1.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::DomainSearchResults(results) = response.rdap else {
        panic!("not domain search results")
    };
    assert_eq!(results.results().len(), 1);
}

#[tokio::test]
async fn test_server_search_domain_by_ns_ldh_name_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_search_by_ns_ldh_name_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    let domain = Domain::builder()
        .ldh_name("foo.example")
        .nameservers(vec![Nameserver::builder()
            .ldh_name("ns1.example")
            .build()
            .unwrap()])
        .build();
    tx.add_domain(&domain).await.expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN - search for nameserver that doesn't exist
    let client_config = ClientConfig::builder()
        .https_only(false)
        .follow_redirects(false)
        .build();
    let client = create_client(&client_config).expect("creating client");
    let query = QueryType::DomainNsNameSearch("ns99.*".to_string());
    let response = rdap_request(&test_srv.rdap_base, &query, &client)
        .await
        .expect("querying server");

    // THEN - returns 200 with empty results (RFC 9082)
    assert_eq!(response.http_data.status_code, 200);
    let RdapResponse::DomainSearchResults(results) = response.rdap else {
        panic!("not domain search results")
    };
    assert_eq!(results.results().len(), 0);
}

#[tokio::test]
async fn test_server_rdap_up_domain() {
    // GIVEN
    let common_config = CommonConfig::builder().domain_rdap_up_enable(true).build();
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
    tx.add_domain(
        &Domain::builder()
            .ldh_name("1.0.0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.1/32")
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
        "{}/domains/rirSearch1/rdap-up/1.0.0.10.in-addr.arpa",
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
async fn test_server_rdap_up_domain_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for ldh in ["10.in-addr.arpa", "1.10.in-addr.arpa"] {
        tx.add_domain(&Domain::builder().ldh_name(ldh).build())
            .await
            .expect("add domain in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-up/1.10.in-addr.arpa",
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
async fn test_server_rdap_up_domain_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder().domain_rdap_up_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("10.in-addr.arpa").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-up/10.in-addr.arpa",
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
async fn test_server_rdap_top_domain() {
    // GIVEN
    let common_config = CommonConfig::builder().domain_rdap_top_enable(true).build();
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
            .ldh_name("1.0.0.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.0.0.1/32")
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
        "{}/domains/rirSearch1/rdap-top/1.0.0.10.in-addr.arpa",
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
async fn test_server_rdap_top_domain_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for ldh in ["10.in-addr.arpa", "1.10.in-addr.arpa"] {
        tx.add_domain(&Domain::builder().ldh_name(ldh).build())
            .await
            .expect("add domain in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-top/1.10.in-addr.arpa",
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
async fn test_server_rdap_top_domain_not_found() {
    // GIVEN
    let common_config = CommonConfig::builder().domain_rdap_top_enable(true).build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("10.in-addr.arpa").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-top/2.10.in-addr.arpa",
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
async fn test_server_rdap_down_domain() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_rdap_down_enable(true)
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
            .ldh_name("1.10.in-addr.arpa")
            .network(
                Network::builder()
                    .cidr("10.1.0.0/16")
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
        "{}/domains/rirSearch1/rdap-down/10.in-addr.arpa",
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

#[tokio::test]
async fn test_server_rdap_down_domain_ipv6() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_rdap_down_enable(true)
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
            .ldh_name("2.0.0.0.d.8.0.0.ip6.arpa")
            .network(
                Network::builder()
                    .cidr("2001:db8:2000::/48")
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
        "{}/domains/rirSearch1/rdap-down/d.8.0.0.ip6.arpa",
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
async fn test_server_rdap_down_domain_disabled() {
    // GIVEN
    let test_srv = SrvTestJig::new().await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    for ldh in ["10.in-addr.arpa", "0.10.in-addr.arpa", "1.10.in-addr.arpa"] {
        tx.add_domain(&Domain::builder().ldh_name(ldh).build())
            .await
            .expect("add domain in tx");
    }
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-down/10.in-addr.arpa",
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
async fn test_server_rdap_down_domain_no_children() {
    // GIVEN
    let common_config = CommonConfig::builder()
        .domain_rdap_down_enable(true)
        .build();
    let test_srv = SrvTestJig::new_common_config(common_config).await;
    let mut tx = test_srv.mem.new_tx().await.expect("new transaction");
    tx.add_domain(&Domain::builder().ldh_name("10.in-addr.arpa").build())
        .await
        .expect("add domain in tx");
    tx.commit().await.expect("tx commit");

    // WHEN
    let client = reqwest::Client::new();
    let url = format!(
        "{}/domains/rirSearch1/rdap-down/10.in-addr.arpa",
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
