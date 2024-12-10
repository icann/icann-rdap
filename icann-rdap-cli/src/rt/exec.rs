//! Function to execute tests.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_client::client::{AsyncClient, ClientConnection, ClientHandle};
use hickory_client::rr::{DNSClass, Name, RecordType};
use hickory_client::udp::UdpClientConnection;
use icann_rdap_client::client::create_client_with_addr;
use icann_rdap_client::{create_client, rdap_url_request, ClientConfig};
use icann_rdap_client::{
    query::bootstrap::{qtype_to_bootstrap_url, BootstrapStore},
    QueryType, RdapClientError,
};
use reqwest::Url;
use thiserror::Error;
use tracing::debug;
use url::ParseError;

use crate::rt::results::TestRun;

use super::results::TestResults;

#[derive(Default)]
pub struct TestOptions {}

#[derive(Debug, Error)]
pub enum TestError {
    #[error(transparent)]
    RdapClient(#[from] RdapClientError),
    #[error(transparent)]
    UrlParseError(#[from] ParseError),
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error("No host to resolve")]
    NoHostToResolve,
    #[error("No rdata")]
    NoRdata,
    #[error("Bad rdata")]
    BadRdata,
    #[error(transparent)]
    Client(#[from] reqwest::Error),
}

pub async fn execute_tests<'a, BS: BootstrapStore>(
    bs: &BS,
    value: &QueryType,
    _options: &TestOptions,
    client_config: &ClientConfig,
) -> Result<TestResults, TestError> {
    let bs_client = create_client(client_config)?;
    let base_url = qtype_to_bootstrap_url(&bs_client, bs, value, |reg| {
        debug!("Fetching IANA registry {} for value {value}", reg.url())
    })
    .await?;
    let parsed_url = Url::parse(&base_url)?;
    let port = parsed_url.port().unwrap_or_else(|| {
        if parsed_url.scheme().eq("https") {
            443
        } else {
            80
        }
    });
    let host = parsed_url.host_str().ok_or(TestError::NoHostToResolve)?;
    debug!("Using base URL {base_url}");

    let query_url = value.query_url(&base_url)?;
    let mut test_results = TestResults::new(query_url.clone());

    let (v4s, v6s) = get_dns_records(host).await?;
    for v4 in v4s {
        let mut test_run = TestRun::new_v4(v4, port);
        let client = create_client_with_addr(client_config, host, test_run.socket_addr)?;
        let rdap_response = rdap_url_request(&query_url, &client).await;
        test_run = test_run.end(rdap_response);
        test_results.add_test_run(test_run);
    }
    for v6 in v6s {
        let mut test_run = TestRun::new_v6(v6, port);
        let client = create_client_with_addr(client_config, host, test_run.socket_addr)?;
        let rdap_response = rdap_url_request(&query_url, &client).await;
        test_run = test_run.end(rdap_response);
        test_results.add_test_run(test_run);
    }

    test_results.end();
    Ok(test_results)
}

async fn get_dns_records(host: &str) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), TestError> {
    let mut v4s = vec![];
    let mut v6s = vec![];

    let conn = UdpClientConnection::new("8.8.8.8:53".parse()?)
        .unwrap()
        .new_stream(None);
    let (mut client, bg) = AsyncClient::connect(conn).await.unwrap();

    // make sure to run the background task
    tokio::spawn(bg);

    // Create a query future
    let query = client.query(Name::from_str(host).unwrap(), DNSClass::IN, RecordType::A);

    // wait for its response
    let response = query.await.unwrap();

    for answer in response.answers() {
        let addr = answer
            .data()
            .ok_or(TestError::NoRdata)?
            .clone()
            .into_a()
            .map_err(|_e| TestError::BadRdata)?
            .0;
        v4s.push(addr);
        debug!("Found {addr}");
    }

    // Create a query future
    let query = client.query(
        Name::from_str(host).unwrap(),
        DNSClass::IN,
        RecordType::AAAA,
    );

    // wait for its response
    let response = query.await.unwrap();

    for answer in response.answers() {
        let addr = answer
            .data()
            .ok_or(TestError::NoRdata)?
            .clone()
            .into_aaaa()
            .map_err(|_e| TestError::BadRdata)?
            .0;
        v6s.push(addr);
        debug!("Found {addr}");
    }

    Ok((v4s, v6s))
}
