//! Function to execute tests.

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
use tracing::{debug, info};
use url::ParseError;

use crate::rt::results::TestRun;

use super::results::{DnsData, TestResults};

#[derive(Default)]
pub struct TestOptions {
    pub skip_v4: bool,
    pub skip_v6: bool,
}

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
    #[error("UnsupporteQueryType")]
    UnsupportedQueryType,
}

pub async fn execute_tests<'a, BS: BootstrapStore>(
    bs: &BS,
    value: &QueryType,
    options: &TestOptions,
    client_config: &ClientConfig,
) -> Result<TestResults, TestError> {
    let bs_client = create_client(client_config)?;
    let query_url = match value {
        QueryType::Help => return Err(TestError::UnsupportedQueryType),
        QueryType::Url(url) => url.to_owned(),
        _ => {
            let base_url = qtype_to_bootstrap_url(&bs_client, bs, value, |reg| {
                debug!("Fetching IANA registry {} for value {value}", reg.url())
            })
            .await?;
            value.query_url(&base_url)?
        }
    };
    let parsed_url = Url::parse(&query_url)?;
    let port = parsed_url.port().unwrap_or_else(|| {
        if parsed_url.scheme().eq("https") {
            443
        } else {
            80
        }
    });
    let host = parsed_url.host_str().ok_or(TestError::NoHostToResolve)?;

    info!("Testing {query_url}");
    let dns_data = get_dns_records(host).await?;
    let mut test_results = TestResults::new(query_url.clone(), dns_data.clone());

    for v4 in dns_data.v4_addrs {
        let mut test_run = TestRun::new_v4(v4, port);
        if !options.skip_v4 {
            let client = create_client_with_addr(client_config, host, test_run.socket_addr)?;
            let rdap_response = rdap_url_request(&query_url, &client).await;
            test_run = test_run.end(rdap_response);
        }
        test_results.add_test_run(test_run);
    }
    for v6 in dns_data.v6_addrs {
        let mut test_run = TestRun::new_v6(v6, port);
        if !options.skip_v6 {
            let client = create_client_with_addr(client_config, host, test_run.socket_addr)?;
            let rdap_response = rdap_url_request(&query_url, &client).await;
            test_run = test_run.end(rdap_response);
        }
        test_results.add_test_run(test_run);
    }

    test_results.end();
    info!("Testing complete.");
    Ok(test_results)
}

async fn get_dns_records(host: &str) -> Result<DnsData, TestError> {
    let conn = UdpClientConnection::new("8.8.8.8:53".parse()?)
        .unwrap()
        .new_stream(None);
    let (mut client, bg) = AsyncClient::connect(conn).await.unwrap();

    // make sure to run the background task
    tokio::spawn(bg);

    let mut dns_data = DnsData::default();

    // Create a query future
    let query = client.query(Name::from_str(host).unwrap(), DNSClass::IN, RecordType::A);

    // wait for its response
    let response = query.await.unwrap();

    for answer in response.answers() {
        match answer.record_type() {
            RecordType::CNAME => {
                let cname = answer
                    .data()
                    .ok_or(TestError::NoRdata)?
                    .clone()
                    .into_cname()
                    .map_err(|_e| TestError::BadRdata)?
                    .0
                    .to_string();
                debug!("Found cname {cname}");
                dns_data.v4_cname = Some(cname);
            }
            RecordType::A => {
                let addr = answer
                    .data()
                    .ok_or(TestError::NoRdata)?
                    .clone()
                    .into_a()
                    .map_err(|_e| TestError::BadRdata)?
                    .0;
                debug!("Found IPv4 {addr}");
                dns_data.v4_addrs.push(addr);
            }
            _ => {
                // do nothing
            }
        };
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
        match answer.record_type() {
            RecordType::CNAME => {
                let cname = answer
                    .data()
                    .ok_or(TestError::NoRdata)?
                    .clone()
                    .into_cname()
                    .map_err(|_e| TestError::BadRdata)?
                    .0
                    .to_string();
                debug!("Found cname {cname}");
                dns_data.v6_cname = Some(cname);
            }
            RecordType::AAAA => {
                let addr = answer
                    .data()
                    .ok_or(TestError::NoRdata)?
                    .clone()
                    .into_aaaa()
                    .map_err(|_e| TestError::BadRdata)?
                    .0;
                debug!("Found IPv6 {addr}");
                dns_data.v6_addrs.push(addr);
            }
            _ => {
                // do nothing
            }
        };
    }

    Ok(dns_data)
}
