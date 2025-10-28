//! Function to execute tests.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use icann_rdap_client::rdap::ResponseData;
use icann_rdap_common::{httpdata::HttpData, prelude::RdapResponse};

use {
    hickory_client::{
        client::{AsyncClient, ClientConnection, ClientHandle},
        error::ClientError,
        proto::error::ProtoError,
        rr::{DNSClass, Name, RecordType},
        udp::UdpClientConnection,
    },
    icann_rdap_client::{
        http::{create_client, create_client_with_addr, ClientConfig},
        iana::{qtype_to_bootstrap_url, BootstrapStore},
        rdap::{rdap_url_request, QueryType},
        RdapClientError,
    },
    icann_rdap_common::response::{get_related_links, ExtensionId},
    reqwest::{header::HeaderValue, Url},
    thiserror::Error,
    tracing::{debug, info},
    url::ParseError,
};

use crate::rt::results::{HttpResults, RunFeature, TestRun};

use super::results::{DnsData, StringResult, TestResults};

pub struct TestOptions {
    pub test_type: TestType,
    pub expect_extensions: Vec<String>,
    pub expect_groups: Vec<ExtensionGroup>,
    pub allow_unregistered_extensions: bool,
}

impl Default for TestOptions {
    fn default() -> Self {
        Self {
            test_type: TestType::String(StringTestOptions {
                json: String::default(),
            }),
            expect_extensions: vec![],
            expect_groups: vec![],
            allow_unregistered_extensions: false,
        }
    }
}

#[derive(Clone)]
pub enum TestType {
    Http(HttpTestOptions),
    String(StringTestOptions),
}

#[derive(Clone)]
pub struct HttpTestOptions {
    pub value: QueryType,
    pub client_config: ClientConfig,
    pub skip_v4: bool,
    pub skip_v6: bool,
    pub skip_origin: bool,
    pub origin_value: String,
    pub chase_referral: bool,
    pub one_addr: bool,
    pub dns_resolver: Option<String>,
}

#[derive(Clone)]
pub struct StringTestOptions {
    pub json: String,
}

#[derive(Clone)]
pub enum ExtensionGroup {
    Gtld,
    Nro,
    NroAsn,
}

#[derive(Debug, Error)]
pub enum TestExecutionError {
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
    #[error(transparent)]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
    #[error("Unsupporte Query Type")]
    UnsupportedQueryType,
    #[error("No referral to chase")]
    NoReferralToChase,
    #[error("Unregistered extension")]
    UnregisteredExtension,
    #[error("Hickory Client Error: {0}")]
    HickoryClient(#[from] ClientError),
    #[error("Hickory Proto Error: {0}")]
    HickoryProto(#[from] ProtoError),
}

pub async fn execute_tests<BS: BootstrapStore>(
    bs: &BS,
    options: &TestOptions,
) -> Result<TestResults, TestExecutionError> {
    match &options.test_type {
        TestType::Http(http_options) => execute_http_tests(bs, http_options, options).await,
        TestType::String(string_options) => execute_string_test(string_options, options),
    }
}

pub async fn execute_http_tests<BS: BootstrapStore>(
    bs: &BS,
    http_options: &HttpTestOptions,
    options: &TestOptions,
) -> Result<TestResults, TestExecutionError> {

    let bs_client = create_client(&http_options.client_config)?;

    // normalize extensions
    let extensions = normalize_extension_ids(options)?;
    let options = &TestOptions {
        test_type: options.test_type.clone(),
        expect_extensions: extensions,
        expect_groups: options.expect_groups.clone(),
        ..*options
    };

    // get the query url
    let mut query_url = match &http_options.value {
        QueryType::Help => return Err(TestExecutionError::UnsupportedQueryType),
        QueryType::Url(url) => url.to_owned(),
        _ => {
            let base_url = qtype_to_bootstrap_url(&bs_client, bs, &http_options.value, |reg| {
                info!(
                    "Fetching IANA registry {} for value {}",
                    reg.url(),
                    http_options.value
                )
            })
            .await?;
            http_options.value.query_url(&base_url)?
        }
    };
    // if the URL to test is a referral
    if http_options.chase_referral {
        let client = create_client(&http_options.client_config)?;
        info!("Fetching referral from {query_url}");
        let response_data = rdap_url_request(&query_url, &client).await?;
        query_url = get_related_links(&response_data.rdap)
            .first()
            .ok_or(TestExecutionError::NoReferralToChase)?
            .to_string();
        info!("Referral is {query_url}");
    }

    let parsed_url = Url::parse(&query_url)?;
    let port = parsed_url.port().unwrap_or_else(|| {
        if parsed_url.scheme().eq("https") {
            443
        } else {
            80
        }
    });
    let host = parsed_url
        .host_str()
        .ok_or(TestExecutionError::NoHostToResolve)?;

    info!("Testing {query_url}");
    let dns_data = get_dns_records(host, http_options).await?;
    let mut http_results = HttpResults::new(query_url.clone(), dns_data.clone());

    let mut more_runs = true;
    for v4 in dns_data.v4_addrs {
        // test run without origin
        let mut test_run = TestRun::new_v4(vec![], v4, port);
        if !http_options.skip_v4 && more_runs {
            let client = create_client_with_addr(
                &http_options.client_config,
                host,
                test_run.socket_addr.expect("socket"),
            )?;
            info!(
                "Sending request to {}",
                test_run.socket_addr.expect("socket")
            );
            let rdap_response = rdap_url_request(&query_url, &client).await;
            test_run = test_run.end(rdap_response, options);
        }
        http_results.add_test_run(test_run);

        // test run with origin
        let mut test_run = TestRun::new_v4(vec![RunFeature::OriginHeader], v4, port);
        if !http_options.skip_v4 && !http_options.skip_origin && more_runs {
            let client_config = ClientConfig::from_config(&http_options.client_config)
                .origin(HeaderValue::from_str(&http_options.origin_value)?)
                .build();
            let client = create_client_with_addr(
                &client_config,
                host,
                test_run.socket_addr.expect("socket"),
            )?;
            info!(
                "Sending request to {}",
                test_run.socket_addr.expect("socket")
            );
            let rdap_response = rdap_url_request(&query_url, &client).await;
            test_run = test_run.end(rdap_response, options);
        }
        http_results.add_test_run(test_run);
        if http_options.one_addr {
            more_runs = false;
        }
    }

    let mut more_runs = true;
    for v6 in dns_data.v6_addrs {
        // test run without origin
        let mut test_run = TestRun::new_v6(vec![], v6, port);
        if !http_options.skip_v6 && more_runs {
            let client = create_client_with_addr(
                &http_options.client_config,
                host,
                test_run.socket_addr.expect("socket"),
            )?;
            info!(
                "Sending request to {}",
                test_run.socket_addr.expect("socket")
            );
            let rdap_response = rdap_url_request(&query_url, &client).await;
            test_run = test_run.end(rdap_response, options);
        }
        http_results.add_test_run(test_run);

        // test run with origin
        let mut test_run = TestRun::new_v6(vec![RunFeature::OriginHeader], v6, port);
        if !http_options.skip_v6 && !http_options.skip_origin && more_runs {
            let client_config = ClientConfig::from_config(&http_options.client_config)
                .origin(HeaderValue::from_str(&http_options.origin_value)?)
                .build();
            let client = create_client_with_addr(
                &client_config,
                host,
                test_run.socket_addr.expect("socket"),
            )?;
            info!(
                "Sending request to {}",
                test_run.socket_addr.expect("socket")
            );
            let rdap_response = rdap_url_request(&query_url, &client).await;
            test_run = test_run.end(rdap_response, options);
        }
        http_results.add_test_run(test_run);
        if http_options.one_addr {
            more_runs = false;
        }
    }

    http_results.end(options);
    info!("Testing complete.");
    Ok(TestResults::Http(http_results))
}

async fn get_dns_records(
    host: &str,
    http_options: &HttpTestOptions,
) -> Result<DnsData, TestExecutionError> {

    // short circuit dns if these are ip addresses
    if let Ok(ip4) = Ipv4Addr::from_str(host) {
        return Ok(DnsData {
            v4_cname: None,
            v6_cname: None,
            v4_addrs: vec![ip4],
            v6_addrs: vec![],
        });
    } else if let Ok(ip6) = Ipv6Addr::from_str(host.trim_start_matches('[').trim_end_matches(']')) {
        return Ok(DnsData {
            v4_cname: None,
            v6_cname: None,
            v4_addrs: vec![],
            v6_addrs: vec![ip6],
        });
    }

    let def_dns_resolver = "8.8.8.8:53".to_string();
    let dns_resolver = http_options
        .dns_resolver
        .as_ref()
        .unwrap_or(&def_dns_resolver);
    let conn = UdpClientConnection::new(dns_resolver.parse()?)?
        .new_stream(None);
    let (mut client, bg) = AsyncClient::connect(conn).await?;

    // make sure to run the background task
    tokio::spawn(bg);

    let mut dns_data = DnsData::default();

    // Create a query future
    let query = client.query(Name::from_str(host)?, DNSClass::IN, RecordType::A);

    // wait for its response
    let response = query.await?;

    for answer in response.answers() {
        match answer.record_type() {
            RecordType::CNAME => {
                let cname = answer
                    .data()
                    .ok_or(TestExecutionError::NoRdata)?
                    .clone()
                    .into_cname()
                    .map_err(|_e| TestExecutionError::BadRdata)?
                    .0
                    .to_string();
                debug!("Found cname {cname}");
                dns_data.v4_cname = Some(cname);
            }
            RecordType::A => {
                let addr = answer
                    .data()
                    .ok_or(TestExecutionError::NoRdata)?
                    .clone()
                    .into_a()
                    .map_err(|_e| TestExecutionError::BadRdata)?
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
        Name::from_str(host)?,
        DNSClass::IN,
        RecordType::AAAA,
    );

    // wait for its response
    let response = query.await?;

    for answer in response.answers() {
        match answer.record_type() {
            RecordType::CNAME => {
                let cname = answer
                    .data()
                    .ok_or(TestExecutionError::NoRdata)?
                    .clone()
                    .into_cname()
                    .map_err(|_e| TestExecutionError::BadRdata)?
                    .0
                    .to_string();
                debug!("Found cname {cname}");
                dns_data.v6_cname = Some(cname);
            }
            RecordType::AAAA => {
                let addr = answer
                    .data()
                    .ok_or(TestExecutionError::NoRdata)?
                    .clone()
                    .into_aaaa()
                    .map_err(|_e| TestExecutionError::BadRdata)?
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

pub fn execute_string_test(
    string_options: &StringTestOptions,
    options: &TestOptions,
) -> Result<TestResults, TestExecutionError> {
    let mut test_run = TestRun::new(vec![]);
    let rdap =
        serde_json::from_str::<RdapResponse>(&string_options.json).map_err(RdapClientError::Json);
    let res_data = match rdap {
        Ok(rdap) => Ok(ResponseData {
            rdap_type: "unknown".to_string(),
            rdap,
            http_data: HttpData::now().scheme("file").host("localhost").build(),
        }),
        Err(e) => Err(e),
    };
    test_run = test_run.end(res_data, options);
    let string_result = StringResult::new(test_run);
    Ok(TestResults::String(Box::new(string_result)))
}

fn normalize_extension_ids(options: &TestOptions) -> Result<Vec<String>, TestExecutionError> {
    let mut retval = options.expect_extensions.clone();

    // check for unregistered extensions
    if !options.allow_unregistered_extensions {
        for ext in &retval {
            if ExtensionId::from_str(ext).is_err() {
                return Err(TestExecutionError::UnregisteredExtension);
            }
        }
    }

    // put the groups in
    for group in &options.expect_groups {
        match group {
            ExtensionGroup::Gtld => {
                retval.push(format!(
                    "{}|{}",
                    ExtensionId::IcannRdapResponseProfile0,
                    ExtensionId::IcannRdapResponseProfile1
                ));
                retval.push(format!(
                    "{}|{}",
                    ExtensionId::IcannRdapTechnicalImplementationGuide0,
                    ExtensionId::IcannRdapTechnicalImplementationGuide1
                ));
            }
            ExtensionGroup::Nro => {
                retval.push(ExtensionId::NroRdapProfile0.to_string());
                retval.push(ExtensionId::Cidr0.to_string());
            }
            ExtensionGroup::NroAsn => {
                retval.push(ExtensionId::NroRdapProfile0.to_string());
                retval.push(format!(
                    "{}|{}",
                    ExtensionId::NroRdapProfileAsnFlat0,
                    ExtensionId::NroRdapProfileAsnHierarchical0
                ));
            }
        }
    }
    Ok(retval)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::response::ExtensionId;

    use crate::rt::exec::{ExtensionGroup, TestOptions};

    use super::normalize_extension_ids;

    #[test]
    fn GIVEN_gtld_WHEN_normalize_extensions_THEN_list_contains_gtld_ids() {
        // GIVEN
        let given = vec![ExtensionGroup::Gtld];

        // WHEN
        let options = TestOptions {
            expect_groups: given,
            ..Default::default()
        };
        let actual = normalize_extension_ids(&options).unwrap();

        // THEN
        let expected1 = format!(
            "{}|{}",
            ExtensionId::IcannRdapResponseProfile0,
            ExtensionId::IcannRdapResponseProfile1
        );
        assert!(actual.contains(&expected1));

        let expected2 = format!(
            "{}|{}",
            ExtensionId::IcannRdapTechnicalImplementationGuide0,
            ExtensionId::IcannRdapTechnicalImplementationGuide1
        );
        assert!(actual.contains(&expected2));
    }

    #[test]
    fn GIVEN_nro_and_foo_WHEN_normalize_extensions_THEN_list_contains_nro_ids_and_foo() {
        // GIVEN
        let groups = vec![ExtensionGroup::Nro];
        let exts = vec!["foo1".to_string()];

        // WHEN
        let options = TestOptions {
            allow_unregistered_extensions: true,
            expect_extensions: exts,
            expect_groups: groups,
            ..Default::default()
        };
        let actual = normalize_extension_ids(&options).unwrap();
        dbg!(&actual);

        // THEN
        assert!(actual.contains(&ExtensionId::NroRdapProfile0.to_string()));
        assert!(actual.contains(&ExtensionId::Cidr0.to_string()));
        assert!(actual.contains(&"foo1".to_string()));
    }

    #[test]
    fn GIVEN_nro_and_foo_WHEN_unreg_disallowed_THEN_err() {
        // GIVEN
        let groups = vec![ExtensionGroup::Nro];
        let exts = vec!["foo1".to_string()];

        // WHEN
        let options = TestOptions {
            expect_extensions: exts,
            expect_groups: groups,
            ..Default::default()
        };
        let actual = normalize_extension_ids(&options);

        // THEN
        assert!(actual.is_err())
    }

    #[test]
    fn GIVEN_unregistered_ext_WHEN_normalize_extensions_THEN_error() {
        // GIVEN
        let given = vec!["foo".to_string()];

        // WHEN
        let options = TestOptions {
            expect_extensions: given,
            ..Default::default()
        };
        let actual = normalize_extension_ids(&options);

        // THEN
        assert!(actual.is_err());
    }

    #[test]
    fn GIVEN_unregistered_ext_WHEN_allowed_THEN_no_error() {
        // GIVEN
        let given = vec!["foo".to_string()];

        // WHEN
        let options = TestOptions {
            expect_extensions: given,
            allow_unregistered_extensions: true,
            ..Default::default()
        };
        let actual = normalize_extension_ids(&options);

        // THEN
        assert!(actual.is_ok());
    }
}
