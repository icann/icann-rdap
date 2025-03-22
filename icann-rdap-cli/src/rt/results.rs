use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Contains the results of test execution.
use chrono::{DateTime, Utc};
use icann_rdap_client::{
    md::{string::StringUtil, table::MultiPartTable, MdOptions},
    rdap::ResponseData,
    RdapClientError,
};
use icann_rdap_common::{
    check::{traverse_checks, Check, CheckClass, CheckItem, CheckParams, Checks, GetChecks},
    response::{ExtensionId, RdapResponse},
};
use reqwest::StatusCode;
use serde::Serialize;
use strum_macros::Display;

use super::exec::TestOptions;

#[derive(Debug, Serialize)]
pub struct TestResults {
    pub query_url: String,
    pub dns_data: DnsData,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub service_checks: Vec<CheckItem>,
    pub test_runs: Vec<TestRun>,
}

impl TestResults {
    pub fn new(query_url: String, dns_data: DnsData) -> Self {
        Self {
            query_url,
            dns_data,
            start_time: Utc::now(),
            end_time: None,
            service_checks: vec![],
            test_runs: vec![],
        }
    }

    pub fn end(&mut self, options: &TestOptions) {
        self.end_time = Some(Utc::now());

        //service checks
        if self.dns_data.v4_cname.is_some() && self.dns_data.v4_addrs.is_empty() {
            self.service_checks
                .push(Check::CnameWithoutARecords.check_item());
        }
        if self.dns_data.v6_cname.is_some() && self.dns_data.v6_addrs.is_empty() {
            self.service_checks
                .push(Check::CnameWithoutAAAARecords.check_item());
        }
        if self.dns_data.v4_addrs.is_empty() {
            self.service_checks.push(Check::NoARecords.check_item());
        }
        if self.dns_data.v6_addrs.is_empty() {
            self.service_checks.push(Check::NoAAAARecords.check_item());

            // see if required by ICANN
            let tig0 = ExtensionId::IcannRdapTechnicalImplementationGuide0.to_string();
            let tig1 = ExtensionId::IcannRdapTechnicalImplementationGuide1.to_string();
            let both_tigs = format!("{tig0}|{tig1}");
            if options.expect_extensions.contains(&tig0)
                || options.expect_extensions.contains(&tig1)
                || options.expect_extensions.contains(&both_tigs)
            {
                self.service_checks
                    .push(Check::Ipv6SupportRequiredByIcann.check_item())
            }
        }
    }

    pub fn add_test_run(&mut self, test_run: TestRun) {
        self.test_runs.push(test_run);
    }

    pub fn to_md(&self, options: &MdOptions, check_classes: &[CheckClass]) -> String {
        let mut md = String::new();

        // h1
        md.push_str(&format!(
            "\n{}\n",
            self.query_url.to_owned().to_header(1, options)
        ));

        // table
        let mut table = MultiPartTable::new();

        // test results summary
        table = table.multi_raw(vec![
            "Start Time".to_inline(options),
            "End Time".to_inline(options),
            "Duration".to_inline(options),
            "Tested".to_inline(options),
        ]);
        let (end_time_s, duration_s) = if let Some(end_time) = self.end_time {
            (
                format_date_time(end_time),
                format!("{} s", (end_time - self.start_time).num_seconds()),
            )
        } else {
            ("FATAL".to_em(options), "N/A".to_string())
        };
        let tested = self
            .test_runs
            .iter()
            .filter(|r| matches!(r.outcome, RunOutcome::Tested))
            .count();
        table = table.multi_raw(vec![
            format_date_time(self.start_time),
            end_time_s,
            duration_s,
            format!("{tested} of {}", self.test_runs.len()),
        ]);

        // dns data
        table = table.multi_raw(vec![
            "DNS Query".to_inline(options),
            "DNS Answer".to_inline(options),
        ]);
        let v4_cname = if let Some(ref cname) = self.dns_data.v4_cname {
            cname.to_owned()
        } else {
            format!("{} A records", self.dns_data.v4_addrs.len())
        };
        table = table.multi_raw(vec!["A (v4)".to_string(), v4_cname]);
        let v6_cname = if let Some(ref cname) = self.dns_data.v6_cname {
            cname.to_owned()
        } else {
            format!("{} AAAA records", self.dns_data.v6_addrs.len())
        };
        table = table.multi_raw(vec!["AAAA (v6)".to_string(), v6_cname]);

        // summary of each run
        table = table.multi_raw(vec![
            "Address".to_inline(options),
            "Attributes".to_inline(options),
            "Duration".to_inline(options),
            "Outcome".to_inline(options),
        ]);
        for test_run in &self.test_runs {
            table = test_run.add_summary(table, options);
        }
        md.push_str(&table.to_md_table(options));

        md.push('\n');

        // checks that are about the service and not a particular test run
        if !self.service_checks.is_empty() {
            md.push_str(&"Service Checks".to_string().to_header(1, options));
            let mut table = MultiPartTable::new();

            table = table.multi_raw(vec!["Message".to_inline(options)]);
            for c in &self.service_checks {
                let message = check_item_md(c, options);
                table = table.multi_raw(vec![message]);
            }
            md.push_str(&table.to_md_table(options));
            md.push('\n');
        }

        // each run in detail
        for run in &self.test_runs {
            md.push_str(&run.to_md(options, check_classes));
        }
        md
    }
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct DnsData {
    pub v4_cname: Option<String>,
    pub v6_cname: Option<String>,
    pub v4_addrs: Vec<Ipv4Addr>,
    pub v6_addrs: Vec<Ipv6Addr>,
}

#[derive(Debug, Serialize, Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum RunOutcome {
    Tested,
    NetworkError,
    HttpProtocolError,
    HttpConnectError,
    HttpRedirectResponse,
    HttpTimeoutError,
    HttpNon200Error,
    HttpTooManyRequestsError,
    HttpNotFoundError,
    HttpBadRequestError,
    HttpUnauthorizedError,
    HttpForbiddenError,
    JsonError,
    RdapDataError,
    InternalError,
    Skipped,
}

#[derive(Debug, Serialize, Display)]
#[strum(serialize_all = "snake_case")]
pub enum RunFeature {
    OriginHeader,
}

impl RunOutcome {
    pub fn to_md(&self, options: &MdOptions) -> String {
        match self {
            Self::Tested => self.to_bold(options),
            Self::Skipped => self.to_string(),
            _ => self.to_em(options),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TestRun {
    pub features: Vec<RunFeature>,
    pub socket_addr: SocketAddr,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub response_data: Option<ResponseData>,
    pub outcome: RunOutcome,
    pub checks: Option<Checks>,
}

impl TestRun {
    pub fn new_v4(features: Vec<RunFeature>, ipv4: Ipv4Addr, port: u16) -> Self {
        Self {
            features,
            start_time: Utc::now(),
            socket_addr: SocketAddr::new(IpAddr::V4(ipv4), port),
            end_time: None,
            response_data: None,
            outcome: RunOutcome::Skipped,
            checks: None,
        }
    }

    pub fn new_v6(features: Vec<RunFeature>, ipv6: Ipv6Addr, port: u16) -> Self {
        Self {
            features,
            start_time: Utc::now(),
            socket_addr: SocketAddr::new(IpAddr::V6(ipv6), port),
            end_time: None,
            response_data: None,
            outcome: RunOutcome::Skipped,
            checks: None,
        }
    }

    pub fn end(
        mut self,
        rdap_response: Result<ResponseData, RdapClientError>,
        options: &TestOptions,
    ) -> Self {
        if let Ok(response_data) = rdap_response {
            self.end_time = Some(Utc::now());
            self.outcome = RunOutcome::Tested;
            self.checks = Some(do_checks(&response_data, options));
            self.response_data = Some(response_data);
        } else {
            self.outcome = match rdap_response.err().unwrap() {
                RdapClientError::InvalidQueryValue
                | RdapClientError::AmbiquousQueryType
                | RdapClientError::Poison
                | RdapClientError::DomainNameError(_)
                | RdapClientError::BootstrapUnavailable
                | RdapClientError::BootstrapError(_)
                | RdapClientError::IanaResponse(_) => RunOutcome::InternalError,
                RdapClientError::Response(_) => RunOutcome::RdapDataError,
                RdapClientError::Json(_) => RunOutcome::JsonError,
                RdapClientError::ParsingError(e) => {
                    let status_code = e.http_data.status_code();
                    if status_code > 299 && status_code < 400 {
                        RunOutcome::HttpRedirectResponse
                    } else {
                        RunOutcome::JsonError
                    }
                }
                RdapClientError::IoError(_) => RunOutcome::NetworkError,
                RdapClientError::Client(e) => {
                    if e.is_redirect() {
                        RunOutcome::HttpRedirectResponse
                    } else if e.is_connect() {
                        RunOutcome::HttpConnectError
                    } else if e.is_timeout() {
                        RunOutcome::HttpTimeoutError
                    } else if e.is_status() {
                        match e.status().unwrap() {
                            StatusCode::TOO_MANY_REQUESTS => RunOutcome::HttpTooManyRequestsError,
                            StatusCode::NOT_FOUND => RunOutcome::HttpNotFoundError,
                            StatusCode::BAD_REQUEST => RunOutcome::HttpBadRequestError,
                            StatusCode::UNAUTHORIZED => RunOutcome::HttpUnauthorizedError,
                            StatusCode::FORBIDDEN => RunOutcome::HttpForbiddenError,
                            _ => RunOutcome::HttpNon200Error,
                        }
                    } else {
                        RunOutcome::HttpProtocolError
                    }
                }
            };
            self.end_time = Some(Utc::now());
        };
        self
    }

    fn add_summary(&self, mut table: MultiPartTable, options: &MdOptions) -> MultiPartTable {
        let duration_s = if let Some(end_time) = self.end_time {
            format!("{} ms", (end_time - self.start_time).num_milliseconds())
        } else {
            "n/a".to_string()
        };
        table = table.multi_raw(vec![
            self.socket_addr.to_string(),
            self.attribute_set(),
            duration_s,
            self.outcome.to_md(options),
        ]);
        table
    }

    fn to_md(&self, options: &MdOptions, check_classes: &[CheckClass]) -> String {
        let mut md = String::new();

        // h1
        let header_value = format!("{} - {}", self.socket_addr, self.attribute_set());
        md.push_str(&format!("\n{}\n", header_value.to_header(1, options)));

        // if outcome is tested
        if matches!(self.outcome, RunOutcome::Tested) {
            // get check items according to class
            let mut check_v: Vec<(String, String)> = vec![];
            if let Some(ref checks) = self.checks {
                traverse_checks(checks, check_classes, None, &mut |struct_name, item| {
                    let message = check_item_md(item, options);
                    check_v.push((struct_name.to_string(), message))
                });
            };

            // table
            let mut table = MultiPartTable::new();

            if check_v.is_empty() {
                table = table.header_ref(&"No issues or errors.");
            } else {
                table = table.multi_raw(vec![
                    "RDAP Structure".to_inline(options),
                    "Message".to_inline(options),
                ]);
                for c in check_v {
                    table = table.nv_raw(&c.0, c.1);
                }
            }
            md.push_str(&table.to_md_table(options));
        } else {
            let mut table = MultiPartTable::new();
            table = table.multi_raw(vec![self.outcome.to_md(options)]);
            md.push_str(&table.to_md_table(options));
        }

        md
    }

    fn attribute_set(&self) -> String {
        let socket_type = if self.socket_addr.is_ipv4() {
            "v4"
        } else {
            "v6"
        };
        if !self.features.is_empty() {
            format!(
                "{socket_type}, {}",
                self.features
                    .iter()
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            socket_type.to_string()
        }
    }
}

fn check_item_md(item: &CheckItem, options: &MdOptions) -> String {
    if !matches!(item.check_class, CheckClass::Informational)
        && !matches!(item.check_class, CheckClass::SpecificationNote)
    {
        item.to_string().to_em(options)
    } else {
        item.to_string()
    }
}

fn format_date_time(date: DateTime<Utc>) -> String {
    date.format("%a, %v %X %Z").to_string()
}

fn do_checks(response: &ResponseData, options: &TestOptions) -> Checks {
    let check_params = CheckParams {
        do_subchecks: true,
        root: &response.rdap,
        parent_type: response.rdap.get_type(),
        allow_unreg_ext: options.allow_unregistered_extensions,
    };
    let mut checks = response.rdap.get_checks(check_params);

    // httpdata checks
    checks
        .items
        .append(&mut response.http_data.get_checks(check_params).items);

    // add expected extension checks
    for ext in &options.expect_extensions {
        if !rdap_has_expected_extension(&response.rdap, ext) {
            checks
                .items
                .push(Check::ExpectedExtensionNotFound.check_item());
        }
    }

    //return
    checks
}

fn rdap_has_expected_extension(rdap: &RdapResponse, ext: &str) -> bool {
    let count = ext.split('|').filter(|s| rdap.has_extension(s)).count();
    count > 0
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_common::{
        prelude::ToResponse,
        response::{Domain, Extension},
    };

    use super::rdap_has_expected_extension;

    #[test]
    fn GIVEN_expected_extension_WHEN_rdap_has_THEN_true() {
        // GIVEN
        let domain = Domain::builder()
            .extension(Extension::from("foo0"))
            .ldh_name("foo.example.com")
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = rdap_has_expected_extension(&rdap, "foo0");

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_expected_extension_WHEN_rdap_does_not_have_THEN_false() {
        // GIVEN
        let domain = Domain::builder()
            .extension(Extension::from("foo0"))
            .ldh_name("foo.example.com")
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = rdap_has_expected_extension(&rdap, "foo1");

        // THEN
        assert!(!actual);
    }

    #[test]
    fn GIVEN_compound_expected_extension_WHEN_rdap_has_THEN_true() {
        // GIVEN
        let domain = Domain::builder()
            .extension(Extension::from("foo0"))
            .ldh_name("foo.example.com")
            .build();
        let rdap = domain.to_response();

        // WHEN
        let actual = rdap_has_expected_extension(&rdap, "foo0|foo1");

        // THEN
        assert!(actual);
    }
}
