use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Contains the results of test execution.
use chrono::{DateTime, Utc};
use icann_rdap_client::{
    md::{string::StringUtil, table::MultiPartTable, MdOptions},
    query::request::ResponseData,
    RdapClientError,
};
use icann_rdap_common::check::{CheckParams, Checks, GetChecks};
use serde::Serialize;
use strum_macros::Display;

#[derive(Debug, Serialize)]
pub struct TestResults<'a> {
    pub query_url: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub test_runs: Vec<TestRun<'a>>,
}

impl<'a> TestResults<'a> {
    pub fn new(query_url: String) -> Self {
        TestResults {
            query_url,
            start_time: Utc::now(),
            end_time: None,
            test_runs: vec![],
        }
    }

    pub fn end(&mut self) {
        self.end_time = Some(Utc::now());
    }

    pub fn add_test_run(&mut self, test_run: TestRun<'a>) {
        self.test_runs.push(test_run);
    }

    pub fn to_md(&self, options: &MdOptions) -> String {
        let mut md = String::new();
        md.push_str(&format!(
            "\n{}\n",
            self.query_url.to_owned().to_header(1, options)
        ));

        let mut table = MultiPartTable::new();
        table = table.data(&"Summary", format!("{} Test Runs", self.test_runs.len()));
        for test_run in &self.test_runs {
            table = test_run.add_summary(table);
        }
        md.push_str(&table.to_md_table(options));
        md
    }
}

#[derive(Debug, Serialize, Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum RunOutcome {
    NoErrors,
    NetworkError,
    JsonError,
    RdapDataError,
    InternalError,
    Skipped,
}

#[derive(Debug, Serialize)]
pub struct TestRun<'a> {
    pub socket_addr: SocketAddr,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub response_data: Option<ResponseData>,
    pub outcome: RunOutcome,
    pub checks: Option<Checks<'a>>,
}

impl<'a> TestRun<'a> {
    pub fn new_v4(ipv4: Ipv4Addr, port: u16) -> Self {
        TestRun {
            start_time: Utc::now(),
            socket_addr: SocketAddr::new(IpAddr::V4(ipv4), port),
            end_time: None,
            response_data: None,
            outcome: RunOutcome::Skipped,
            checks: None,
        }
    }

    pub fn new_v6(ipv6: Ipv6Addr, port: u16) -> Self {
        TestRun {
            start_time: Utc::now(),
            socket_addr: SocketAddr::new(IpAddr::V6(ipv6), port),
            end_time: None,
            response_data: None,
            outcome: RunOutcome::Skipped,
            checks: None,
        }
    }

    pub fn end(mut self, rdap_response: Result<ResponseData, RdapClientError>) -> Self {
        if let Ok(response_data) = rdap_response {
            self.end_time = Some(Utc::now());
            self.outcome = RunOutcome::NoErrors;
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
                RdapClientError::Json(_) | RdapClientError::ParsingError(_) => {
                    RunOutcome::JsonError
                }
                RdapClientError::IoError(_) | RdapClientError::Client(_) => {
                    RunOutcome::NetworkError
                }
            };
            self.end_time = Some(Utc::now());
        };
        self
    }

    pub fn calc_checks(&'a mut self) {
        if let Some(ref response_data) = self.response_data {
            self.checks = Some(do_checks(response_data));
        }
    }

    fn add_summary(&self, mut table: MultiPartTable) -> MultiPartTable {
        table = table.header_ref(&self.socket_addr.to_string());
        table = table.data(&"Start Time", format_date_time(self.start_time));
        if let Some(ref end_time) = self.end_time {
            table = table.data(&"End Time", format_date_time(*end_time));
            table = table.data(
                &"Duration",
                format!("{} ms", (*end_time - self.start_time).num_milliseconds()),
            );
        } else {
            table = table.data(&"Status", "Skipped");
        }
        table
    }
}

fn format_date_time(date: DateTime<Utc>) -> String {
    date.format("%a, %v %X %Z").to_string()
}

fn do_checks(response: &ResponseData) -> Checks {
    let check_params = CheckParams {
        do_subchecks: true,
        root: &response.rdap,
        parent_type: response.rdap.get_type(),
    };
    let mut checks = response.rdap.get_checks(check_params);
    checks
        .items
        .append(&mut response.http_data.get_checks(check_params).items);
    checks
}
