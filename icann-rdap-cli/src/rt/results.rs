use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Contains the results of test execution.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct TestResults {
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub test_runs: Vec<TestRun>,
}

impl Default for TestResults {
    fn default() -> Self {
        Self::new()
    }
}

impl TestResults {
    pub fn new() -> Self {
        TestResults {
            start_time: Utc::now(),
            end_time: None,
            test_runs: vec![],
        }
    }

    pub fn end(&mut self) {
        self.end_time = Some(Utc::now());
    }

    pub fn add_test_run(&mut self, mut test_run: TestRun) {
        test_run.end();
        self.test_runs.push(test_run);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestRun {
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub socket_addr: SocketAddr,
}

impl TestRun {
    pub fn new_v4(ipv4: Ipv4Addr, port: u16) -> Self {
        TestRun {
            start_time: Utc::now(),
            end_time: None,
            socket_addr: SocketAddr::new(IpAddr::V4(ipv4), port),
        }
    }

    pub fn new_v6(ipv6: Ipv6Addr, port: u16) -> Self {
        TestRun {
            start_time: Utc::now(),
            end_time: None,
            socket_addr: SocketAddr::new(IpAddr::V6(ipv6), port),
        }
    }

    pub fn end(&mut self) {
        self.end_time = Some(Utc::now());
    }
}
