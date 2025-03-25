//! Creates a Reqwest client.

pub use reqwest::header::{self, HeaderValue};
pub use reqwest::Client as ReqwestClient;
pub use reqwest::Error as ReqwestError;

use icann_rdap_common::media_types::{JSON_MEDIA_TYPE, RDAP_MEDIA_TYPE};

#[cfg(not(target_arch = "wasm32"))]
use {icann_rdap_common::VERSION, std::net::SocketAddr, std::time::Duration};

const ACCEPT_HEADER_VALUES: &str = const_format::formatcp!("{RDAP_MEDIA_TYPE}, {JSON_MEDIA_TYPE}");

/// Configures the HTTP client.
pub struct ReqwestClientConfig {
    /// This string is appended to the user agent.
    ///
    /// It is provided so
    /// library users may identify their programs.
    /// This is ignored on wasm32.
    pub user_agent_suffix: String,

    /// If set to true, connections will be required to use HTTPS.
    ///
    /// This is ignored on wasm32.
    pub https_only: bool,

    /// If set to true, invalid host names will be accepted.
    ///
    /// This is ignored on wasm32.
    pub accept_invalid_host_names: bool,

    /// If set to true, invalid certificates will be accepted.
    ///
    /// This is ignored on wasm32.
    pub accept_invalid_certificates: bool,

    /// If true, HTTP redirects will be followed.
    ///
    /// This is ignored on wasm32.
    pub follow_redirects: bool,

    /// Specify Host
    pub host: Option<HeaderValue>,

    /// Specify the value of the origin header.
    ///
    /// Most browsers ignore this by default.
    pub origin: Option<HeaderValue>,

    /// Query timeout in seconds.
    ///
    /// This corresponds to the total timeout of the request (connection plus reading all the data).
    ///
    /// This is ignored on wasm32.
    pub timeout_secs: u64,
}

impl Default for ReqwestClientConfig {
    fn default() -> Self {
        Self {
            user_agent_suffix: "library".to_string(),
            https_only: true,
            accept_invalid_host_names: false,
            accept_invalid_certificates: false,
            follow_redirects: true,
            host: None,
            origin: None,
            timeout_secs: 60,
        }
    }
}

#[buildstructor::buildstructor]
impl ReqwestClientConfig {
    #[builder]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_agent_suffix: Option<String>,
        https_only: Option<bool>,
        accept_invalid_host_names: Option<bool>,
        accept_invalid_certificates: Option<bool>,
        follow_redirects: Option<bool>,
        host: Option<HeaderValue>,
        origin: Option<HeaderValue>,
        timeout_secs: Option<u64>,
    ) -> Self {
        let default = Self::default();
        Self {
            user_agent_suffix: user_agent_suffix.unwrap_or(default.user_agent_suffix),
            https_only: https_only.unwrap_or(default.https_only),
            accept_invalid_host_names: accept_invalid_host_names
                .unwrap_or(default.accept_invalid_host_names),
            accept_invalid_certificates: accept_invalid_certificates
                .unwrap_or(default.accept_invalid_certificates),
            follow_redirects: follow_redirects.unwrap_or(default.follow_redirects),
            host,
            origin,
            timeout_secs: timeout_secs.unwrap_or(default.timeout_secs),
        }
    }

    #[builder(entry = "from_config", exit = "build")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_config(
        &self,
        user_agent_suffix: Option<String>,
        https_only: Option<bool>,
        accept_invalid_host_names: Option<bool>,
        accept_invalid_certificates: Option<bool>,
        follow_redirects: Option<bool>,
        host: Option<HeaderValue>,
        origin: Option<HeaderValue>,
        timeout_secs: Option<u64>,
    ) -> Self {
        Self {
            user_agent_suffix: user_agent_suffix.unwrap_or(self.user_agent_suffix.clone()),
            https_only: https_only.unwrap_or(self.https_only),
            accept_invalid_host_names: accept_invalid_host_names
                .unwrap_or(self.accept_invalid_host_names),
            accept_invalid_certificates: accept_invalid_certificates
                .unwrap_or(self.accept_invalid_certificates),
            follow_redirects: follow_redirects.unwrap_or(self.follow_redirects),
            host: host.map_or(self.host.clone(), Some),
            origin: origin.map_or(self.origin.clone(), Some),
            timeout_secs: timeout_secs.unwrap_or(self.timeout_secs),
        }
    }
}

/// Creates an HTTP client using Reqwest. The Reqwest
/// client holds its own connection pools, so in many
/// uses cases creating only one client per process is
/// necessary.
#[cfg(not(target_arch = "wasm32"))]
pub fn create_reqwest_client(config: &ReqwestClientConfig) -> Result<ReqwestClient, ReqwestError> {
    let default_headers = default_headers(config);

    let mut client = reqwest::Client::builder();

    let redirects = if config.follow_redirects {
        reqwest::redirect::Policy::default()
    } else {
        reqwest::redirect::Policy::none()
    };
    client = client
        .timeout(Duration::from_secs(config.timeout_secs))
        .user_agent(format!(
            "icann_rdap client {VERSION} {}",
            config.user_agent_suffix
        ))
        .redirect(redirects)
        .https_only(config.https_only)
        .danger_accept_invalid_hostnames(config.accept_invalid_host_names)
        .danger_accept_invalid_certs(config.accept_invalid_certificates);

    let client = client.default_headers(default_headers).build()?;
    Ok(client)
}

/// Creates an HTTP client using Reqwest. The Reqwest
/// client holds its own connection pools, so in many
/// uses cases creating only one client per process is
/// necessary.
#[cfg(not(target_arch = "wasm32"))]
pub fn create_reqwest_client_with_addr(
    config: &ReqwestClientConfig,
    domain: &str,
    addr: SocketAddr,
) -> Result<ReqwestClient, ReqwestError> {
    let default_headers = default_headers(config);

    let mut client = reqwest::Client::builder();

    let redirects = if config.follow_redirects {
        reqwest::redirect::Policy::default()
    } else {
        reqwest::redirect::Policy::none()
    };
    client = client
        .timeout(Duration::from_secs(config.timeout_secs))
        .user_agent(format!(
            "icann_rdap client {VERSION} {}",
            config.user_agent_suffix
        ))
        .redirect(redirects)
        .https_only(config.https_only)
        .danger_accept_invalid_hostnames(config.accept_invalid_host_names)
        .danger_accept_invalid_certs(config.accept_invalid_certificates)
        .resolve(domain, addr);

    let client = client.default_headers(default_headers).build()?;
    Ok(client)
}

/// Creates an HTTP client using Reqwest. The Reqwest
/// client holds its own connection pools, so in many
/// uses cases creating only one client per process is
/// necessary.
/// Note that the WASM version does not set redirect policy,
/// https_only, or TLS settings.
#[cfg(target_arch = "wasm32")]
pub fn create_reqwest_client(config: &ReqwestClientConfig) -> Result<ReqwestClient, ReqwestError> {
    let default_headers = default_headers(config);

    let client = reqwest::Client::builder();

    let client = client.default_headers(default_headers).build()?;
    Ok(client)
}

fn default_headers(config: &ReqwestClientConfig) -> header::HeaderMap {
    let mut default_headers = header::HeaderMap::new();
    default_headers.insert(
        header::ACCEPT,
        HeaderValue::from_static(ACCEPT_HEADER_VALUES),
    );
    if let Some(host) = &config.host {
        default_headers.insert(header::HOST, host.into());
    };
    if let Some(origin) = &config.origin {
        default_headers.insert(header::ORIGIN, origin.into());
    }
    default_headers
}
