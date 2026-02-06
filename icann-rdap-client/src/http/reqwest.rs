//! Creates a Reqwest client.

#![allow(mismatched_lifetime_syntaxes)] // TODO see if this can be removed with a buildstructor upgrade

use std::collections::HashSet;

pub use reqwest::{
    header::{self, HeaderValue},
    Client as ReqwestClient, Error as ReqwestError,
};

use icann_rdap_common::{
    media_types::{JSON_MEDIA_TYPE, RDAP_MEDIA_TYPE},
    prelude::ExtensionId,
};

#[cfg(not(target_arch = "wasm32"))]
use {icann_rdap_common::VERSION, std::net::SocketAddr, std::time::Duration};

/// Configures the HTTP client.
#[derive(Clone)]
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

    /// Extension IDs.
    ///
    /// The set of extension identifiers to be used in the exts_list in the media type.
    pub exts_list: HashSet<ExtensionId>,
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
            exts_list: HashSet::default(),
        }
    }
}

#[buildstructor::buildstructor]
impl ReqwestClientConfig {
    #[builder]
    pub fn new(
        user_agent_suffix: Option<String>,
        https_only: Option<bool>,
        accept_invalid_host_names: Option<bool>,
        accept_invalid_certificates: Option<bool>,
        follow_redirects: Option<bool>,
        host: Option<HeaderValue>,
        origin: Option<HeaderValue>,
        timeout_secs: Option<u64>,
        exts_list: Option<HashSet<ExtensionId>>,
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
            exts_list: exts_list.unwrap_or_default(),
        }
    }

    #[builder(entry = "from_config", exit = "build")]
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
        exts_list: Option<HashSet<ExtensionId>>,
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
            exts_list: exts_list.unwrap_or(self.exts_list.clone()),
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
    let accept_media_types = if config.exts_list.is_empty() {
        format!("{RDAP_MEDIA_TYPE}, {JSON_MEDIA_TYPE}")
    } else {
        let mut exts_list: Vec<String> = config.exts_list.iter().map(|e| e.to_string()).collect();
        exts_list.sort();
        let exts_list_param = exts_list.join(" ");
        format!("{RDAP_MEDIA_TYPE};exts_list=\"{exts_list_param}\", {JSON_MEDIA_TYPE}")
    };
    // We are unwrapping this value because this should never happen as the construction of
    // the header value is under our control. Unwrapping will cause a fail fast whereas propagating
    // the result up the stack may get it swallowed.
    let accept_value = HeaderValue::from_str(&accept_media_types).unwrap();
    default_headers.insert(header::ACCEPT, accept_value);
    if let Some(host) = &config.host {
        default_headers.insert(header::HOST, host.into());
    };
    if let Some(origin) = &config.origin {
        default_headers.insert(header::ORIGIN, origin.into());
    }
    default_headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use icann_rdap_common::prelude::ExtensionId;
    use std::collections::HashSet;

    #[test]
    fn test_default_headers_empty_exts_list() {
        // GIVEN a config with an empty extensions list
        let config = ReqwestClientConfig {
            exts_list: HashSet::new(),
            ..Default::default()
        };

        // WHEN the default headers are generated
        let headers = default_headers(&config);
        let accept_header = headers.get(header::ACCEPT).unwrap();

        // THEN the accept header should only include RDAP and JSON media types without exts_list parameter
        let expected = format!("{RDAP_MEDIA_TYPE}, {JSON_MEDIA_TYPE}");
        assert_eq!(accept_header.to_str().unwrap(), expected);
    }

    #[test]
    fn test_default_headers_with_exts_list() {
        // GIVEN a config with multiple extensions in the list
        let mut exts_list = HashSet::new();
        exts_list.insert(ExtensionId::Cidr0);
        exts_list.insert(ExtensionId::JsContact);
        let config = ReqwestClientConfig {
            exts_list,
            ..Default::default()
        };

        // WHEN the default headers are generated
        let headers = default_headers(&config);
        let accept_header = headers.get(header::ACCEPT).unwrap();

        // THEN the accept header should include exts_list parameter with sorted space-separated extension IDs
        let expected =
            format!("{RDAP_MEDIA_TYPE};exts_list=\"cidr0 jscontact\", {JSON_MEDIA_TYPE}");
        assert_eq!(accept_header.to_str().unwrap(), expected);
    }

    #[test]
    fn test_default_headers_single_extension() {
        // GIVEN a config with a single extension in the list
        let mut exts_list = HashSet::new();
        exts_list.insert(ExtensionId::Redacted);
        let config = ReqwestClientConfig {
            exts_list,
            ..Default::default()
        };

        // WHEN the default headers are generated
        let headers = default_headers(&config);
        let accept_header = headers.get(header::ACCEPT).unwrap();

        // THEN the accept header should include exts_list parameter with the single extension name
        let expected = format!("{RDAP_MEDIA_TYPE};exts_list=\"redacted\", {JSON_MEDIA_TYPE}");
        assert_eq!(accept_header.to_str().unwrap(), expected);
    }

    #[test]
    fn test_default_headers_with_host_and_origin() {
        // GIVEN a config with extensions, host, and origin headers
        let mut exts_list = HashSet::new();
        exts_list.insert(ExtensionId::Sorting);
        let config = ReqwestClientConfig {
            host: Some(HeaderValue::from_static("example.com")),
            origin: Some(HeaderValue::from_static("https://example.com")),
            exts_list,
            ..Default::default()
        };

        // WHEN the default headers are generated
        let headers = default_headers(&config);

        // THEN all headers should be properly set
        // Check Accept header with exts_list parameter
        let accept_header = headers.get(header::ACCEPT).unwrap();
        let expected = format!("{RDAP_MEDIA_TYPE};exts_list=\"sorting\", {JSON_MEDIA_TYPE}");
        assert_eq!(accept_header.to_str().unwrap(), expected);

        // Check Host header
        let host_header = headers.get(header::HOST).unwrap();
        assert_eq!(host_header, "example.com");

        // Check Origin header
        let origin_header = headers.get(header::ORIGIN).unwrap();
        assert_eq!(origin_header, "https://example.com");
    }
}
