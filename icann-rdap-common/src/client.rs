use lazy_static::lazy_static;
use reqwest::{
    header::{self, HeaderValue},
    Client,
};

use crate::media_types::{JSON_MEDIA_TYPE, RDAP_MEDIA_TYPE};
#[cfg(not(target_arch = "wasm32"))]
use crate::VERSION;

lazy_static! {
    static ref ACCEPT_HEADER_VALUES: String = format!("{RDAP_MEDIA_TYPE}, {JSON_MEDIA_TYPE}");
}

/// Configures the HTTP client.
pub struct ClientConfig {
    /// This string is appended to the user agent. It is provided so
    /// library users may identify their programs.
    pub user_agent_suffix: String,

    /// If set to true, connections will be required to use HTTPS.
    pub https_only: bool,

    /// If set to true, invalid host names will be accepted.
    pub accept_invalid_host_names: bool,

    /// If set to true, invalid certificates will be accepted.
    pub accept_invalid_certificates: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            user_agent_suffix: "library".to_string(),
            https_only: true,
            accept_invalid_host_names: false,
            accept_invalid_certificates: false,
        }
    }
}

#[buildstructor::buildstructor]
impl ClientConfig {
    #[builder]
    pub fn new(
        user_agent_suffix: Option<String>,
        https_only: Option<bool>,
        accept_invalid_host_names: Option<bool>,
        accept_invalid_certificates: Option<bool>,
    ) -> Self {
        let default = ClientConfig::default();
        Self {
            user_agent_suffix: user_agent_suffix.unwrap_or(default.user_agent_suffix),
            https_only: https_only.unwrap_or(default.https_only),
            accept_invalid_host_names: accept_invalid_host_names
                .unwrap_or(default.accept_invalid_host_names),
            accept_invalid_certificates: accept_invalid_certificates
                .unwrap_or(default.accept_invalid_certificates),
        }
    }
}

/// Creates an HTTP client using Reqwest. The Reqwest
/// client holds its own connection pools, so in many
/// uses cases creating only one client per process is
/// necessary.
#[allow(unused_variables)] // for config and wasm32
pub fn create_client(config: &ClientConfig) -> Result<Client, reqwest::Error> {
    let mut default_headers = header::HeaderMap::new();
    default_headers.insert(
        header::ACCEPT,
        HeaderValue::from_static(&ACCEPT_HEADER_VALUES),
    );

    #[allow(unused_mut)]
    let mut client = reqwest::Client::builder();

    #[cfg(not(target_arch = "wasm32"))]
    {
        client = client
            .user_agent(format!(
                "icann_rdap client {VERSION} {}",
                config.user_agent_suffix
            ))
            .https_only(config.https_only)
            .danger_accept_invalid_hostnames(config.accept_invalid_host_names)
            .danger_accept_invalid_certs(config.accept_invalid_certificates);
    }

    let client = client.default_headers(default_headers).build()?;
    Ok(client)
}
