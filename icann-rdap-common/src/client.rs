use buildstructor::Builder;
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

#[derive(Builder)]
/// Configures the HTTP client.
pub struct ClientConfig {
    /// This string is appended to the user agent. It is provided so
    /// library users may identify their programs.
    pub user_agent_suffix: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            user_agent_suffix: "library".to_string(),
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
    let client = reqwest::Client::builder();

    #[cfg(not(target_arch = "wasm32"))]
    let client = client.user_agent(format!(
        "icann_rdap client {VERSION} {}",
        config.user_agent_suffix
    ));

    let client = client.default_headers(default_headers).build()?;
    Ok(client)
}
