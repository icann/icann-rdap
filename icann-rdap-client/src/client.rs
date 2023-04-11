use buildstructor::Builder;
use reqwest::{
    header::{self, HeaderValue},
    Client,
};

use crate::RdapClientError;

#[cfg(not(target_arch = "wasm32"))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

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
pub fn create_client(config: &ClientConfig) -> Result<Client, RdapClientError> {
    let mut default_headers = header::HeaderMap::new();
    default_headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/rdap+json, application/json"),
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
