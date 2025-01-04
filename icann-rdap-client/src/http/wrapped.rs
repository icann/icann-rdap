//! Wrapped Client.

pub use reqwest::header::HeaderValue;
pub use reqwest::Client as ReqwestClient;

use super::create_reqwest_client;
#[cfg(not(target_arch = "wasm32"))]
use super::create_reqwest_client_with_addr;
use super::ReqwestClientConfig;
use crate::RdapClientError;
#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;

/// Used by the request functions.
#[derive(Clone, Copy)]
pub struct RequestOptions {
    pub retry_seconds: u16,
    pub max_retries: u16,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            retry_seconds: 120,
            max_retries: 2,
        }
    }
}

/// Configures the HTTP client.
#[derive(Default)]
pub struct ClientConfig {
    /// Config for the Reqwest client.
    client_config: ReqwestClientConfig,

    /// Request options.
    request_options: RequestOptions,
}

#[buildstructor::buildstructor]
impl ClientConfig {
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
        retry_seconds: Option<u16>,
        max_retries: Option<u16>,
    ) -> Self {
        let default_cc = ReqwestClientConfig::default();
        let default_ro = RequestOptions::default();
        Self {
            client_config: ReqwestClientConfig {
                user_agent_suffix: user_agent_suffix.unwrap_or(default_cc.user_agent_suffix),
                https_only: https_only.unwrap_or(default_cc.https_only),
                accept_invalid_host_names: accept_invalid_host_names
                    .unwrap_or(default_cc.accept_invalid_host_names),
                accept_invalid_certificates: accept_invalid_certificates
                    .unwrap_or(default_cc.accept_invalid_certificates),
                follow_redirects: follow_redirects.unwrap_or(default_cc.follow_redirects),
                host,
                origin,
            },
            request_options: RequestOptions {
                retry_seconds: retry_seconds.unwrap_or(default_ro.retry_seconds),
                max_retries: max_retries.unwrap_or(default_ro.max_retries),
            },
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
        retry_seconds: Option<u16>,
        max_retries: Option<u16>,
    ) -> Self {
        Self {
            client_config: ReqwestClientConfig {
                user_agent_suffix: user_agent_suffix
                    .unwrap_or(self.client_config.user_agent_suffix.clone()),
                https_only: https_only.unwrap_or(self.client_config.https_only),
                accept_invalid_host_names: accept_invalid_host_names
                    .unwrap_or(self.client_config.accept_invalid_host_names),
                accept_invalid_certificates: accept_invalid_certificates
                    .unwrap_or(self.client_config.accept_invalid_certificates),
                follow_redirects: follow_redirects.unwrap_or(self.client_config.follow_redirects),
                host: host.map_or(self.client_config.host.clone(), Some),
                origin: origin.map_or(self.client_config.origin.clone(), Some),
            },
            request_options: RequestOptions {
                retry_seconds: retry_seconds.unwrap_or(self.request_options.retry_seconds),
                max_retries: max_retries.unwrap_or(self.request_options.max_retries),
            },
        }
    }
}

/// A wrapper around Reqwest client to give additional features when used with the request functions.
pub struct Client {
    /// The reqwest client.
    pub(crate) reqwest_client: ReqwestClient,

    /// Request options.
    pub(crate) request_options: RequestOptions,
}

impl Client {
    pub fn new(reqwest_client: ReqwestClient, request_options: RequestOptions) -> Self {
        Self {
            reqwest_client,
            request_options,
        }
    }
}

/// Creates a wrapped HTTP client. The wrapped
/// client holds its own connection pools, so in many
/// uses cases creating only one client per process is
/// necessary.
pub fn create_client(config: &ClientConfig) -> Result<Client, RdapClientError> {
    let client = create_reqwest_client(&config.client_config)?;
    Ok(Client::new(client, config.request_options))
}

/// Creates a wrapped HTTP client.
/// This will direct the underlying client to connect to a specific socket.
#[cfg(not(target_arch = "wasm32"))]
pub fn create_client_with_addr(
    config: &ClientConfig,
    domain: &str,
    addr: SocketAddr,
) -> Result<Client, RdapClientError> {
    let client = create_reqwest_client_with_addr(&config.client_config, domain, addr)?;
    Ok(Client::new(client, config.request_options))
}
