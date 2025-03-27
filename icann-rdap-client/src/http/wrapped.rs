//! Wrapped Client.

pub use reqwest::{header::HeaderValue, Client as ReqwestClient, Error as ReqwestError};
use {
    icann_rdap_common::httpdata::HttpData,
    reqwest::header::{
        ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE, EXPIRES, LOCATION, RETRY_AFTER,
        STRICT_TRANSPORT_SECURITY,
    },
};

use {
    super::{create_reqwest_client, ReqwestClientConfig},
    crate::RdapClientError,
};

#[cfg(not(target_arch = "wasm32"))]
use {
    super::create_reqwest_client_with_addr, chrono::DateTime, chrono::Utc, reqwest::StatusCode,
    std::net::SocketAddr, tracing::debug, tracing::info,
};

/// Used by the request functions.
#[derive(Clone, Copy)]
pub struct RequestOptions {
    pub(crate) max_retry_secs: u32,
    pub(crate) def_retry_secs: u32,
    pub(crate) max_retries: u16,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            max_retry_secs: 120,
            def_retry_secs: 60,
            max_retries: 1,
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
        timeout_secs: Option<u64>,
        max_retry_secs: Option<u32>,
        def_retry_secs: Option<u32>,
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
                timeout_secs: timeout_secs.unwrap_or(default_cc.timeout_secs),
            },
            request_options: RequestOptions {
                max_retry_secs: max_retry_secs.unwrap_or(default_ro.max_retry_secs),
                def_retry_secs: def_retry_secs.unwrap_or(default_ro.def_retry_secs),
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
        timeout_secs: Option<u64>,
        max_retry_secs: Option<u32>,
        def_retry_secs: Option<u32>,
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
                timeout_secs: timeout_secs.unwrap_or(self.client_config.timeout_secs),
            },
            request_options: RequestOptions {
                max_retry_secs: max_retry_secs.unwrap_or(self.request_options.max_retry_secs),
                def_retry_secs: def_retry_secs.unwrap_or(self.request_options.def_retry_secs),
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

pub(crate) struct WrappedResponse {
    pub(crate) http_data: HttpData,
    pub(crate) text: String,
}

pub(crate) async fn wrapped_request(
    request_uri: &str,
    client: &Client,
) -> Result<WrappedResponse, ReqwestError> {
    // send request and loop for possible retries
    #[allow(unused_mut)] //because of wasm32 exclusion below
    let mut response = client.reqwest_client.get(request_uri).send().await?;

    // this doesn't work on wasm32 because tokio doesn't work on wasm
    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut tries: u16 = 0;
        loop {
            debug!("HTTP version: {:?}", response.version());
            // don't repeat the request
            if !matches!(response.status(), StatusCode::TOO_MANY_REQUESTS) {
                break;
            }
            // loop if HTTP 429
            let retry_after_header = response
                .headers()
                .get(RETRY_AFTER)
                .map(|value| value.to_str().unwrap().to_string());
            let retry_after = if let Some(rt) = retry_after_header {
                info!("Server says too many requests and to retry-after '{rt}'.");
                rt
            } else {
                info!("Server says too many requests but does not offer 'retry-after' value.");
                client.request_options.def_retry_secs.to_string()
            };
            let mut wait_time_seconds = if let Ok(date) = DateTime::parse_from_rfc2822(&retry_after)
            {
                (date.with_timezone(&Utc) - Utc::now()).num_seconds() as u64
            } else if let Ok(seconds) = retry_after.parse::<u64>() {
                seconds
            } else {
                info!(
                    "Unable to parse retry-after header value. Using {}",
                    client.request_options.def_retry_secs
                );
                client.request_options.def_retry_secs.into()
            };
            if wait_time_seconds == 0 {
                info!("Given {wait_time_seconds} for retry-after. Does not make sense.");
                wait_time_seconds = client.request_options.def_retry_secs as u64;
            }
            if wait_time_seconds > client.request_options.max_retry_secs as u64 {
                info!(
                    "Server is asking to wait longer than configured max of {}.",
                    client.request_options.max_retry_secs
                );
                wait_time_seconds = client.request_options.max_retry_secs as u64;
            }
            info!("Waiting {wait_time_seconds} seconds to retry.");
            tokio::time::sleep(tokio::time::Duration::from_secs(wait_time_seconds + 1)).await;
            tries += 1;
            if tries > client.request_options.max_retries {
                info!("Max query retries reached.");
                break;
            } else {
                // send the query again
                response = client.reqwest_client.get(request_uri).send().await?;
            }
        }
    }

    // throw an error if not 200 OK
    let response = response.error_for_status()?;

    // get the response
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|value| value.to_str().unwrap().to_string());
    let expires = response
        .headers()
        .get(EXPIRES)
        .map(|value| value.to_str().unwrap().to_string());
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .map(|value| value.to_str().unwrap().to_string());
    let location = response
        .headers()
        .get(LOCATION)
        .map(|value| value.to_str().unwrap().to_string());
    let access_control_allow_origin = response
        .headers()
        .get(ACCESS_CONTROL_ALLOW_ORIGIN)
        .map(|value| value.to_str().unwrap().to_string());
    let strict_transport_security = response
        .headers()
        .get(STRICT_TRANSPORT_SECURITY)
        .map(|value| value.to_str().unwrap().to_string());
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .map(|value| value.to_str().unwrap().to_string());
    let content_length = response.content_length();
    let status_code = response.status().as_u16();
    let url = response.url().to_owned();
    let text = response.text().await?;

    let http_data = HttpData::now()
        .status_code(status_code)
        .and_location(location)
        .and_content_length(content_length)
        .and_content_type(content_type)
        .scheme(url.scheme())
        .host(
            url.host_str()
                .expect("URL has no host. This shouldn't happen.")
                .to_owned(),
        )
        .and_expires(expires)
        .and_cache_control(cache_control)
        .and_access_control_allow_origin(access_control_allow_origin)
        .and_strict_transport_security(strict_transport_security)
        .and_retry_after(retry_after)
        .request_uri(request_uri)
        .build();

    Ok(WrappedResponse { http_data, text })
}
