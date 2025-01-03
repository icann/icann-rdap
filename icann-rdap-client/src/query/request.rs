//! Functions to make RDAP requests.

use icann_rdap_common::{httpdata::HttpData, iana::IanaRegistryType, response::RdapResponse};
use reqwest::{
    header::{
        ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE, EXPIRES, LOCATION, RETRY_AFTER,
        STRICT_TRANSPORT_SECURITY,
    },
    Client,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::RdapClientError;

use super::{
    bootstrap::{qtype_to_bootstrap_url, BootstrapStore},
    qtype::QueryType,
};

/// Makes an RDAP request with a full RDAP URL.
///
/// This function takes the following parameters:
/// * url - a string reference of the URL
/// * client - a reference to a [reqwest::Client].
///
/// ```no_run
/// use icann_rdap_client::client::ClientConfig;
/// use icann_rdap_client::client::create_client;
/// use icann_rdap_client::query::request::rdap_url_request;
/// use icann_rdap_client::RdapClientError;
/// use std::str::FromStr;
/// use tokio::main;
///
/// #[tokio::main]
/// async fn main() -> Result<(), RdapClientError> {
///
///     // create a client (from icann-rdap-common)
///     let config = ClientConfig::default();
///     let client = create_client(&config)?;
///
///     // issue the RDAP query
///     let response =
///         rdap_url_request(
///             "https://rdap-bootstrap.arin.net/bootstrap/ip/192.168.0.1",
///             &client,
///     ).await?;
///
///     Ok(())
/// }
/// ```
pub async fn rdap_url_request(url: &str, client: &Client) -> Result<ResponseData, RdapClientError> {
    let response = client.get(url).send().await?.error_for_status()?;
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
        .build();

    let json: Result<Value, serde_json::Error> = serde_json::from_str(&text);
    if let Ok(rdap_json) = json {
        let rdap = RdapResponse::try_from(rdap_json)?;
        Ok(ResponseData {
            http_data,
            rdap_type: rdap.to_string(),
            rdap,
        })
    } else {
        Err(RdapClientError::ParsingError(Box::new(
            crate::ParsingErrorInfo {
                text,
                http_data,
                error: json.err().unwrap(),
            },
        )))
    }
}

/// Makes an RDAP request with a base URL.
///
/// This function takes the following parameters:
/// * base_url - a string reference of the base URL
/// * query_type - a reference to the RDAP query.
/// * client - a reference to a [reqwest::Client].
///
/// ```no_run
/// use icann_rdap_client::client::ClientConfig;
/// use icann_rdap_client::client::create_client;
/// use icann_rdap_client::query::request::rdap_request;
/// use icann_rdap_client::query::qtype::QueryType;
/// use icann_rdap_client::RdapClientError;
/// use std::str::FromStr;
/// use tokio::main;
///
/// #[tokio::main]
/// async fn main() -> Result<(), RdapClientError> {
///
///     // create a query
///     let query = QueryType::from_str("192.168.0.1")?;
///     // or
///     let query = QueryType::from_str("icann.org")?;
///
///     // create a client (from icann-rdap-common)
///     let config = ClientConfig::default();
///     let client = create_client(&config)?;
///
///     // issue the RDAP query
///     let response =
///         rdap_request(
///             "https://rdap-bootstrap.arin.net/bootstrap",
///             &query,
///             &client,
///     ).await?;
///
///     Ok(())
/// }
/// ```
pub async fn rdap_request(
    base_url: &str,
    query_type: &QueryType,
    client: &Client,
) -> Result<ResponseData, RdapClientError> {
    let url = query_type.query_url(base_url)?;
    rdap_url_request(&url, client).await
}

/// Makes an RDAP request using bootstrapping.
///
/// This function takes the following parameters:
/// * query_type - a reference to the RDAP query.
/// * client - a reference to a [reqwest::Client].
/// * store - a reference to a [BootstrapStore].
/// * callback - a closure that is called when an IANA registry is fetched.
///
/// The [BootstrapStore] is responsible for holding IANA RDAP bootstrap registries.
/// It will be populated with IANA registries as needed. Ideally, the calling code
/// would be kept it in the same scope as `client`. When using the [crate::query::bootstrap::MemoryBootstrapStore],
/// creating a new store for each request will result it fetching the appropriate IANA
/// registry with each request which is most likely not the desired behavior.
///
/// ```no_run
/// use icann_rdap_client::client::ClientConfig;
/// use icann_rdap_client::client::create_client;
/// use icann_rdap_client::query::request::rdap_bootstrapped_request;
/// use icann_rdap_client::query::qtype::QueryType;
/// use icann_rdap_client::query::bootstrap::MemoryBootstrapStore;
/// use icann_rdap_client::RdapClientError;
/// use std::str::FromStr;
/// use tokio::main;
///
/// #[tokio::main]
/// async fn main() -> Result<(), RdapClientError> {
///
///     // create a query
///     let query = QueryType::from_str("192.168.0.1")?;
///     // or
///     let query = QueryType::from_str("icann.org")?;
///
///     // create a client (from icann-rdap-common)
///     let config = ClientConfig::default();
///     let client = create_client(&config)?;
///     let store = MemoryBootstrapStore::new();
///
///     // issue the RDAP query
///     let response =
///         rdap_bootstrapped_request(
///             &query,
///             &client,
///             &store,
///             |reg| eprintln!("fetching {reg:?}")
///     ).await?;
///
///     Ok(())
/// }
/// ```
pub async fn rdap_bootstrapped_request<F>(
    query_type: &QueryType,
    client: &Client,
    store: &dyn BootstrapStore,
    callback: F,
) -> Result<ResponseData, RdapClientError>
where
    F: FnOnce(&IanaRegistryType),
{
    let base_url = qtype_to_bootstrap_url(client, store, query_type, callback).await?;
    rdap_request(&base_url, query_type, client).await
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseData {
    pub rdap: RdapResponse,
    pub rdap_type: String,
    pub http_data: HttpData,
}
