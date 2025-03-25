//! Functions to make RDAP requests.

use {
    icann_rdap_common::{httpdata::HttpData, iana::IanaRegistryType, response::RdapResponse},
    serde::{Deserialize, Serialize},
    serde_json::Value,
};

use crate::{
    http::{wrapped_request, Client},
    iana::bootstrap::{qtype_to_bootstrap_url, BootstrapStore},
    RdapClientError,
};

use super::qtype::QueryType;

/// Makes an RDAP request with a full RDAP URL.
///
/// This function takes the following parameters:
/// * url - a string reference of the URL
/// * client - a reference to a [reqwest::Client].
///
/// ```no_run
/// use icann_rdap_client::prelude::*;
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
    let wrapped_response = wrapped_request(url, client).await?;
    // for convenience purposes
    let text = wrapped_response.text;
    let http_data = wrapped_response.http_data;

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
/// use icann_rdap_client::prelude::*;
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
/// would be kept it in the same scope as `client`. When using the [crate::iana::bootstrap::MemoryBootstrapStore],
/// creating a new store for each request will result it fetching the appropriate IANA
/// registry with each request which is most likely not the desired behavior.
///
/// ```no_run
/// use icann_rdap_client::prelude::*;
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

/// The data returned from an rdap request.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResponseData {
    pub rdap: RdapResponse,
    pub rdap_type: String,
    pub http_data: HttpData,
}
