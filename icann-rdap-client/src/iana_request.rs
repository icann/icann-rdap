//! The IANA RDAP Bootstrap Registries.

use icann_rdap_common::httpdata::HttpData;
use icann_rdap_common::iana::IanaRegistry;
use icann_rdap_common::iana::IanaRegistryType;
use icann_rdap_common::iana::RdapBootstrapRegistry;
use reqwest::header::ACCESS_CONTROL_ALLOW_ORIGIN;
use reqwest::header::RETRY_AFTER;
use reqwest::header::STRICT_TRANSPORT_SECURITY;
use reqwest::{
    header::{CACHE_CONTROL, CONTENT_TYPE, EXPIRES, LOCATION},
    Client,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IanaResponse {
    pub registry: IanaRegistry,
    pub registry_type: IanaRegistryType,
    pub http_data: HttpData,
}

#[derive(Debug, Error)]
pub enum IanaResponseError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

pub async fn iana_request(
    registry_type: IanaRegistryType,
    client: &Client,
) -> Result<IanaResponse, IanaResponseError> {
    let url = registry_type.url();
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
    let status_code = response.status().as_u16();
    let content_length = response.content_length();
    let url = response.url().to_owned();
    let text = response.text().await?;
    let json: RdapBootstrapRegistry = serde_json::from_str(&text)?;
    let http_data = HttpData::now()
        .scheme(url.scheme())
        .host(
            url.host_str()
                .expect("URL has no host. This shouldn't happen.")
                .to_owned(),
        )
        .status_code(status_code)
        .and_location(location)
        .and_content_length(content_length)
        .and_content_type(content_type)
        .and_expires(expires)
        .and_cache_control(cache_control)
        .and_access_control_allow_origin(access_control_allow_origin)
        .and_strict_transport_security(strict_transport_security)
        .and_retry_after(retry_after)
        .build();
    Ok(IanaResponse {
        registry: IanaRegistry::RdapBootstrapRegistry(json),
        registry_type,
        http_data,
    })
}
