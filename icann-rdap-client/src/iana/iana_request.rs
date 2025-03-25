//! The IANA RDAP Bootstrap Registries.

use icann_rdap_common::{
    httpdata::HttpData,
    iana::{IanaRegistry, IanaRegistryType, RdapBootstrapRegistry},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::http::{wrapped_request, Client};

/// Response from getting an IANA registry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IanaResponse {
    pub registry: IanaRegistry,
    pub registry_type: IanaRegistryType,
    pub http_data: HttpData,
}

/// Errors from issuing a request to get an IANA registry.
#[derive(Debug, Error)]
pub enum IanaResponseError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
}

/// Issues the HTTP request to get an IANA registry.
pub async fn iana_request(
    registry_type: IanaRegistryType,
    client: &Client,
) -> Result<IanaResponse, IanaResponseError> {
    let url = registry_type.url();

    let wrapped_response = wrapped_request(url, client).await?;
    let text = wrapped_response.text;
    let http_data = wrapped_response.http_data;

    let json: RdapBootstrapRegistry = serde_json::from_str(&text)?;
    Ok(IanaResponse {
        registry: IanaRegistry::RdapBootstrapRegistry(json),
        registry_type,
        http_data,
    })
}
