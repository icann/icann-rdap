use reqwest::{header::EXPIRES, Client};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IanaRegistryType {
    RdapBootstrapDns,
    RdapBootstrapAsn,
    RdapBootstrapIpv4,
    RdapBootstrapIpv6,
    RdapObjectTags,
}

impl IanaRegistryType {
    pub fn url(&self) -> &str {
        match self {
            IanaRegistryType::RdapBootstrapDns => "https://data.iana.org/rdap/dns.json",
            IanaRegistryType::RdapBootstrapAsn => "https://data.iana.org/rdap/asn.json",
            IanaRegistryType::RdapBootstrapIpv4 => "https://data.iana.org/rdap/ipv4.json",
            IanaRegistryType::RdapBootstrapIpv6 => "https://data.iana.org/rdap/ipv6.json",
            IanaRegistryType::RdapObjectTags => "https://data.iana.org/rdap/object-tags.json",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IanaRegistry {
    RdapBootstrapRegistry(RdapBootstrapRegistry),
    // might add IANA registrar IDs later
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RdapBootstrapRegistry {
    pub version: String,
    pub publication: String,
    pub description: Option<String>,
    pub services: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IanaResponse {
    pub registry: IanaRegistry,
    pub registry_type: IanaRegistryType,
    pub expires: Option<String>,
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
    let expires = response
        .headers()
        .get(EXPIRES)
        .map(|value| value.to_str().unwrap().to_string());
    let text = response.text().await?;
    let json: RdapBootstrapRegistry = serde_json::from_str(&text)?;
    Ok(IanaResponse {
        registry: IanaRegistry::RdapBootstrapRegistry(json),
        registry_type,
        expires,
    })
}
