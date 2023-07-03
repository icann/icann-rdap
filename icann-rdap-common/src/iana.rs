use reqwest::{
    header::{CACHE_CONTROL, CONTENT_TYPE, EXPIRES},
    Client,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cache::HttpData;

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

    pub fn file_name(&self) -> &str {
        let url = self.url();
        url.rsplit('/')
            .next()
            .expect("unexpected errror: cannot get filename from url")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum IanaRegistry {
    RdapBootstrapRegistry(RdapBootstrapRegistry),
    // might add IANA registrar IDs later
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RdapBootstrapRegistry {
    pub version: String,
    pub publication: String,
    pub description: Option<String>,
    pub services: Vec<Vec<Vec<String>>>,
}

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
    let content_length = response.content_length();
    let url = response.url().to_owned();
    let text = response.text().await?;
    let json: RdapBootstrapRegistry = serde_json::from_str(&text)?;
    let http_data = HttpData::now()
        .host(
            url.host_str()
                .expect("URL has no host. This shouldn't happen.")
                .to_owned(),
        )
        .and_content_length(content_length)
        .and_content_type(content_type)
        .and_expires(expires)
        .and_cache_control(cache_control)
        .build();
    Ok(IanaResponse {
        registry: IanaRegistry::RdapBootstrapRegistry(json),
        registry_type,
        http_data,
    })
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use rstest::rstest;

    use super::{IanaRegistry, IanaRegistryType};

    #[rstest]
    #[case(IanaRegistryType::RdapBootstrapDns, "dns.json")]
    #[case(IanaRegistryType::RdapBootstrapAsn, "asn.json")]
    #[case(IanaRegistryType::RdapBootstrapIpv4, "ipv4.json")]
    #[case(IanaRegistryType::RdapBootstrapIpv6, "ipv6.json")]
    #[case(IanaRegistryType::RdapObjectTags, "object-tags.json")]
    fn GIVEN_registry_WHEN_get_file_name_THEN_correct_result(
        #[case] registry: IanaRegistryType,
        #[case] expected: &str,
    ) {
        // GIVEN in parameters

        // WHEN
        let actual = registry.file_name();

        // THEN
        assert_eq!(actual, expected);
    }

    #[test]
    fn GIVEN_domain_bootstrap_WHEN_deserialize_THEN_success() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Some text",
                "services": [
                  [
                    ["net", "com"],
                    [
                      "https://registry.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["org", "mytld"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["xn--zckzah"],
                    [
                      "https://example.net/rdap/xn--zckzah/",
                      "http://example.net/rdap/xn--zckzah/"
                    ]
                  ]
                ]
            }
        "#;

        // WHEN
        let actual = serde_json::from_str::<IanaRegistry>(bootstrap);

        // THEN
        actual.unwrap();
    }
}
