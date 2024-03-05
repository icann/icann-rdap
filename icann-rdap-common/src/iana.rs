use ipnet::Ipv4Net;
use ipnet::Ipv6Net;
use prefix_trie::PrefixMap;
use reqwest::{
    header::{CACHE_CONTROL, CONTENT_TYPE, EXPIRES, LOCATION},
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

pub trait BootstrapRegistry {
    fn get_dns_bootstrap_urls(&self, ldh: &str) -> Result<Vec<String>, BootstrapRegistryError>;
    fn get_asn_bootstrap_urls(&self, asn: &str) -> Result<Vec<String>, BootstrapRegistryError>;
    fn get_ipv4_bootstrap_urls(&self, ipv4: &str) -> Result<Vec<String>, BootstrapRegistryError>;
    fn get_ipv6_bootstrap_urls(&self, ipv6: &str) -> Result<Vec<String>, BootstrapRegistryError>;
    fn get_tag_bootstrap_urls(&self, tag: &str) -> Result<Vec<String>, BootstrapRegistryError>;
}

#[derive(Debug, Error)]
pub enum BootstrapRegistryError {
    #[error("Empty Service")]
    EmptyService,
    #[error("Empty URL Set")]
    EmptyUrlSet,
    #[error("Invalid Bootstrap Input")]
    InvalidBootstrapInput,
    #[error("No Bootstrap URLs Found")]
    NoBootstrapUrls,
    #[error("Invalid Bootstrap Service")]
    InvalidBootstrapService,
}

impl BootstrapRegistry for IanaRegistry {
    fn get_dns_bootstrap_urls(&self, ldh: &str) -> Result<Vec<String>, BootstrapRegistryError> {
        let mut longest_match: Option<(usize, Vec<String>)> = None;
        let IanaRegistry::RdapBootstrapRegistry(bootstrap) = self;
        for service in &bootstrap.services {
            let tlds = service
                .first()
                .ok_or(BootstrapRegistryError::EmptyService)?;
            for tld in tlds {
                // if the ldh domain ends with the tld or the tld is the empty string which means the root
                if ldh.ends_with(tld) || tld.eq("") {
                    let urls = service.last().ok_or(BootstrapRegistryError::EmptyUrlSet)?;
                    let longest = longest_match.get_or_insert_with(|| (tld.len(), urls.to_owned()));
                    if longest.0 < tld.len() {
                        *longest = (tld.len(), urls.to_owned());
                    }
                }
            }
        }
        let longest = longest_match.ok_or(BootstrapRegistryError::NoBootstrapUrls)?;
        Ok(longest.1)
    }

    fn get_asn_bootstrap_urls(&self, asn: &str) -> Result<Vec<String>, BootstrapRegistryError> {
        let autnum = asn
            .trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') })
            .parse::<u32>()
            .map_err(|_| BootstrapRegistryError::InvalidBootstrapInput)?;
        let IanaRegistry::RdapBootstrapRegistry(bootstrap) = self;
        for service in &bootstrap.services {
            let as_ranges = service
                .first()
                .ok_or(BootstrapRegistryError::EmptyService)?;
            for range in as_ranges {
                let as_split = range.split('-').collect::<Vec<&str>>();
                let start_as = as_split
                    .first()
                    .ok_or(BootstrapRegistryError::InvalidBootstrapService)?
                    .parse::<u32>()
                    .map_err(|_| BootstrapRegistryError::InvalidBootstrapInput)?;
                let end_as = as_split
                    .last()
                    .ok_or(BootstrapRegistryError::InvalidBootstrapService)?
                    .parse::<u32>()
                    .map_err(|_| BootstrapRegistryError::InvalidBootstrapService)?;
                if start_as <= autnum && end_as >= autnum {
                    let urls = service.last().ok_or(BootstrapRegistryError::EmptyUrlSet)?;
                    return Ok(urls.to_owned());
                }
            }
        }
        Err(BootstrapRegistryError::NoBootstrapUrls)
    }

    fn get_ipv4_bootstrap_urls(&self, ipv4: &str) -> Result<Vec<String>, BootstrapRegistryError> {
        let mut pm: PrefixMap<Ipv4Net, Vec<String>> = PrefixMap::new();
        let IanaRegistry::RdapBootstrapRegistry(bootstrap) = self;
        for service in &bootstrap.services {
            let urls = service.last().ok_or(BootstrapRegistryError::EmptyService)?;
            for cidr in service
                .first()
                .ok_or(BootstrapRegistryError::InvalidBootstrapService)?
            {
                pm.insert(
                    cidr.parse()
                        .map_err(|_| BootstrapRegistryError::InvalidBootstrapService)?,
                    urls.clone(),
                );
            }
        }
        let net = pm
            .get_lpm(
                &ipv4
                    .parse::<Ipv4Net>()
                    .map_err(|_| BootstrapRegistryError::InvalidBootstrapInput)?,
            )
            .ok_or(BootstrapRegistryError::NoBootstrapUrls)?;
        Ok(net.1.to_owned())
    }

    fn get_ipv6_bootstrap_urls(&self, ipv6: &str) -> Result<Vec<String>, BootstrapRegistryError> {
        let mut pm: PrefixMap<Ipv6Net, Vec<String>> = PrefixMap::new();
        let IanaRegistry::RdapBootstrapRegistry(bootstrap) = self;
        for service in &bootstrap.services {
            let urls = service.last().ok_or(BootstrapRegistryError::EmptyService)?;
            for cidr in service
                .first()
                .ok_or(BootstrapRegistryError::InvalidBootstrapService)?
            {
                pm.insert(
                    cidr.parse()
                        .map_err(|_| BootstrapRegistryError::InvalidBootstrapService)?,
                    urls.clone(),
                );
            }
        }
        let net = pm
            .get_lpm(
                &ipv6
                    .parse::<Ipv6Net>()
                    .map_err(|_| BootstrapRegistryError::InvalidBootstrapInput)?,
            )
            .ok_or(BootstrapRegistryError::NoBootstrapUrls)?;
        Ok(net.1.to_owned())
    }

    fn get_tag_bootstrap_urls(&self, tag: &str) -> Result<Vec<String>, BootstrapRegistryError> {
        let IanaRegistry::RdapBootstrapRegistry(bootstrap) = self;
        for service in &bootstrap.services {
            let object_tag = service
                .get(1)
                .ok_or(BootstrapRegistryError::InvalidBootstrapService)?
                .first()
                .ok_or(BootstrapRegistryError::EmptyService)?;
            if object_tag.to_ascii_uppercase() == tag.to_ascii_uppercase() {
                let urls = service.last().ok_or(BootstrapRegistryError::EmptyUrlSet)?;
                return Ok(urls.to_owned());
            }
        }
        Err(BootstrapRegistryError::NoBootstrapUrls)
    }
}

/// Prefer HTTPS urls.
pub fn get_preferred_url(urls: Vec<String>) -> Result<String, BootstrapRegistryError> {
    if urls.is_empty() {
        Err(BootstrapRegistryError::EmptyUrlSet)
    } else {
        let url = urls
            .iter()
            .find(|s| s.starts_with("https://"))
            .unwrap_or_else(|| urls.first().unwrap());
        Ok(url.to_owned())
    }
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
    let location = response
        .headers()
        .get(LOCATION)
        .map(|value| value.to_str().unwrap().to_string());
    let status_code = response.status().as_u16();
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
        .status_code(status_code)
        .and_location(location)
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

    use crate::iana::{get_preferred_url, BootstrapRegistry};

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

    #[test]
    fn GIVEN_one_url_WHEN_preferred_urls_THEN_that_is_the_one() {
        // GIVEN
        let urls = vec!["http://foo.example".to_string()];

        // WHEN
        let actual = get_preferred_url(urls).expect("cannot get preferred url");

        // THEN
        assert_eq!(actual, "http://foo.example");
    }

    #[test]
    fn GIVEN_one_http_and_https_url_WHEN_preferred_urls_THEN_return_https() {
        // GIVEN
        let urls = vec![
            "http://foo.example".to_string(),
            "https://foo.example".to_string(),
        ];

        // WHEN
        let actual = get_preferred_url(urls).expect("cannot get preferred url");

        // THEN
        assert_eq!(actual, "https://foo.example");
    }

    #[test]
    fn GIVEN_domain_bootstrap_with_matching_WHEN_find_THEN_url_matches() {
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
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse domain bootstrap");

        // WHEN
        let actual = iana.get_dns_bootstrap_urls("foo.org");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://example.org/"
        );
    }

    #[test]
    fn GIVEN_domain_bootstrap_with_two_matching_WHEN_find_THEN_return_longest_match() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Some text",
                "services": [
                  [
                    ["co.uk"],
                    [
                      "https://registry.co.uk/"
                    ]
                  ],
                  [
                    ["uk"],
                    [
                      "https://registry.uk/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse domain bootstrap");

        // WHEN
        let actual = iana.get_dns_bootstrap_urls("foo.co.uk");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://registry.co.uk/"
        );
    }

    #[test]
    fn GIVEN_domain_bootstrap_with_root_WHEN_find_THEN_url_matches() {
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
                    [""],
                    [
                      "https://example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse domain bootstrap");

        // WHEN
        let actual = iana.get_dns_bootstrap_urls("foo.org");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://example.org/"
        );
    }

    #[test]
    fn GIVEN_autnum_bootstrap_with_match_WHEN_find_with_string_THEN_return_match() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["64496-64496"],
                    [
                      "https://rir3.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["64497-64510", "65536-65551"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["64512-65534"],
                    [
                      "http://example.net/rdaprir2/",
                      "https://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse autnum bootstrap");

        // WHEN
        let actual = iana.get_asn_bootstrap_urls("as64498");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://example.org/"
        );
    }

    #[rstest]
    #[case(64497u32, "https://example.org/")]
    #[case(64498u32, "https://example.org/")]
    #[case(64510u32, "https://example.org/")]
    #[case(65536u32, "https://example.org/")]
    #[case(65537u32, "https://example.org/")]
    #[case(64513u32, "http://example.net/rdaprir2/")]
    fn GIVEN_autnum_bootstrap_with_match_WHEN_find_with_number_THEN_return_match(
        #[case] asn: u32,
        #[case] bootstrap_url: &str,
    ) {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["64496-64496"],
                    [
                      "https://rir3.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["64497-64510", "65536-65551"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["64512-65534"],
                    [
                      "http://example.net/rdaprir2/",
                      "https://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse autnum bootstrap");

        // WHEN
        let actual = iana.get_asn_bootstrap_urls(&asn.to_string());

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            bootstrap_url
        );
    }

    #[test]
    fn GIVEN_ipv4_bootstrap_with_match_WHEN_find_with_ip_address_THEN_return_match() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["198.51.100.0/24", "192.0.0.0/8"],
                    [
                      "https://rir1.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["203.0.113.0/24", "192.0.2.0/24"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["203.0.113.0/28"],
                    [
                      "https://example.net/rdaprir2/",
                      "http://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse ipv4 bootstrap");

        // WHEN
        let actual = iana.get_ipv4_bootstrap_urls("198.51.100.1/32");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://rir1.example.com/myrdap/"
        );
    }

    #[test]
    fn GIVEN_ipv4_bootstrap_with_match_WHEN_find_with_cidr_THEN_return_match() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["198.51.100.0/24", "192.0.0.0/8"],
                    [
                      "https://rir1.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["203.0.113.0/24", "192.0.2.0/24"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["203.0.113.0/28"],
                    [
                      "https://example.net/rdaprir2/",
                      "http://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse ipv4 bootstrap");

        // WHEN
        let actual = iana.get_ipv4_bootstrap_urls("203.0.113.0/24");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://example.org/"
        );
    }

    #[test]
    fn GIVEN_ipv6_bootstrap_with_match_WHEN_find_with_ip_address_THEN_return_match() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["2001:db8::/34"],
                    [
                      "https://rir2.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["2001:db8:4000::/36", "2001:db8:ffff::/48"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["2001:db8:1000::/36"],
                    [
                      "https://example.net/rdaprir2/",
                      "http://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse ipv6 bootstrap");

        // WHEN
        let actual = iana.get_ipv6_bootstrap_urls("2001:db8::1/128");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://rir2.example.com/myrdap/"
        );
    }

    #[test]
    fn GIVEN_ipv6_bootstrap_with_match_WHEN_find_with_ip_cidr_THEN_return_match() {
        // GIVEN
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "RDAP Bootstrap file for example registries.",
                "services": [
                  [
                    ["2001:db8::/34"],
                    [
                      "https://rir2.example.com/myrdap/"
                    ]
                  ],
                  [
                    ["2001:db8:4000::/36", "2001:db8:ffff::/48"],
                    [
                      "https://example.org/"
                    ]
                  ],
                  [
                    ["2001:db8:1000::/36"],
                    [
                      "https://example.net/rdaprir2/",
                      "http://example.net/rdaprir2/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse ipv6 bootstrap");

        // WHEN
        let actual = iana.get_ipv6_bootstrap_urls("2001:db8:4000::/36");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://example.org/"
        );
    }

    #[test]
    fn GIVEN_tag_bootstrap_with_match_WHEN_find_with_tag_THEN_return_match() {
        // GIVEN
        let bootstrap = r#"
            {
              "version": "1.0",
              "publication": "YYYY-MM-DDTHH:MM:SSZ",
              "description": "RDAP bootstrap file for service provider object tags",
              "services": [
                [
                  ["contact@example.com"],
                  ["YYYY"],
                  [
                    "https://example.com/rdap/"
                  ]
                ],
                [
                  ["contact@example.org"],
                  ["ZZ54"],
                  [
                    "http://rdap.example.org/"
                  ]
                ],
                [
                  ["contact@example.net"],
                  ["1754"],
                  [
                    "https://example.net/rdap/",
                    "http://example.net/rdap/"
                  ]
                ]
              ]
             }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse tag bootstrap");

        // WHEN
        let actual = iana.get_tag_bootstrap_urls("YYYY");

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://example.com/rdap/"
        );
    }
}
