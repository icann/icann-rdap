use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use icann_rdap_client::query::qtype::QueryType;
use icann_rdap_common::{
    cache::HttpData,
    iana::{iana_request, IanaRegistry, IanaRegistryType},
};
use reqwest::Client;
use simplelog::debug;

use crate::{dirs::bootstrap_cache_path, error::CliError};

pub(crate) fn qtype_to_iana_type(query_type: &QueryType) -> Option<IanaRegistryType> {
    match query_type {
        QueryType::IpV4Addr(_) => Some(IanaRegistryType::RdapBootstrapIpv4),
        QueryType::IpV6Addr(_) => Some(IanaRegistryType::RdapBootstrapIpv6),
        QueryType::IpV4Cidr(_) => Some(IanaRegistryType::RdapBootstrapIpv4),
        QueryType::IpV6Cidr(_) => Some(IanaRegistryType::RdapBootstrapIpv6),
        QueryType::AsNumber(_) => Some(IanaRegistryType::RdapBootstrapAsn),
        QueryType::Domain(_) => Some(IanaRegistryType::RdapBootstrapDns),
        QueryType::Entity(_) => Some(IanaRegistryType::RdapObjectTags),
        QueryType::Nameserver(_) => Some(IanaRegistryType::RdapBootstrapDns),
        _ => None,
    }
}

/// Prefer HTTPS urls.
fn get_preferred_url(urls: Vec<String>) -> Result<String, CliError> {
    if urls.is_empty() {
        Err(CliError::InvalidBootstrap)
    } else {
        let url = urls
            .iter()
            .find(|s| s.starts_with("https://"))
            .unwrap_or_else(|| urls.first().unwrap());
        Ok(url.to_owned())
    }
}

/// Gets the bootstrap url from IANA. Requirements are that it must be the longest match.
fn get_domain_bootstrap_urls(
    iana: IanaRegistry,
    query_type: &QueryType,
) -> Result<Vec<String>, CliError> {
    let QueryType::Domain(domain_name) = query_type else {panic!("invalid query type")};
    let mut longest_match: Option<(usize, Vec<String>)> = None;
    let IanaRegistry::RdapBootstrapRegistry(bootstrap) = iana;
    for service in bootstrap.services {
        let tlds = service.first().ok_or(CliError::InvalidBootstrap)?;
        for tld in tlds {
            if domain_name.ends_with(tld) {
                let urls = service.last().ok_or(CliError::InvalidBootstrap)?;
                let longest = longest_match.get_or_insert_with(|| (tld.len(), urls.to_owned()));
                if longest.0 < tld.len() {
                    *longest = (tld.len(), urls.to_owned());
                }
            }
        }
    }
    let longest = longest_match.ok_or(CliError::BootstrapNotFound)?;
    Ok(longest.1)
}

async fn get_iana_registry(
    reg_type: IanaRegistryType,
    client: &Client,
) -> Result<IanaRegistry, CliError> {
    let path = bootstrap_cache_path().join(reg_type.file_name());
    if path.exists() {
        let input = File::open(&path)?;
        let buf = BufReader::new(input);
        let mut lines = Vec::new();
        for line in buf.lines() {
            lines.push(line?);
        }
        let cache_data = HttpData::from_lines(&lines)?;
        if !cache_data.0.is_expired(604800i64) {
            debug!("Getting bootstrap from {}", reg_type.file_name());
            let iana: IanaRegistry = serde_json::from_str(&cache_data.1.join(""))?;
            return Ok(iana);
        }
    }
    debug!("Getting IANA bootstrap from {}", reg_type.url());
    let iana = iana_request(reg_type, client).await?;
    let data = serde_json::to_string_pretty(&iana.registry)?;
    let cache_contents = iana.http_data.to_lines(&data)?;
    fs::write(path, cache_contents)?;
    Ok(iana.registry)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use icann_rdap_client::query::qtype::QueryType;
    use icann_rdap_common::iana::IanaRegistry;

    use super::{get_domain_bootstrap_urls, get_preferred_url};

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
        let actual = get_domain_bootstrap_urls(iana, &QueryType::Domain("foo.org".to_string()));

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
        let actual = get_domain_bootstrap_urls(iana, &QueryType::Domain("foo.co.uk".to_string()));

        // THEN
        assert_eq!(
            actual.expect("no vec").first().expect("vec is empty"),
            "https://registry.co.uk/"
        );
    }
}
