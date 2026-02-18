use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::PathBuf,
};

use crate::dirs::config_path;

use {
    icann_rdap_client::iana::{BootstrapStore, RegistryHasNotExpired},
    icann_rdap_common::{
        httpdata::HttpData,
        iana::{BootstrapRegistry, IanaRegistry, IanaRegistryType},
    },
    tracing::debug,
};

use super::bootstrap_cache_path;

pub struct FileCacheBootstrapStore;

impl BootstrapStore for FileCacheBootstrapStore {
    fn has_bootstrap_registry(
        &self,
        reg_type: &IanaRegistryType,
    ) -> Result<bool, icann_rdap_client::RdapClientError> {
        let path = bootstrap_cache_path().join(reg_type.file_name());
        if path.exists() {
            let fc_reg = fetch_bootstrap_file(path, |s| debug!("Checking for {s}"))?;
            return Ok(Some(fc_reg).registry_has_not_expired());
        }
        Ok(false)
    }

    fn put_bootstrap_registry(
        &self,
        reg_type: &IanaRegistryType,
        registry: IanaRegistry,
        http_data: HttpData,
    ) -> Result<(), icann_rdap_client::RdapClientError> {
        let bootstrap_cache_path = bootstrap_cache_path().join(reg_type.file_name());
        let data = serde_json::to_string_pretty(&registry)?;
        let cache_contents = http_data.to_lines(&data)?;
        fs::write(bootstrap_cache_path, cache_contents)?;
        Ok(())
    }

    fn get_dns_urls(&self, ldh: &str) -> Result<Vec<String>, icann_rdap_client::RdapClientError> {
        let file_name = IanaRegistryType::RdapBootstrapDns.file_name();

        // check in configured bootstrap override
        let config_path = config_path().join(file_name);
        if config_path.exists() {
            let (iana, _http_data) = fetch_bootstrap_file(config_path, |s| debug!("Reading {s}"))?;
            if let Ok(urls) = iana.get_dns_bootstrap_urls(ldh) {
                debug!("Bootstrap URLs found in configured bootstrap override.");
                return Ok(urls);
            }
        }

        let bootstrap_cache_path = bootstrap_cache_path().join(file_name);
        let (iana, _http_data) =
            fetch_bootstrap_file(bootstrap_cache_path, |s| debug!("Reading {s}"))?;
        Ok(iana.get_dns_bootstrap_urls(ldh)?)
    }

    fn get_asn_urls(&self, asn: &str) -> Result<Vec<String>, icann_rdap_client::RdapClientError> {
        let file_name = IanaRegistryType::RdapBootstrapAsn.file_name();

        // check in configured bootstrap override
        let config_path = config_path().join(file_name);
        if config_path.exists() {
            let (iana, _http_data) = fetch_bootstrap_file(config_path, |s| debug!("Reading {s}"))?;
            if let Ok(urls) = iana.get_asn_bootstrap_urls(asn) {
                debug!("Bootstrap URLs found in configured bootstrap override.");
                return Ok(urls);
            }
        }

        // check in bootstrap cache
        let bootstrap_cache_path = bootstrap_cache_path().join(file_name);
        let (iana, _http_data) =
            fetch_bootstrap_file(bootstrap_cache_path, |s| debug!("Reading {s}"))?;
        Ok(iana.get_asn_bootstrap_urls(asn)?)
    }

    fn get_ipv4_urls(&self, ipv4: &str) -> Result<Vec<String>, icann_rdap_client::RdapClientError> {
        let file_name = IanaRegistryType::RdapBootstrapIpv4.file_name();

        // check in configured bootstrap override
        let config_path = config_path().join(file_name);
        if config_path.exists() {
            let (iana, _http_data) = fetch_bootstrap_file(config_path, |s| debug!("Reading {s}"))?;
            if let Ok(urls) = iana.get_ipv4_bootstrap_urls(ipv4) {
                debug!("Bootstrap URLs found in configured bootstrap override.");
                return Ok(urls);
            }
        }

        // check in bootstrap cache
        let bootstrap_cache_path = bootstrap_cache_path().join(file_name);
        let (iana, _http_data) =
            fetch_bootstrap_file(bootstrap_cache_path, |s| debug!("Reading {s}"))?;
        Ok(iana.get_ipv4_bootstrap_urls(ipv4)?)
    }

    fn get_ipv6_urls(&self, ipv6: &str) -> Result<Vec<String>, icann_rdap_client::RdapClientError> {
        let file_name = IanaRegistryType::RdapBootstrapIpv6.file_name();

        // check in configured bootstrap override
        let config_path = config_path().join(file_name);
        if config_path.exists() {
            let (iana, _http_data) = fetch_bootstrap_file(config_path, |s| debug!("Reading {s}"))?;
            if let Ok(urls) = iana.get_ipv6_bootstrap_urls(ipv6) {
                debug!("Bootstrap URLs found in configured bootstrap override.");
                return Ok(urls);
            }
        }

        // check in bootstrap cache
        let bootstrap_cache_path = bootstrap_cache_path().join(file_name);
        let (iana, _http_data) =
            fetch_bootstrap_file(bootstrap_cache_path, |s| debug!("Reading {s}"))?;
        Ok(iana.get_ipv6_bootstrap_urls(ipv6)?)
    }

    fn get_tag_urls(&self, tag: &str) -> Result<Vec<String>, icann_rdap_client::RdapClientError> {
        let file_name = IanaRegistryType::RdapObjectTags.file_name();

        // check in configured bootstrap override
        let config_path = config_path().join(file_name);
        if config_path.exists() {
            let (iana, _http_data) = fetch_bootstrap_file(config_path, |s| debug!("Reading {s}"))?;
            if let Ok(urls) = iana.get_tag_bootstrap_urls(tag) {
                debug!("Bootstrap URLs found in configured bootstrap override.");
                return Ok(urls);
            }
        }

        // check in bootstrap cache
        let bootstrap_cache_path = bootstrap_cache_path().join(file_name);
        let (iana, _http_data) =
            fetch_bootstrap_file(bootstrap_cache_path, |s| debug!("Reading {s}"))?;
        Ok(iana.get_tag_bootstrap_urls(tag)?)
    }
}

pub fn fetch_bootstrap_file<F>(
    path: PathBuf,
    callback: F,
) -> Result<(IanaRegistry, HttpData), std::io::Error>
where
    F: FnOnce(String),
{
    let input = File::open(&path)?;
    let buf = BufReader::new(input);
    let mut lines = vec![];
    for line in buf.lines() {
        lines.push(line?);
    }
    let cache_data = HttpData::from_lines(&lines)?;
    callback(path.display().to_string());
    let iana: IanaRegistry = serde_json::from_str(&cache_data.1.join(""))?;
    Ok((iana, cache_data.0))
}

#[cfg(test)]
mod test {
    use {
        icann_rdap_client::{
            iana::{BootstrapStore, PreferredUrl},
            rdap::QueryType,
        },
        icann_rdap_common::{
            httpdata::HttpData,
            iana::{IanaRegistry, IanaRegistryType},
        },
        serial_test::serial,
        test_dir::{DirBuilder, FileType, TestDir},
    };

    use crate::dirs::{self, fcbs::FileCacheBootstrapStore};

    fn test_dir() -> TestDir {
        let test_dir = TestDir::temp()
            .create("cache", FileType::Dir)
            .create("config", FileType::Dir);
        unsafe {
            std::env::set_var("XDG_CACHE_HOME", test_dir.path("cache"));
            std::env::set_var("XDG_CONFIG_HOME", test_dir.path("config"));
        };
        dirs::init().expect("unable to init directories");
        test_dir
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_with_dns() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;
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
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapDns,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = bs
            .get_domain_query_urls(&QueryType::domain("example.org").expect("invalid domain name"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://example.org/")
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_with_autnum() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;
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
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapAsn,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = bs
            .get_autnum_query_urls(&QueryType::autnum("as64512").expect("invalid autnum"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://example.net/rdaprir2/");
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_with_ipv4() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;
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
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse autnum bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapIpv4,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = bs
            .get_ipv4_query_urls(&QueryType::ipv4("198.51.100.1").expect("invalid IP address"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://rir1.example.com/myrdap/");
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_with_ipv6() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;
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
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse autnum bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapIpv6,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = bs
            .get_ipv6_query_urls(&QueryType::ipv6("2001:db8::1").expect("invalid IP address"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://rir2.example.com/myrdap/");
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_with_tag() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;
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
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse autnum bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapObjectTags,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = bs
            .get_entity_handle_query_urls(&QueryType::Entity("foo-YYYY".to_string()))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://example.com/rdap/");
    }
}
