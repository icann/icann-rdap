use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::PathBuf,
};

use crate::dirs::config_dir;

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
        let file_name = reg_type.file_name();
        let path = bootstrap_cache_path().join(file_name);
        if path.exists() {
            debug!("Looking for {file_name} bootstrap information.");
            let fc_reg = read_bootstrap_cache_file(path, |_| {})?;
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

    fn get_dns_urls(
        &self,
        ldh: &str,
    ) -> Result<Option<Vec<String>>, icann_rdap_client::RdapClientError> {
        self.get_bootstrap_urls(&IanaRegistryType::RdapBootstrapDns, ldh)
    }

    fn get_asn_urls(
        &self,
        asn: &str,
    ) -> Result<Option<Vec<String>>, icann_rdap_client::RdapClientError> {
        self.get_bootstrap_urls(&IanaRegistryType::RdapBootstrapAsn, asn)
    }

    fn get_ipv4_urls(
        &self,
        ipv4: &str,
    ) -> Result<Option<Vec<String>>, icann_rdap_client::RdapClientError> {
        self.get_bootstrap_urls(&IanaRegistryType::RdapBootstrapIpv4, ipv4)
    }

    fn get_ipv6_urls(
        &self,
        ipv6: &str,
    ) -> Result<Option<Vec<String>>, icann_rdap_client::RdapClientError> {
        self.get_bootstrap_urls(&IanaRegistryType::RdapBootstrapIpv6, ipv6)
    }

    fn get_tag_urls(
        &self,
        tag: &str,
    ) -> Result<Option<Vec<String>>, icann_rdap_client::RdapClientError> {
        self.get_bootstrap_urls(&IanaRegistryType::RdapObjectTags, tag)
    }
}

impl FileCacheBootstrapStore {
    fn get_bootstrap_urls(
        &self,
        reg_type: &IanaRegistryType,
        key: &str,
    ) -> Result<Option<Vec<String>>, icann_rdap_client::RdapClientError> {
        let file_name = reg_type.file_name();

        // Check in configured bootstrap override
        let config_bootstrap_path = config_dir().join(file_name);
        if config_bootstrap_path.exists() {
            let iana = read_bootstrap_config_file(config_bootstrap_path, |s| debug!("Reading {s}"));
            match iana {
                Ok(iana) => {
                    let urls = match reg_type {
                        IanaRegistryType::RdapBootstrapDns => iana.get_dns_bootstrap_urls(key),
                        IanaRegistryType::RdapBootstrapAsn => iana.get_asn_bootstrap_urls(key),
                        IanaRegistryType::RdapBootstrapIpv4 => iana.get_ipv4_bootstrap_urls(key),
                        IanaRegistryType::RdapBootstrapIpv6 => iana.get_ipv6_bootstrap_urls(key),
                        IanaRegistryType::RdapObjectTags => iana.get_tag_bootstrap_urls(key),
                    };
                    match urls {
                        Ok(Some(urls)) => {
                            debug!("Bootstrap URLs found in configured bootstrap override.");
                            return Ok(Some(urls));
                        }
                        Ok(None) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(err) => return Err(err),
            }
        }

        // Fall back to bootstrap cache
        let bootstrap_cache_path = bootstrap_cache_path().join(file_name);
        let (iana, _http_data) =
            read_bootstrap_cache_file(bootstrap_cache_path, |s| debug!("Reading {s}"))?;
        let urls = match reg_type {
            IanaRegistryType::RdapBootstrapDns => iana.get_dns_bootstrap_urls(key),
            IanaRegistryType::RdapBootstrapAsn => iana.get_asn_bootstrap_urls(key),
            IanaRegistryType::RdapBootstrapIpv4 => iana.get_ipv4_bootstrap_urls(key),
            IanaRegistryType::RdapBootstrapIpv6 => iana.get_ipv6_bootstrap_urls(key),
            IanaRegistryType::RdapObjectTags => iana.get_tag_bootstrap_urls(key),
        };
        Ok(urls?)
    }
}

pub fn read_bootstrap_cache_file<F>(
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

pub fn read_bootstrap_config_file<F>(
    path: PathBuf,
    callback: F,
) -> Result<IanaRegistry, icann_rdap_client::RdapClientError>
where
    F: FnOnce(String),
{
    let mut input = File::open(&path)?;
    let mut content = String::new();
    input.read_to_string(&mut content)?;
    callback(path.display().to_string());
    let iana: IanaRegistry = serde_json::from_str(&content)?;
    Ok(iana)
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
            iana::{BootstrapRegistry, IanaRegistry, IanaRegistryType},
        },
        serial_test::serial,
        test_dir::{DirBuilder, FileType, TestDir},
    };

    use crate::dirs::{self, bootstrap_cache_path, config_dir, fcbs::FileCacheBootstrapStore};

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
        assert_eq!(actual, "https://example.com/rdap/")
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_dns_config_override() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        let cache_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Cache bootstrap",
                "services": [
                  [
                    ["org"],
                    [
                      "https://cache.example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let iana = serde_json::from_str::<IanaRegistry>(cache_bootstrap)
            .expect("cannot parse cache bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapDns,
            iana,
            HttpData::example().build(),
        )
        .expect("put cache iana registry");

        let config_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Config override bootstrap",
                "services": [
                  [
                    ["org"],
                    [
                      "https://config.example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let bootstrap_config_path = config_dir().join("dns.json");
        std::fs::write(&bootstrap_config_path, config_bootstrap).expect("write config bootstrap");

        // WHEN
        let actual = bs
            .get_domain_query_urls(&QueryType::domain("example.org").expect("invalid domain name"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://config.example.org/")
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_asn_config_override() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        let cache_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Cache bootstrap",
                "services": [
                  [
                    ["64496-64496"],
                    [
                      "https://cache.example.com/"
                    ]
                  ]
                ]
            }
        "#;
        let iana = serde_json::from_str::<IanaRegistry>(cache_bootstrap)
            .expect("cannot parse cache bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapAsn,
            iana,
            HttpData::example().build(),
        )
        .expect("put cache iana registry");

        let config_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Config override bootstrap",
                "services": [
                  [
                    ["64496-64496"],
                    [
                      "https://config.example.com/"
                    ]
                  ]
                ]
            }
        "#;
        let bootstrap_config_path = config_dir().join("asn.json");
        std::fs::write(&bootstrap_config_path, config_bootstrap).expect("write config bootstrap");

        // WHEN
        let actual = bs
            .get_autnum_query_urls(&QueryType::autnum("as64496").expect("invalid autnum"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://config.example.com/")
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_ipv4_config_override() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        let cache_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Cache bootstrap",
                "services": [
                  [
                    ["198.51.100.0/24"],
                    [
                      "https://cache.example.com/"
                    ]
                  ]
                ]
            }
        "#;
        let iana = serde_json::from_str::<IanaRegistry>(cache_bootstrap)
            .expect("cannot parse cache bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapIpv4,
            iana,
            HttpData::example().build(),
        )
        .expect("put cache iana registry");

        let config_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Config override bootstrap",
                "services": [
                  [
                    ["198.51.100.0/24"],
                    [
                      "https://config.example.com/"
                    ]
                  ]
                ]
            }
        "#;
        let bootstrap_config_path = config_dir().join("ipv4.json");
        std::fs::write(&bootstrap_config_path, config_bootstrap).expect("write config bootstrap");

        // WHEN
        let actual = bs
            .get_ipv4_query_urls(&QueryType::ipv4("198.51.100.1").expect("invalid IP address"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://config.example.com/")
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_ipv6_config_override() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        let cache_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Cache bootstrap",
                "services": [
                  [
                    ["2001:db8::/32"],
                    [
                      "https://cache.example.com/"
                    ]
                  ]
                ]
            }
        "#;
        let iana = serde_json::from_str::<IanaRegistry>(cache_bootstrap)
            .expect("cannot parse cache bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapIpv6,
            iana,
            HttpData::example().build(),
        )
        .expect("put cache iana registry");

        let config_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Config override bootstrap",
                "services": [
                  [
                    ["2001:db8::/32"],
                    [
                      "https://config.example.com/"
                    ]
                  ]
                ]
            }
        "#;
        let bootstrap_config_path = config_dir().join("ipv6.json");
        std::fs::write(&bootstrap_config_path, config_bootstrap).expect("write config bootstrap");

        // WHEN
        let actual = bs
            .get_ipv6_query_urls(&QueryType::ipv6("2001:db8::1").expect("invalid IP address"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://config.example.com/")
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_tag_config_override() {
        // GIVEN
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        let cache_bootstrap = r#"
            {
              "version": "1.0",
              "publication": "YYYY-MM-DDTHH:MM:SSZ",
              "description": "Cache bootstrap",
              "services": [
                [
                  ["contact@example.com"],
                  ["YYYY"],
                  [
                    "https://cache.example.com/rdap/"
                  ]
                ]
              ]
             }
        "#;
        let iana = serde_json::from_str::<IanaRegistry>(cache_bootstrap)
            .expect("cannot parse cache bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapObjectTags,
            iana,
            HttpData::example().build(),
        )
        .expect("put cache iana registry");

        let config_bootstrap = r#"
            {
              "version": "1.0",
              "publication": "YYYY-MM-DDTHH:MM:SSZ",
              "description": "Config override bootstrap",
              "services": [
                [
                  ["contact@example.com"],
                  ["YYYY"],
                  [
                    "https://config.example.com/rdap/"
                  ]
                ]
              ]
             }
        "#;
        let bootstrap_config_path = config_dir().join("object-tags.json");
        std::fs::write(&bootstrap_config_path, config_bootstrap).expect("write config bootstrap");

        // WHEN
        let actual = bs
            .get_entity_handle_query_urls(&QueryType::Entity("foo-YYYY".to_string()))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://config.example.com/rdap/")
    }

    #[test]
    fn test_iana_registry_propagates_invalid_asn_input_error() {
        // GIVEN - valid ASN bootstrap
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "ASN bootstrap",
                "services": [
                  [
                    ["64496-64496"],
                    [
                      "https://example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let iana: IanaRegistry =
            serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse bootstrap");

        // WHEN - query with invalid (non-numeric) ASN input
        let result = iana.get_asn_bootstrap_urls("notanumber");

        // THEN - should return error for invalid input
        assert!(
            result.is_err(),
            "Expected error for invalid ASN input but got: {:?}",
            result
        );
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_propagates_invalid_asn_via_store() {
        // GIVEN - valid ASN bootstrap in store
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;
        let bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "ASN bootstrap",
                "services": [
                  [
                    ["64496-64496"],
                    [
                      "https://example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let iana = serde_json::from_str::<IanaRegistry>(bootstrap).expect("cannot parse bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapAsn,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN - query with invalid ASN (non-numeric)
        let result = bs.get_asn_urls("notanumber");

        // THEN - should propagate the error
        assert!(
            result.is_err(),
            "Expected error for invalid ASN but got: {:?}",
            result
        );
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_config_override_propagates_errors() {
        // GIVEN - config override with valid bootstrap but query returns None
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        // Valid bootstrap but doesn't have "example.org"
        let config_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Config bootstrap",
                "services": [
                  [
                    ["com"],
                    [
                      "https://config.example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let bootstrap_config_path = config_dir().join("dns.json");
        std::fs::write(&bootstrap_config_path, config_bootstrap).expect("write config bootstrap");

        // Also put a cache version that has a different TLD
        let cache_bootstrap = r#"
            {
                "version": "1.0",
                "publication": "2024-01-07T10:11:12Z",
                "description": "Cache bootstrap",
                "services": [
                  [
                    ["net"],
                    [
                      "https://cache.example.org/"
                    ]
                  ]
                ]
            }
        "#;
        let iana =
            serde_json::from_str::<IanaRegistry>(cache_bootstrap).expect("cannot parse bootstrap");
        bs.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapDns,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN - query for a TLD that doesn't exist in either config or cache
        let result = bs
            .get_domain_query_urls(&QueryType::domain("example.org").expect("invalid domain name"));

        // THEN - should return Ok(None) for not found, not an error
        assert!(result.is_ok(), "Expected Ok but got: {:?}", result);
        assert!(result.unwrap().is_none(), "Expected None but got Some");
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_propagates_invalid_json_error() {
        // GIVEN - invalid JSON in config override
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        // Write invalid (malformed) JSON
        let invalid_json = r#"{ "version": "1.0", invalid json }"#;
        let bootstrap_config_path = config_dir().join("dns.json");
        std::fs::write(&bootstrap_config_path, invalid_json).expect("write invalid json");

        // WHEN
        let result = bs
            .get_domain_query_urls(&QueryType::domain("example.org").expect("invalid domain name"));

        // THEN - should propagate the JSON parse error
        assert!(
            result.is_err(),
            "Expected error for invalid JSON but got: {:?}",
            result
        );
    }

    #[test]
    #[serial]
    fn test_fcbootstrap_propagates_invalid_json_in_cache_error() {
        // GIVEN - invalid JSON in cache file
        let _test_dir = test_dir();
        let bs = FileCacheBootstrapStore;

        // Write invalid (malformed) JSON to cache directly
        let invalid_json = r#"{ "version": "1.0", bad json }"#;
        let cache_path = bootstrap_cache_path().join("dns.json");
        std::fs::write(&cache_path, invalid_json).expect("write invalid json to cache");

        // WHEN
        let result = bs
            .get_domain_query_urls(&QueryType::domain("example.org").expect("invalid domain name"));

        // THEN - should propagate the JSON parse error
        assert!(
            result.is_err(),
            "Expected error for invalid JSON in cache but got: {:?}",
            result
        );
    }
}
