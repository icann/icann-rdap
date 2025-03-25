//! Does RDAP query bootstrapping.

use std::sync::{Arc, RwLock};

use icann_rdap_common::{
    httpdata::HttpData,
    iana::{
        get_preferred_url, BootstrapRegistry, BootstrapRegistryError, IanaRegistry,
        IanaRegistryType,
    },
};

use crate::{http::Client, iana::iana_request::iana_request, rdap::QueryType, RdapClientError};

const SECONDS_IN_WEEK: i64 = 604800;

/// Defines a trait for things that store bootstrap registries.
pub trait BootstrapStore: Send + Sync {
    /// Called when store is checked to see if it has a valid bootstrap registry.
    ///
    /// This method should return false (i.e. `Ok(false)``) if the registry doesn't
    /// exist in the store or if the registry in the store is out-of-date (such as
    /// the cache control data indicates it is old).
    fn has_bootstrap_registry(&self, reg_type: &IanaRegistryType) -> Result<bool, RdapClientError>;

    /// Puts a registry into the bootstrap registry store.
    fn put_bootstrap_registry(
        &self,
        reg_type: &IanaRegistryType,
        registry: IanaRegistry,
        http_data: HttpData,
    ) -> Result<(), RdapClientError>;

    /// Get the urls for a domain or nameserver (which are domain names) query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_domain_query_urls(
        &self,
        query_type: &QueryType,
    ) -> Result<Vec<String>, RdapClientError> {
        let domain_name = match query_type {
            QueryType::Domain(domain) => domain.to_ascii(),
            QueryType::Nameserver(ns) => ns.to_ascii(),
            _ => panic!("invalid domain query type"),
        };
        self.get_dns_urls(domain_name)
    }

    /// Get the urls for an autnum query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_autnum_query_urls(
        &self,
        query_type: &QueryType,
    ) -> Result<Vec<String>, RdapClientError> {
        let QueryType::AsNumber(asn) = query_type else {
            panic!("invalid query type")
        };
        self.get_asn_urls(asn.to_string().as_str())
    }

    /// Get the urls for an IPv4 query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_ipv4_query_urls(&self, query_type: &QueryType) -> Result<Vec<String>, RdapClientError> {
        let ip = match query_type {
            QueryType::IpV4Addr(addr) => format!("{addr}/32"),
            QueryType::IpV4Cidr(cidr) => cidr.to_string(),
            _ => panic!("non ip query for ip bootstrap"),
        };
        self.get_ipv4_urls(&ip)
    }

    /// Get the urls for an IPv6 query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_ipv6_query_urls(&self, query_type: &QueryType) -> Result<Vec<String>, RdapClientError> {
        let ip = match query_type {
            QueryType::IpV6Addr(addr) => format!("{addr}/128"),
            QueryType::IpV6Cidr(cidr) => cidr.to_string(),
            _ => panic!("non ip query for ip bootstrap"),
        };
        self.get_ipv6_urls(&ip)
    }

    /// Get the urls for an entity handle query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_entity_handle_query_urls(
        &self,
        query_type: &QueryType,
    ) -> Result<Vec<String>, RdapClientError> {
        let QueryType::Entity(handle) = query_type else {
            panic!("non entity handle for bootstrap")
        };
        let handle_split = handle
            .rsplit_once('-')
            .ok_or(BootstrapRegistryError::InvalidBootstrapInput)?;
        self.get_tag_query_urls(handle_split.1)
    }

    /// Get the urls for an object tag query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_tag_query_urls(&self, tag: &str) -> Result<Vec<String>, RdapClientError> {
        self.get_tag_urls(tag)
    }

    /// Get the URLs associated with the IANA RDAP DNS bootstrap.
    ///
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_dns_bootstrap_urls] method.
    fn get_dns_urls(&self, ldh: &str) -> Result<Vec<String>, RdapClientError>;

    /// Get the URLs associated with the IANA RDAP ASN bootstrap.
    ///
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_asn_bootstrap_urls] method.
    fn get_asn_urls(&self, asn: &str) -> Result<Vec<String>, RdapClientError>;

    /// Get the URLs associated with the IANA RDAP IPv4 bootstrap.
    ///
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_ipv4_bootstrap_urls] method.
    fn get_ipv4_urls(&self, ipv4: &str) -> Result<Vec<String>, RdapClientError>;

    /// Get the URLs associated with the IANA RDAP IPv6 bootstrap.
    ///
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_ipv6_bootstrap_urls] method.
    fn get_ipv6_urls(&self, ipv6: &str) -> Result<Vec<String>, RdapClientError>;

    /// Get the URLs associated with the IANA RDAP Object Tags bootstrap.
    ///
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_tag_bootstrap_urls] method.
    fn get_tag_urls(&self, tag: &str) -> Result<Vec<String>, RdapClientError>;
}

/// A trait to find the preferred URL from a bootstrap service.
pub trait PreferredUrl {
    fn preferred_url(self) -> Result<String, RdapClientError>;
}

impl PreferredUrl for Vec<String> {
    fn preferred_url(self) -> Result<String, RdapClientError> {
        Ok(get_preferred_url(self)?)
    }
}

/// A bootstrap registry store backed by memory.
///
/// This implementation of [BootstrapStore] keeps registries in memory. Every new instance starts with
/// no registries in memory. They are added and maintained over time by calls to [MemoryBootstrapStore::put_bootstrap_registry()] by the
/// machinery of [crate::rdap::request::rdap_bootstrapped_request()] and [crate::iana::bootstrap::qtype_to_bootstrap_url()].
///
/// Ideally, this should be kept in the same scope as [reqwest::Client].
pub struct MemoryBootstrapStore {
    ipv4: Arc<RwLock<Option<(IanaRegistry, HttpData)>>>,
    ipv6: Arc<RwLock<Option<(IanaRegistry, HttpData)>>>,
    autnum: Arc<RwLock<Option<(IanaRegistry, HttpData)>>>,
    dns: Arc<RwLock<Option<(IanaRegistry, HttpData)>>>,
    tag: Arc<RwLock<Option<(IanaRegistry, HttpData)>>>,
}

unsafe impl Send for MemoryBootstrapStore {}
unsafe impl Sync for MemoryBootstrapStore {}

impl Default for MemoryBootstrapStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBootstrapStore {
    pub fn new() -> Self {
        Self {
            ipv4: <_>::default(),
            ipv6: <_>::default(),
            autnum: <_>::default(),
            dns: <_>::default(),
            tag: <_>::default(),
        }
    }
}

impl BootstrapStore for MemoryBootstrapStore {
    fn has_bootstrap_registry(&self, reg_type: &IanaRegistryType) -> Result<bool, RdapClientError> {
        Ok(match reg_type {
            IanaRegistryType::RdapBootstrapDns => self.dns.read()?.registry_has_not_expired(),
            IanaRegistryType::RdapBootstrapAsn => self.autnum.read()?.registry_has_not_expired(),
            IanaRegistryType::RdapBootstrapIpv4 => self.ipv4.read()?.registry_has_not_expired(),
            IanaRegistryType::RdapBootstrapIpv6 => self.ipv6.read()?.registry_has_not_expired(),
            IanaRegistryType::RdapObjectTags => self.tag.read()?.registry_has_not_expired(),
        })
    }

    fn put_bootstrap_registry(
        &self,
        reg_type: &IanaRegistryType,
        registry: IanaRegistry,
        http_data: HttpData,
    ) -> Result<(), RdapClientError> {
        match reg_type {
            IanaRegistryType::RdapBootstrapDns => {
                let mut g = self.dns.write()?;
                *g = Some((registry, http_data));
            }
            IanaRegistryType::RdapBootstrapAsn => {
                let mut g = self.autnum.write()?;
                *g = Some((registry, http_data));
            }
            IanaRegistryType::RdapBootstrapIpv4 => {
                let mut g = self.ipv4.write()?;
                *g = Some((registry, http_data));
            }
            IanaRegistryType::RdapBootstrapIpv6 => {
                let mut g = self.ipv6.write()?;
                *g = Some((registry, http_data));
            }
            IanaRegistryType::RdapObjectTags => {
                let mut g = self.tag.write()?;
                *g = Some((registry, http_data));
            }
        };
        Ok(())
    }

    fn get_dns_urls(&self, ldh: &str) -> Result<Vec<String>, RdapClientError> {
        if let Some((iana, _http_data)) = self.dns.read()?.as_ref() {
            Ok(iana.get_dns_bootstrap_urls(ldh)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_asn_urls(&self, asn: &str) -> Result<Vec<String>, RdapClientError> {
        if let Some((iana, _http_data)) = self.autnum.read()?.as_ref() {
            Ok(iana.get_asn_bootstrap_urls(asn)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_ipv4_urls(&self, ipv4: &str) -> Result<Vec<String>, RdapClientError> {
        if let Some((iana, _http_data)) = self.ipv4.read()?.as_ref() {
            Ok(iana.get_ipv4_bootstrap_urls(ipv4)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_ipv6_urls(&self, ipv6: &str) -> Result<Vec<String>, RdapClientError> {
        if let Some((iana, _http_data)) = self.ipv6.read()?.as_ref() {
            Ok(iana.get_ipv6_bootstrap_urls(ipv6)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_tag_urls(&self, tag: &str) -> Result<Vec<String>, RdapClientError> {
        if let Some((iana, _http_data)) = self.tag.read()?.as_ref() {
            Ok(iana.get_tag_bootstrap_urls(tag)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }
}

/// Trait to determine if a bootstrap registry is past its expiration (i.e. needs to be rechecked).
pub trait RegistryHasNotExpired {
    fn registry_has_not_expired(&self) -> bool;
}

impl RegistryHasNotExpired for Option<(IanaRegistry, HttpData)> {
    fn registry_has_not_expired(&self) -> bool {
        if let Some((_iana, http_data)) = self {
            !http_data.is_expired(SECONDS_IN_WEEK)
        } else {
            false
        }
    }
}

/// Given a [QueryType], it will get the bootstrap URL.
pub async fn qtype_to_bootstrap_url<F>(
    client: &Client,
    store: &dyn BootstrapStore,
    query_type: &QueryType,
    callback: F,
) -> Result<String, RdapClientError>
where
    F: FnOnce(&IanaRegistryType),
{
    match query_type {
        QueryType::IpV4Addr(_) | QueryType::IpV4Cidr(_) => {
            fetch_bootstrap(
                &IanaRegistryType::RdapBootstrapIpv4,
                client,
                store,
                callback,
            )
            .await?;
            Ok(store.get_ipv4_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::IpV6Addr(_) | QueryType::IpV6Cidr(_) => {
            fetch_bootstrap(
                &IanaRegistryType::RdapBootstrapIpv6,
                client,
                store,
                callback,
            )
            .await?;
            Ok(store.get_ipv6_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::AsNumber(_) => {
            fetch_bootstrap(&IanaRegistryType::RdapBootstrapAsn, client, store, callback).await?;
            Ok(store.get_autnum_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::Domain(_) => {
            fetch_bootstrap(&IanaRegistryType::RdapBootstrapDns, client, store, callback).await?;
            Ok(store.get_domain_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::Entity(_) => {
            fetch_bootstrap(&IanaRegistryType::RdapObjectTags, client, store, callback).await?;
            Ok(store
                .get_entity_handle_query_urls(query_type)?
                .preferred_url()?)
        }
        QueryType::Nameserver(_) => {
            fetch_bootstrap(&IanaRegistryType::RdapBootstrapDns, client, store, callback).await?;
            Ok(store.get_domain_query_urls(query_type)?.preferred_url()?)
        }
        _ => Err(RdapClientError::BootstrapUnavailable),
    }
}

/// Fetches a bootstrap registry for a [BootstrapStore].
pub async fn fetch_bootstrap<F>(
    reg_type: &IanaRegistryType,
    client: &Client,
    store: &dyn BootstrapStore,
    callback: F,
) -> Result<(), RdapClientError>
where
    F: FnOnce(&IanaRegistryType),
{
    if !store.has_bootstrap_registry(reg_type)? {
        callback(reg_type);
        let iana_resp = iana_request(reg_type.clone(), client).await?;
        store.put_bootstrap_registry(reg_type, iana_resp.registry, iana_resp.http_data)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use icann_rdap_common::{
        httpdata::HttpData,
        iana::{IanaRegistry, IanaRegistryType},
    };

    use crate::{iana::bootstrap::PreferredUrl, rdap::QueryType};

    use super::{BootstrapStore, MemoryBootstrapStore};

    #[test]
    fn GIVEN_membootstrap_with_dns_WHEN_get_domain_query_url_THEN_correct_url() {
        // GIVEN
        let mem = MemoryBootstrapStore::new();
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
        mem.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapDns,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = mem
            .get_domain_query_urls(&QueryType::domain("example.org").expect("invalid domain name"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://example.org/")
    }

    #[test]
    fn GIVEN_membootstrap_with_autnum_WHEN_get_autnum_query_url_THEN_correct_url() {
        // GIVEN
        let mem = MemoryBootstrapStore::new();
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
        mem.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapAsn,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = mem
            .get_autnum_query_urls(&QueryType::autnum("as64512").expect("invalid autnum"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://example.net/rdaprir2/");
    }

    #[test]
    fn GIVEN_membootstrap_with_ipv4_THEN_get_ipv4_query_urls_THEN_correct_url() {
        // GIVEN
        let mem = MemoryBootstrapStore::new();
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
        mem.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapIpv4,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = mem
            .get_ipv4_query_urls(&QueryType::ipv4("198.51.100.1").expect("invalid IP address"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://rir1.example.com/myrdap/");
    }

    #[test]
    fn GIVEN_membootstrap_with_ipv6_THEN_get_ipv6_query_urls_THEN_correct_url() {
        // GIVEN
        let mem = MemoryBootstrapStore::new();
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
        mem.put_bootstrap_registry(
            &IanaRegistryType::RdapBootstrapIpv6,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = mem
            .get_ipv6_query_urls(&QueryType::ipv6("2001:db8::1").expect("invalid IP address"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://rir2.example.com/myrdap/");
    }

    #[test]
    fn GIVEN_membootstrap_with_tag_THEN_get_tag_query_urls_THEN_correct_url() {
        // GIVEN
        let mem = MemoryBootstrapStore::new();
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
        mem.put_bootstrap_registry(
            &IanaRegistryType::RdapObjectTags,
            iana,
            HttpData::example().build(),
        )
        .expect("put iana registry");

        // WHEN
        let actual = mem
            .get_entity_handle_query_urls(&QueryType::Entity("foo-YYYY".to_string()))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://example.com/rdap/");
    }
}
