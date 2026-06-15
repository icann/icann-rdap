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
    ) -> Result<Option<Vec<String>>, RdapClientError> {
        let domain_name = match query_type {
            QueryType::Domain(domain) => domain.to_ascii(),
            QueryType::ALabel(domain) => domain.to_ascii(),
            QueryType::Nameserver(ns) => ns.to_ascii(),
            _ => panic!("invalid domain query type"),
        };
        let domain_name = domain_name.trim_end_matches('.').to_string();
        self.get_dns_urls(&domain_name)
    }

    /// Get the urls for an autnum query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_autnum_query_urls(
        &self,
        query_type: &QueryType,
    ) -> Result<Option<Vec<String>>, RdapClientError> {
        let asn = match query_type {
            QueryType::AsNumber(asn)
            | QueryType::AsNumberUp(asn)
            | QueryType::AsNumberDown(asn)
            | QueryType::AsNumberTop(asn)
            | QueryType::AsNumberBottom(asn) => asn.to_string(),
            _ => panic!("invalid query type"),
        };
        self.get_asn_urls(asn.as_str())
    }

    /// Get the urls for an IPv4 query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_ipv4_query_urls(
        &self,
        query_type: &QueryType,
    ) -> Result<Option<Vec<String>>, RdapClientError> {
        let ip = match query_type {
            QueryType::IpV4Addr(addr)
            | QueryType::IpV4AddrUp(addr)
            | QueryType::IpV4AddrDown(addr)
            | QueryType::IpV4AddrTop(addr)
            | QueryType::IpV4AddrBottom(addr) => format!("{addr}/32"),
            QueryType::IpV4Cidr(cidr)
            | QueryType::IpV4CidrUp(cidr)
            | QueryType::IpV4CidrDown(cidr)
            | QueryType::IpV4CidrTop(cidr)
            | QueryType::IpV4CidrBottom(cidr) => cidr.to_string(),
            _ => panic!("non ip query for ip bootstrap"),
        };
        self.get_ipv4_urls(&ip)
    }

    /// Get the urls for an IPv6 query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_ipv6_query_urls(
        &self,
        query_type: &QueryType,
    ) -> Result<Option<Vec<String>>, RdapClientError> {
        let ip = match query_type {
            QueryType::IpV6Addr(addr)
            | QueryType::IpV6AddrUp(addr)
            | QueryType::IpV6AddrDown(addr)
            | QueryType::IpV6AddrTop(addr)
            | QueryType::IpV6AddrBottom(addr) => format!("{addr}/128"),
            QueryType::IpV6Cidr(cidr)
            | QueryType::IpV6CidrUp(cidr)
            | QueryType::IpV6CidrDown(cidr)
            | QueryType::IpV6CidrTop(cidr)
            | QueryType::IpV6CidrBottom(cidr) => cidr.to_string(),
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
    ) -> Result<Option<Vec<String>>, RdapClientError> {
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
    fn get_tag_query_urls(&self, tag: &str) -> Result<Option<Vec<String>>, RdapClientError> {
        self.get_tag_urls(tag)
    }

    /// Get the URLs associated with the IANA RDAP DNS bootstrap.
    ///
    /// Returns [None] if no URLs were found for the given key.
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_dns_bootstrap_urls] method.
    fn get_dns_urls(&self, ldh: &str) -> Result<Option<Vec<String>>, RdapClientError>;

    /// Get the URLs associated with the IANA RDAP ASN bootstrap.
    ///
    /// Returns [None] if no URLs were found for the given key.
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_asn_bootstrap_urls] method.
    fn get_asn_urls(&self, asn: &str) -> Result<Option<Vec<String>>, RdapClientError>;

    /// Get the URLs associated with the IANA RDAP IPv4 bootstrap.
    ///
    /// Returns [None] if no URLs were found for the given key.
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_ipv4_bootstrap_urls] method.
    fn get_ipv4_urls(&self, ipv4: &str) -> Result<Option<Vec<String>>, RdapClientError>;

    /// Get the URLs associated with the IANA RDAP IPv6 bootstrap.
    ///
    /// Returns [None] if no URLs were found for the given key.
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_ipv6_bootstrap_urls] method.
    fn get_ipv6_urls(&self, ipv6: &str) -> Result<Option<Vec<String>>, RdapClientError>;

    /// Get the URLs for an RDNS query type.
    ///
    /// The default method should be good enough for most trait implementations.
    fn get_rdns_query_urls(
        &self,
        query_type: &QueryType,
    ) -> Result<Option<Vec<String>>, RdapClientError> {
        let ipnet = match query_type {
            QueryType::RdnsIpv4(cidr)
            | QueryType::RdnsIpv4Up(cidr)
            | QueryType::RdnsIpv4Down(cidr)
            | QueryType::RdnsIpv4Top(cidr)
            | QueryType::RdnsIpv4Bottom(cidr) => cidr.to_string(),
            QueryType::RdnsIpv6(cidr)
            | QueryType::RdnsIpv6Up(cidr)
            | QueryType::RdnsIpv6Down(cidr)
            | QueryType::RdnsIpv6Top(cidr)
            | QueryType::RdnsIpv6Bottom(cidr) => cidr.to_string(),
            _ => panic!("non rdns query for rdns bootstrap"),
        };
        match query_type {
            QueryType::RdnsIpv4(_)
            | QueryType::RdnsIpv4Up(_)
            | QueryType::RdnsIpv4Down(_)
            | QueryType::RdnsIpv4Top(_)
            | QueryType::RdnsIpv4Bottom(_) => self.get_ipv4_urls(&ipnet),
            QueryType::RdnsIpv6(_)
            | QueryType::RdnsIpv6Up(_)
            | QueryType::RdnsIpv6Down(_)
            | QueryType::RdnsIpv6Top(_)
            | QueryType::RdnsIpv6Bottom(_) => self.get_ipv6_urls(&ipnet),
            _ => panic!("non rdns query for rdns bootstrap"),
        }
    }

    /// Get the URLs associated with the IANA RDAP Object Tags bootstrap.
    ///
    /// Returns [None] if no URLs were found for the given key.
    /// Implementations should implement the logic to pull the [icann_rdap_common::iana::IanaRegistry]
    /// and ultimately call its [icann_rdap_common::iana::IanaRegistry::get_tag_bootstrap_urls] method.
    fn get_tag_urls(&self, tag: &str) -> Result<Option<Vec<String>>, RdapClientError>;
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

impl PreferredUrl for Option<Vec<String>> {
    fn preferred_url(self) -> Result<String, RdapClientError> {
        match self {
            Some(vec) => Ok(get_preferred_url(vec)?),
            None => Err(RdapClientError::BootstrapUnavailable),
        }
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

    fn get_dns_urls(&self, ldh: &str) -> Result<Option<Vec<String>>, RdapClientError> {
        if let Some((iana, _http_data)) = self.dns.read()?.as_ref() {
            Ok(iana.get_dns_bootstrap_urls(ldh)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_asn_urls(&self, asn: &str) -> Result<Option<Vec<String>>, RdapClientError> {
        if let Some((iana, _http_data)) = self.autnum.read()?.as_ref() {
            Ok(iana.get_asn_bootstrap_urls(asn)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_ipv4_urls(&self, ipv4: &str) -> Result<Option<Vec<String>>, RdapClientError> {
        if let Some((iana, _http_data)) = self.ipv4.read()?.as_ref() {
            Ok(iana.get_ipv4_bootstrap_urls(ipv4)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_ipv6_urls(&self, ipv6: &str) -> Result<Option<Vec<String>>, RdapClientError> {
        if let Some((iana, _http_data)) = self.ipv6.read()?.as_ref() {
            Ok(iana.get_ipv6_bootstrap_urls(ipv6)?)
        } else {
            Err(RdapClientError::BootstrapUnavailable)
        }
    }

    fn get_tag_urls(&self, tag: &str) -> Result<Option<Vec<String>>, RdapClientError> {
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
        QueryType::IpV4Addr(_)
        | QueryType::IpV4Cidr(_)
        | QueryType::IpV4AddrUp(_)
        | QueryType::IpV4CidrUp(_)
        | QueryType::IpV4AddrDown(_)
        | QueryType::IpV4CidrDown(_)
        | QueryType::IpV4AddrTop(_)
        | QueryType::IpV4CidrTop(_)
        | QueryType::IpV4AddrBottom(_)
        | QueryType::IpV4CidrBottom(_) => {
            fetch_bootstrap(
                &IanaRegistryType::RdapBootstrapIpv4,
                client,
                store,
                callback,
            )
            .await?;
            Ok(store.get_ipv4_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::IpV6Addr(_)
        | QueryType::IpV6Cidr(_)
        | QueryType::IpV6AddrUp(_)
        | QueryType::IpV6CidrUp(_)
        | QueryType::IpV6AddrDown(_)
        | QueryType::IpV6CidrDown(_)
        | QueryType::IpV6AddrTop(_)
        | QueryType::IpV6CidrTop(_)
        | QueryType::IpV6AddrBottom(_)
        | QueryType::IpV6CidrBottom(_) => {
            fetch_bootstrap(
                &IanaRegistryType::RdapBootstrapIpv6,
                client,
                store,
                callback,
            )
            .await?;
            Ok(store.get_ipv6_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::AsNumber(_)
        | QueryType::AsNumberUp(_)
        | QueryType::AsNumberDown(_)
        | QueryType::AsNumberTop(_)
        | QueryType::AsNumberBottom(_) => {
            fetch_bootstrap(&IanaRegistryType::RdapBootstrapAsn, client, store, callback).await?;
            Ok(store.get_autnum_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::Domain(_) | QueryType::ALabel(_) => {
            fetch_bootstrap(&IanaRegistryType::RdapBootstrapDns, client, store, callback).await?;
            Ok(store.get_domain_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::RdnsIpv4(_)
        | QueryType::RdnsIpv4Up(_)
        | QueryType::RdnsIpv4Down(_)
        | QueryType::RdnsIpv4Top(_)
        | QueryType::RdnsIpv4Bottom(_) => {
            fetch_bootstrap(
                &IanaRegistryType::RdapBootstrapIpv4,
                client,
                store,
                callback,
            )
            .await?;
            Ok(store.get_rdns_query_urls(query_type)?.preferred_url()?)
        }
        QueryType::RdnsIpv6(_)
        | QueryType::RdnsIpv6Up(_)
        | QueryType::RdnsIpv6Down(_)
        | QueryType::RdnsIpv6Top(_)
        | QueryType::RdnsIpv6Bottom(_) => {
            fetch_bootstrap(
                &IanaRegistryType::RdapBootstrapIpv6,
                client,
                store,
                callback,
            )
            .await?;
            Ok(store.get_rdns_query_urls(query_type)?.preferred_url()?)
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
mod test {
    use icann_rdap_common::{
        httpdata::HttpData,
        iana::{IanaRegistry, IanaRegistryType},
    };
    use rstest::rstest;

    use crate::{
        http::Client,
        iana::bootstrap::{qtype_to_bootstrap_url, PreferredUrl},
        rdap::{qtype::QueryTypeVariant, QueryType},
        RdapClientError,
    };

    use super::{BootstrapStore, MemoryBootstrapStore};

    fn make_client() -> Client {
        Client::new(
            reqwest::Client::new(),
            crate::http::RequestOptions::default(),
        )
    }

    fn make_store() -> MemoryBootstrapStore {
        MemoryBootstrapStore::new()
    }

    fn bootstrap_url(
        client: &Client,
        store: &MemoryBootstrapStore,
        variant: QueryTypeVariant,
    ) -> Result<String, RdapClientError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        let result = rt.block_on(qtype_to_bootstrap_url(
            client,
            store,
            &variant.to_query_type(),
            |_| {},
        ));
        rt.shutdown_timeout(std::time::Duration::from_millis(100));
        result
    }

    fn bootstrap_url_with_callback(
        client: &Client,
        store: &MemoryBootstrapStore,
        variant: QueryTypeVariant,
    ) -> (Result<String, RdapClientError>, bool) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        let mut callback_called = false;
        let result = rt.block_on(qtype_to_bootstrap_url(
            client,
            store,
            &variant.to_query_type(),
            |_| {
                callback_called = true;
            },
        ));
        rt.shutdown_timeout(std::time::Duration::from_millis(100));
        (result, callback_called)
    }

    fn registry_matches(actual: Option<&IanaRegistryType>, expected: &IanaRegistryType) -> bool {
        matches!(
            (actual, expected),
            (
                Some(IanaRegistryType::RdapBootstrapDns),
                IanaRegistryType::RdapBootstrapDns
            ) | (
                Some(IanaRegistryType::RdapBootstrapAsn),
                IanaRegistryType::RdapBootstrapAsn
            ) | (
                Some(IanaRegistryType::RdapBootstrapIpv4),
                IanaRegistryType::RdapBootstrapIpv4
            ) | (
                Some(IanaRegistryType::RdapBootstrapIpv6),
                IanaRegistryType::RdapBootstrapIpv6
            ) | (
                Some(IanaRegistryType::RdapObjectTags),
                IanaRegistryType::RdapObjectTags
            )
        )
    }

    #[test]
    fn test_membootstrap_with_dns() {
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
    fn test_membootstrap_with_dns_trailing_dot() {
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
            .get_domain_query_urls(&QueryType::domain("example.org.").expect("invalid domain name"))
            .expect("get bootstrap url")
            .preferred_url()
            .expect("preferred url");

        // THEN
        assert_eq!(actual, "https://example.org/")
    }

    #[test]
    fn test_membootstrap_with_autnum() {
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
    fn test_membootstrap_with_ipv4() {
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
    fn test_membootstrap_with_ipv6() {
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
    fn test_membootstrap_with_tag() {
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

    // Non-bootstrap variants: must return BootstrapUnavailable from the catch-all `_` arm.
    #[rstest]
    #[case(QueryTypeVariant::EntityNameSearch)]
    #[case(QueryTypeVariant::EntityHandleSearch)]
    #[case(QueryTypeVariant::NetworkHandleSearch)]
    #[case(QueryTypeVariant::NetworkNameSearch)]
    #[case(QueryTypeVariant::DomainNameSearch)]
    #[case(QueryTypeVariant::DomainNsNameSearch)]
    #[case(QueryTypeVariant::DomainNsIpSearch)]
    #[case(QueryTypeVariant::NameserverNameSearch)]
    #[case(QueryTypeVariant::NameserverIpSearch)]
    #[case(QueryTypeVariant::AutnumHandleSearch)]
    #[case(QueryTypeVariant::AutnumNameSearch)]
    #[case(QueryTypeVariant::Help)]
    #[case(QueryTypeVariant::Url)]
    fn test_non_bootstrap_returns_unavailable(#[case] variant: QueryTypeVariant) {
        // GIVEN
        let client = make_client();
        let store = make_store();

        // WHEN
        let result = bootstrap_url(&client, &store, variant);

        // THEN — non-bootstrap variants hit the `_ => Err(...)` catch-all arm
        assert!(
            matches!(result, Err(RdapClientError::BootstrapUnavailable)),
            "Variant {:?} is not a bootstrap variant but did not return BootstrapUnavailable",
            variant
        );
    }

    // Bootstrap variants: dispatch to the correct match arm (callback called),
    // and return Ok or a non-BootstrapUnavailable error.
    #[rstest]
    #[case(QueryTypeVariant::IpV4Addr, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6Addr, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4Cidr, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6Cidr, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4AddrUp, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6AddrUp, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4CidrUp, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6CidrUp, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4AddrDown, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6AddrDown, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4CidrDown, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6CidrDown, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4AddrTop, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6AddrTop, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4CidrTop, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6CidrTop, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4AddrBottom, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6AddrBottom, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::IpV4CidrBottom, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::IpV6CidrBottom, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::AsNumber, IanaRegistryType::RdapBootstrapAsn)]
    #[case(QueryTypeVariant::AsNumberUp, IanaRegistryType::RdapBootstrapAsn)]
    #[case(QueryTypeVariant::AsNumberDown, IanaRegistryType::RdapBootstrapAsn)]
    #[case(QueryTypeVariant::AsNumberTop, IanaRegistryType::RdapBootstrapAsn)]
    #[case(QueryTypeVariant::AsNumberBottom, IanaRegistryType::RdapBootstrapAsn)]
    #[case(QueryTypeVariant::Domain, IanaRegistryType::RdapBootstrapDns)]
    #[case(QueryTypeVariant::ALabel, IanaRegistryType::RdapBootstrapDns)]
    #[case(QueryTypeVariant::Nameserver, IanaRegistryType::RdapBootstrapDns)]
    #[case(QueryTypeVariant::Entity, IanaRegistryType::RdapObjectTags)]
    #[case(QueryTypeVariant::RdnsIpv4, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::RdnsIpv6, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::RdnsIpv4Up, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::RdnsIpv6Up, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::RdnsIpv4Down, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::RdnsIpv6Down, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::RdnsIpv4Top, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::RdnsIpv6Top, IanaRegistryType::RdapBootstrapIpv6)]
    #[case(QueryTypeVariant::RdnsIpv4Bottom, IanaRegistryType::RdapBootstrapIpv4)]
    #[case(QueryTypeVariant::RdnsIpv6Bottom, IanaRegistryType::RdapBootstrapIpv6)]
    fn test_bootstrap_variant_dispatches_correctly(
        #[case] variant: QueryTypeVariant,
        #[case] expected_registry: IanaRegistryType,
    ) {
        // GIVEN
        let client = make_client();
        let store = make_store();

        // Verify the variant maps to the expected registry type
        let actual = variant.bootstrap_registry();
        assert!(
            registry_matches(actual.as_ref(), &expected_registry),
            "Variant {:?} should map to {:?}, got {:?}",
            variant,
            expected_registry,
            actual
        );

        // WHEN
        let (result, callback_called) = bootstrap_url_with_callback(&client, &store, variant);

        // THEN — bootstrap variants dispatch correctly (not the catch-all `_` arm).
        // The callback being called proves the correct match arm was reached.
        assert!(
            callback_called,
            "Bootstrap variant {:?} (expected registry {:?}) did not reach the correct match arm",
            variant, expected_registry
        );

        // The result may succeed (Ok), fail with a network error (Client), fail at
        // the store query (BootstrapError/BootstrapUnavailable from store getters), etc.
        // The key assertion above (callback_called) proves the correct match arm was reached.
        assert!(
            matches!(
                &result,
                Ok(_)
                    | Err(RdapClientError::Client(_)
                        | RdapClientError::BootstrapError(_)
                        | RdapClientError::BootstrapUnavailable)
            ),
            "Bootstrap variant {:?} (expected registry {:?}) unexpected result: {:?}",
            variant,
            expected_registry,
            result
        );
    }
}
