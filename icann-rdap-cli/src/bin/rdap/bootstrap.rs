use {
    crate::error::RdapCliError,
    icann_rdap_cli::dirs::fcbs::FileCacheBootstrapStore,
    icann_rdap_client::{
        http::Client,
        iana::{fetch_bootstrap, qtype_to_bootstrap_url, BootstrapStore, PreferredUrl},
        rdap::QueryType,
    },
    icann_rdap_common::iana::IanaRegistryType,
    tracing::debug,
};

/// Defines the type of bootstrapping to use.
pub(crate) enum BootstrapType {
    /// Use RFC 9224 bootstrapping.
    ///
    /// This is the typical bootstrapping for RDAP as defined by RFC 9224.
    Rfc9224,

    /// Use the supplied URL.
    ///
    /// Essentially, this means no bootstrapping as the client is being given
    /// a full URL.
    Url(String),

    /// Use a hint.
    ///
    /// This will try to find an authoritative server by cycling through the various
    /// bootstrap registries in the following order: object tags, TLDs, IP addresses,
    /// ASNs.
    Hint(String),
}

pub(crate) async fn get_base_url(
    bootstrap_type: &BootstrapType,
    client: &Client,
    query_type: &QueryType,
) -> Result<String, RdapCliError> {
    if let QueryType::Url(url) = query_type {
        // this is ultimately ignored without this logic a bootstrap not found error is thrown
        // which is wrong for URL queries.
        return Ok(url.to_owned());
    }

    let store = FileCacheBootstrapStore;

    match bootstrap_type {
        BootstrapType::Rfc9224 => Ok(qtype_to_bootstrap_url(client, &store, query_type, |reg| {
            debug!("Fetching IANA registry {}", reg.url())
        })
        .await?),
        BootstrapType::Url(url) => Ok(url.to_owned()),
        BootstrapType::Hint(hint) => {
            fetch_bootstrap(&IanaRegistryType::RdapObjectTags, client, &store, |_reg| {
                debug!("Fetching IANA RDAP Object Tag Registry")
            })
            .await?;
            if let Ok(urls) = store.get_tag_urls(hint) {
                Ok(urls.preferred_url()?)
            } else {
                fetch_bootstrap(
                    &IanaRegistryType::RdapBootstrapDns,
                    client,
                    &store,
                    |_reg| debug!("Fetching IANA RDAP DNS Registry"),
                )
                .await?;
                if let Ok(urls) = store.get_dns_urls(hint) {
                    Ok(urls.preferred_url()?)
                } else {
                    fetch_bootstrap(
                        &IanaRegistryType::RdapBootstrapIpv4,
                        client,
                        &store,
                        |_reg| debug!("Fetching IANA RDAP IPv4 Registry"),
                    )
                    .await?;
                    if let Ok(urls) = store.get_ipv4_urls(hint) {
                        Ok(urls.preferred_url()?)
                    } else {
                        fetch_bootstrap(
                            &IanaRegistryType::RdapBootstrapIpv6,
                            client,
                            &store,
                            |_reg| debug!("Fetching IANA RDAP IPv6 Registry"),
                        )
                        .await?;
                        if let Ok(urls) = store.get_ipv6_urls(hint) {
                            Ok(urls.preferred_url()?)
                        } else {
                            fetch_bootstrap(
                                &IanaRegistryType::RdapBootstrapAsn,
                                client,
                                &store,
                                |_reg| debug!("Fetching IANA RDAP ASN Registry"),
                            )
                            .await?;
                            Ok(store.get_asn_urls(hint)?.preferred_url()?)
                        }
                    }
                }
            }
        }
    }
}
