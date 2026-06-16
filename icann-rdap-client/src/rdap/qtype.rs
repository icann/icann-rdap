//! Defines the various types of RDAP queries.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::LazyLock,
};

use icann_rdap_common::rdns::{ip_to_reverse_dns, reverse_dns_to_ipnet};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use {
    cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr},
    icann_rdap_common::{check::StringCheck, dns_types::DomainName, iana::IanaRegistryType},
    pct_str::{PctString, UriReserved},
    regex::Regex,
};

use strum::{Display as EnumDisplay, VariantArray};

use crate::RdapClientError;

/// Defines the various types of RDAP lookups and searches.
#[derive(EnumDisplay, Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub enum QueryType {
    /// Standard IPv4 address lookup.
    #[strum(serialize = "IpV4 Address Lookup")]
    IpV4Addr(Ipv4Addr),

    /// Standard IPv6 address lookup.
    #[strum(serialize = "IpV6 Address Lookup")]
    IpV6Addr(Ipv6Addr),

    /// IPv4 CIDR block lookup.
    #[strum(serialize = "IpV4 CIDR Lookup")]
    IpV4Cidr(Ipv4Cidr),

    /// IPv6 CIDR block lookup.
    #[strum(serialize = "IpV6 CIDR Lookup")]
    IpV6Cidr(Ipv6Cidr),

    /// RDAP-UP IPv4 address lookup.
    #[strum(serialize = "IpV4 Address Rdap-Up Lookup")]
    IpV4AddrUp(Ipv4Addr),

    /// RDAP-UP IPv6 address lookup.
    #[strum(serialize = "IpV6 Address Rdap-Up Lookup")]
    IpV6AddrUp(Ipv6Addr),

    /// RDAP-UP IPv4 CIDR block lookup.
    #[strum(serialize = "IpV4 CIDR Rdap-Up Lookup")]
    IpV4CidrUp(Ipv4Cidr),

    /// RDAP-UP IPv6 CIDR block lookup.
    #[strum(serialize = "IpV6 CIDR Rdap-Up Lookup")]
    IpV6CidrUp(Ipv6Cidr),

    /// RDAP-DOWN IPv4 address lookup.
    #[strum(serialize = "IpV4 Address Rdap-Down Lookup")]
    IpV4AddrDown(Ipv4Addr),

    /// RDAP-DOWN IPv6 address lookup.
    #[strum(serialize = "IpV6 Address Rdap-Down Lookup")]
    IpV6AddrDown(Ipv6Addr),

    /// RDAP-DOWN IPv4 CIDR block lookup.
    #[strum(serialize = "IpV4 CIDR Rdap-Down Lookup")]
    IpV4CidrDown(Ipv4Cidr),

    /// RDAP-DOWN IPv6 CIDR block lookup.
    #[strum(serialize = "IpV6 CIDR Rdap-Down Lookup")]
    IpV6CidrDown(Ipv6Cidr),

    /// RDAP-TOP IPv4 address lookup.
    #[strum(serialize = "IpV4 Address Rdap-Top Lookup")]
    IpV4AddrTop(Ipv4Addr),

    /// RDAP-TOP IPv6 address lookup.
    #[strum(serialize = "IpV6 Address Rdap-Top Lookup")]
    IpV6AddrTop(Ipv6Addr),

    /// RDAP-TOP IPv4 CIDR block lookup.
    #[strum(serialize = "IpV4 CIDR Rdap-Top Lookup")]
    IpV4CidrTop(Ipv4Cidr),

    /// RDAP-TOP IPv6 CIDR block lookup.
    #[strum(serialize = "IpV6 CIDR Rdap-Top Lookup")]
    IpV6CidrTop(Ipv6Cidr),

    /// RDAP-BOTTOM IPv4 address lookup.
    #[strum(serialize = "IpV4 Address Rdap-Bottom Search")]
    IpV4AddrBottom(Ipv4Addr),

    /// RDAP-BOTTOM IPv6 address lookup.
    #[strum(serialize = "IpV6 Address Rdap-Bottom Search")]
    IpV6AddrBottom(Ipv6Addr),

    /// RDAP-BOTTOM IPv4 CIDR block lookup.
    #[strum(serialize = "IpV4 CIDR Rdap-Bottom Search")]
    IpV4CidrBottom(Ipv4Cidr),

    /// RDAP-BOTTOM IPv6 CIDR block lookup.
    #[strum(serialize = "IpV6 Address Rdap-Bottom Search")]
    IpV6CidrBottom(Ipv6Cidr),

    /// Autonomous System Number lookup.
    #[strum(serialize = "Autonomous System Number Lookup")]
    AsNumber(u32),

    /// RDAP-UP ASN lookup.
    #[strum(serialize = "Autonomous System Number Rdap-Up Lookup")]
    AsNumberUp(u32),

    /// RDAP-DOWN ASN lookup.
    #[strum(serialize = "Autonomous System Number Rdap-Down Lookup")]
    AsNumberDown(u32),

    /// RDAP-TOP ASN lookup.
    #[strum(serialize = "Autonomous System Number Rdap-Top Search")]
    AsNumberTop(u32),

    /// RDAP-BOTTOM ASN lookup.
    #[strum(serialize = "Autonomous System Number Rdap-Bottom Search")]
    AsNumberBottom(u32),

    /// Domain name lookup.
    #[strum(serialize = "Domain Lookup")]
    Domain(DomainName),

    /// A-label (punycode/ACE) domain name lookup.
    #[strum(serialize = "A-Label Domain Lookup")]
    ALabel(DomainName),

    /// Reverse DNS IPv4 lookup.
    #[strum(serialize = "Reverse DNS IPv4 Lookup")]
    RdnsIpv4(Ipv4Net),

    /// Reverse DNS IPv6 lookup.
    #[strum(serialize = "Reverse DNS IPv6 Lookup")]
    RdnsIpv6(Ipv6Net),

    /// RDAP-UP reverse DNS IPv4 lookup.
    #[strum(serialize = "Reverse DNS IPv4 Rdap-Up Lookup")]
    RdnsIpv4Up(Ipv4Net),

    /// RDAP-UP reverse DNS IPv6 lookup.
    #[strum(serialize = "Reverse DNS IPv6 Rdap-Up Lookup")]
    RdnsIpv6Up(Ipv6Net),

    /// RDAP-DOWN reverse DNS IPv4 lookup.
    #[strum(serialize = "Reverse DNS IPv4 Rdap-Down Lookup")]
    RdnsIpv4Down(Ipv4Net),

    /// RDAP-DOWN reverse DNS IPv6 lookup.
    #[strum(serialize = "Reverse DNS IPv6 Rdap-Down Lookup")]
    RdnsIpv6Down(Ipv6Net),

    /// RDAP-TOP reverse DNS IPv4 lookup.
    #[strum(serialize = "Reverse DNS IPv4 Rdap-Top Lookup")]
    RdnsIpv4Top(Ipv4Net),

    /// RDAP-TOP reverse DNS IPv6 lookup.
    #[strum(serialize = "Reverse DNS IPv6 Rdap-Top Lookup")]
    RdnsIpv6Top(Ipv6Net),

    /// RDAP-BOTTOM reverse DNS IPv4 lookup.
    #[strum(serialize = "Reverse DNS IPv4 Rdap-Bottom Lookup")]
    RdnsIpv4Bottom(Ipv4Net),

    /// RDAP-BOTTOM reverse DNS IPv6 lookup.
    #[strum(serialize = "Reverse DNS IPv6 Rdap-Bottom Lookup")]
    RdnsIpv6Bottom(Ipv6Net),

    /// Entity lookup by handle.
    #[strum(serialize = "Entity Lookup")]
    Entity(String),

    /// Nameserver lookup by domain name.
    #[strum(serialize = "Nameserver Lookup")]
    Nameserver(DomainName),

    /// Search entities by name (RDAP `fn` parameter).
    #[strum(serialize = "Entity Name Search")]
    EntityNameSearch(String),

    /// Search entities by handle (RDAP `handle` parameter).
    #[strum(serialize = "Entity Handle Search")]
    EntityHandleSearch(String),

    /// Search network handles (RDAP `ips?handle` parameter).
    #[strum(serialize = "Network Handle Search")]
    NetworkHandleSearch(String),

    /// Search network names (RDAP `ips?name` parameter).
    #[strum(serialize = "Network Name Search")]
    NetworkNameSearch(String),

    /// Search domain names (RDAP `domains?name` parameter).
    #[strum(serialize = "Domain Name Search")]
    DomainNameSearch(String),

    /// Search domains by nameserver LDH name (RDAP `domains?nsLdhName` parameter).
    #[strum(serialize = "Domain Nameserver Name Search")]
    DomainNsNameSearch(String),

    /// Search domains by nameserver IP address (RDAP `domains?nsIp` parameter).
    #[strum(serialize = "Domain Nameserver IP Address Search")]
    DomainNsIpSearch(IpAddr),

    /// Search nameservers by name (RDAP `nameservers?name` parameter).
    #[strum(serialize = "Nameserver Name Search")]
    NameserverNameSearch(String),

    /// Search nameservers by IP address (RDAP `nameservers?ip` parameter).
    #[strum(serialize = "Nameserver IP Address Search")]
    NameserverIpSearch(IpAddr),

    /// Search autonomous system numbers by handle (RDAP `autnums?handle` parameter).
    #[strum(serialize = "Autnum Handle Search")]
    AutnumHandleSearch(String),

    /// Search autonomous system numbers by name (RDAP `autnums?name` parameter).
    #[strum(serialize = "Autnum Name Search")]
    AutnumNameSearch(String),

    /// Server help endpoint lookup.
    #[strum(serialize = "Server Help Lookup")]
    Help,

    /// Explicit URL passthrough. The string is used as-is without modification.
    #[strum(serialize = "Explicit URL")]
    Url(String),
}

/// Unit-only discriminants for [`QueryType`], enabling iteration over all
/// query type variants without needing to construct values with associated data.
#[derive(Debug, Clone, Copy, VariantArray)]
pub enum QueryTypeVariant {
    IpV4Addr,
    IpV6Addr,
    IpV4Cidr,
    IpV6Cidr,
    IpV4AddrUp,
    IpV6AddrUp,
    IpV4CidrUp,
    IpV6CidrUp,
    IpV4AddrDown,
    IpV6AddrDown,
    IpV4CidrDown,
    IpV6CidrDown,
    IpV4AddrTop,
    IpV6AddrTop,
    IpV4CidrTop,
    IpV6CidrTop,
    IpV4AddrBottom,
    IpV6AddrBottom,
    IpV4CidrBottom,
    IpV6CidrBottom,
    AsNumber,
    AsNumberUp,
    AsNumberDown,
    AsNumberTop,
    AsNumberBottom,
    Domain,
    ALabel,
    RdnsIpv4,
    RdnsIpv6,
    RdnsIpv4Up,
    RdnsIpv6Up,
    RdnsIpv4Down,
    RdnsIpv6Down,
    RdnsIpv4Top,
    RdnsIpv6Top,
    RdnsIpv4Bottom,
    RdnsIpv6Bottom,
    Entity,
    Nameserver,
    EntityNameSearch,
    EntityHandleSearch,
    NetworkHandleSearch,
    NetworkNameSearch,
    DomainNameSearch,
    DomainNsNameSearch,
    DomainNsIpSearch,
    NameserverNameSearch,
    NameserverIpSearch,
    AutnumHandleSearch,
    AutnumNameSearch,
    Help,
    Url,
}

impl QueryTypeVariant {
    /// Returns the [`IanaRegistryType`] this variant maps to for bootstrapping,
    /// or `None` if the variant does not use bootstrap lookups.
    pub fn bootstrap_registry(&self) -> Option<IanaRegistryType> {
        match self {
            Self::IpV4Addr
            | Self::IpV4Cidr
            | Self::IpV4AddrUp
            | Self::IpV4CidrUp
            | Self::IpV4AddrDown
            | Self::IpV4CidrDown
            | Self::IpV4AddrTop
            | Self::IpV4CidrTop
            | Self::IpV4AddrBottom
            | Self::IpV4CidrBottom
            | Self::RdnsIpv4
            | Self::RdnsIpv4Up
            | Self::RdnsIpv4Down
            | Self::RdnsIpv4Top
            | Self::RdnsIpv4Bottom => Some(IanaRegistryType::RdapBootstrapIpv4),
            Self::IpV6Addr
            | Self::IpV6Cidr
            | Self::IpV6AddrUp
            | Self::IpV6CidrUp
            | Self::IpV6AddrDown
            | Self::IpV6CidrDown
            | Self::IpV6AddrTop
            | Self::IpV6CidrTop
            | Self::IpV6AddrBottom
            | Self::IpV6CidrBottom
            | Self::RdnsIpv6
            | Self::RdnsIpv6Up
            | Self::RdnsIpv6Down
            | Self::RdnsIpv6Top
            | Self::RdnsIpv6Bottom => Some(IanaRegistryType::RdapBootstrapIpv6),
            Self::AsNumber
            | Self::AsNumberUp
            | Self::AsNumberDown
            | Self::AsNumberTop
            | Self::AsNumberBottom => Some(IanaRegistryType::RdapBootstrapAsn),
            Self::Domain | Self::ALabel | Self::Nameserver => {
                Some(IanaRegistryType::RdapBootstrapDns)
            }
            Self::Entity => Some(IanaRegistryType::RdapObjectTags),
            _ => None,
        }
    }

    /// Constructs a concrete [`QueryType`] value suitable for passing to
    /// [`crate::iana::bootstrap::qtype_to_bootstrap_url`].
    pub fn to_query_type(&self) -> QueryType {
        match self {
            Self::IpV4Addr => QueryType::ipv4("192.0.2.1").unwrap(),
            Self::IpV6Addr => QueryType::ipv6("2001:db8::1").unwrap(),
            Self::IpV4Cidr => QueryType::ipv4cidr("192.0.2.0/24").unwrap(),
            Self::IpV6Cidr => QueryType::ipv6cidr("2001:db8::/32").unwrap(),
            Self::IpV4AddrUp => QueryType::ipv4_up("192.0.2.1").unwrap(),
            Self::IpV6AddrUp => QueryType::ipv6_up("2001:db8::1").unwrap(),
            Self::IpV4CidrUp => QueryType::ipv4cidr_up("192.0.2.0/24").unwrap(),
            Self::IpV6CidrUp => QueryType::ipv6cidr_up("2001:db8::/32").unwrap(),
            Self::IpV4AddrDown => QueryType::ipv4_down("192.0.2.1").unwrap(),
            Self::IpV6AddrDown => QueryType::ipv6_down("2001:db8::1").unwrap(),
            Self::IpV4CidrDown => QueryType::ipv4cidr_down("192.0.2.0/24").unwrap(),
            Self::IpV6CidrDown => QueryType::ipv6cidr_down("2001:db8::/32").unwrap(),
            Self::IpV4AddrTop => QueryType::ipv4_top("192.0.2.1").unwrap(),
            Self::IpV6AddrTop => QueryType::ipv6_top("2001:db8::1").unwrap(),
            Self::IpV4CidrTop => QueryType::ipv4cidr_top("192.0.2.0/24").unwrap(),
            Self::IpV6CidrTop => QueryType::ipv6cidr_top("2001:db8::/32").unwrap(),
            Self::IpV4AddrBottom => QueryType::ipv4_bottom("192.0.2.1").unwrap(),
            Self::IpV6AddrBottom => QueryType::ipv6_bottom("2001:db8::1").unwrap(),
            Self::IpV4CidrBottom => QueryType::ipv4cidr_bottom("192.0.2.0/24").unwrap(),
            Self::IpV6CidrBottom => QueryType::ipv6cidr_bottom("2001:db8::/32").unwrap(),
            Self::AsNumber => QueryType::autnum("as64512").unwrap(),
            Self::AsNumberUp => QueryType::autnum_up("as64512").unwrap(),
            Self::AsNumberDown => QueryType::autnum_down("as64512").unwrap(),
            Self::AsNumberTop => QueryType::autnum_top("as64512").unwrap(),
            Self::AsNumberBottom => QueryType::autnum_bottom("as64512").unwrap(),
            Self::Domain => QueryType::domain("example.org").unwrap(),
            Self::ALabel => QueryType::alabel("xn--fsq.org").unwrap(),
            Self::RdnsIpv4 => QueryType::rdns_ipv4("2.0.0.192.in-addr.arpa").unwrap(),
            Self::RdnsIpv6 => QueryType::rdns_ipv6(
                "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            )
            .unwrap(),
            Self::RdnsIpv4Up => QueryType::rdns_ipv4_up("2.0.0.192.in-addr.arpa").unwrap(),
            Self::RdnsIpv6Up => QueryType::rdns_ipv6_up(
                "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            )
            .unwrap(),
            Self::RdnsIpv4Down => QueryType::rdns_ipv4_down("2.0.0.192.in-addr.arpa").unwrap(),
            Self::RdnsIpv6Down => QueryType::rdns_ipv6_down(
                "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            )
            .unwrap(),
            Self::RdnsIpv4Top => QueryType::rdns_ipv4_top("2.0.0.192.in-addr.arpa").unwrap(),
            Self::RdnsIpv6Top => QueryType::rdns_ipv6_top(
                "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            )
            .unwrap(),
            Self::RdnsIpv4Bottom => QueryType::rdns_ipv4_bottom("2.0.0.192.in-addr.arpa").unwrap(),
            Self::RdnsIpv6Bottom => QueryType::rdns_ipv6_bottom(
                "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            )
            .unwrap(),
            Self::Entity => QueryType::Entity("X".to_string()),
            Self::Nameserver => QueryType::ns("ns.example.org").unwrap(),
            Self::EntityNameSearch => QueryType::EntityNameSearch("test".to_string()),
            Self::EntityHandleSearch => QueryType::EntityHandleSearch("X".to_string()),
            Self::NetworkHandleSearch => QueryType::NetworkHandleSearch("test".to_string()),
            Self::NetworkNameSearch => QueryType::NetworkNameSearch("test".to_string()),
            Self::DomainNameSearch => QueryType::DomainNameSearch("example".to_string()),
            Self::DomainNsNameSearch => QueryType::DomainNsNameSearch("ns".to_string()),
            Self::DomainNsIpSearch => {
                QueryType::DomainNsIpSearch(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            }
            Self::NameserverNameSearch => QueryType::NameserverNameSearch("ns".to_string()),
            Self::NameserverIpSearch => {
                QueryType::NameserverIpSearch(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
            }
            Self::AutnumHandleSearch => QueryType::AutnumHandleSearch("AS64512".to_string()),
            Self::AutnumNameSearch => QueryType::AutnumNameSearch("test".to_string()),
            Self::Help => QueryType::Help,
            Self::Url => QueryType::Url("https://example.com".to_string()),
        }
    }
}

impl QueryType {
    pub fn query_url(&self, base_url: &str) -> Result<String, RdapClientError> {
        let base_url = base_url.trim_end_matches('/');
        match self {
            Self::IpV4Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV6Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV4Cidr(value) => Ok(format!(
                "{base_url}/ip/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV6Cidr(value) => Ok(format!(
                "{base_url}/ip/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV4AddrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV6AddrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV4CidrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV6CidrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV4AddrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV6AddrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV4CidrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV6CidrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV4AddrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV6AddrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV4CidrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV6CidrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV4AddrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV6AddrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::IpV4CidrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::IpV6CidrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), UriReserved::Path),
                PctString::encode(
                    value.network_length().to_string().chars(),
                    UriReserved::Path
                )
            )),
            Self::AsNumber(value) => Ok(format!(
                "{base_url}/autnum/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::AsNumberUp(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-up/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::AsNumberDown(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-down/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::AsNumberTop(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-top/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::AsNumberBottom(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-bottom/{}",
                PctString::encode(value.to_string().chars(), UriReserved::Path)
            )),
            Self::Domain(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.trim_leading_dot().chars(), UriReserved::Path)
            )),
            Self::RdnsIpv4(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V4(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv6(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V6(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv4Up(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-up/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V4(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv6Up(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-up/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V6(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv4Down(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-down/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V4(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv6Down(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-down/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V6(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv4Top(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-top/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V4(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv6Top(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-top/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V6(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv4Bottom(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-bottom/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V4(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::RdnsIpv6Bottom(value) => Ok(format!(
                "{base_url}/domains/rirSearch1/rdap-bottom/{}",
                PctString::encode(
                    ip_to_reverse_dns(&IpAddr::V6(value.network())).chars(),
                    UriReserved::Path
                )
            )),
            Self::ALabel(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.to_ascii().chars(), UriReserved::Path),
            )),
            Self::Entity(value) => Ok(format!(
                "{base_url}/entity/{}",
                PctString::encode(value.chars(), UriReserved::Path)
            )),
            Self::Nameserver(value) => Ok(format!(
                "{base_url}/nameserver/{}",
                PctString::encode(value.to_ascii().chars(), UriReserved::Path)
            )),
            Self::EntityNameSearch(value) => search_query(value, "entities?fn", base_url),
            Self::EntityHandleSearch(value) => search_query(value, "entities?handle", base_url),
            Self::NetworkHandleSearch(value) => search_query(value, "ips?handle", base_url),
            Self::NetworkNameSearch(value) => search_query(value, "ips?name", base_url),
            Self::DomainNameSearch(value) => search_query(value, "domains?name", base_url),
            Self::DomainNsNameSearch(value) => search_query(value, "domains?nsLdhName", base_url),
            Self::DomainNsIpSearch(value) => {
                search_query(&value.to_string(), "domains?nsIp", base_url)
            }
            Self::NameserverNameSearch(value) => search_query(value, "nameservers?name", base_url),
            Self::NameserverIpSearch(value) => {
                search_query(&value.to_string(), "nameservers?ip", base_url)
            }
            Self::AutnumHandleSearch(value) => search_query(value, "autnums?handle", base_url),
            Self::AutnumNameSearch(value) => search_query(value, "autnums?name", base_url),
            Self::Help => Ok(format!("{base_url}/help")),
            Self::Url(url) => Ok(url.to_owned()),
        }
    }

    pub fn domain(domain_name: &str) -> Result<Self, RdapClientError> {
        Ok(Self::Domain(DomainName::from_str(domain_name)?))
    }

    pub fn alabel(alabel: &str) -> Result<Self, RdapClientError> {
        Ok(Self::ALabel(DomainName::from_str(alabel)?))
    }

    pub fn rdns_ipv4(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V4(v4) => Ok(Self::RdnsIpv4(v4)),
            IpNet::V6(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv6(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V6(v6) => Ok(Self::RdnsIpv6(v6)),
            IpNet::V4(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv4_up(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V4(v4) => Ok(Self::RdnsIpv4Up(v4)),
            IpNet::V6(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv6_up(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V6(v6) => Ok(Self::RdnsIpv6Up(v6)),
            IpNet::V4(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv4_down(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V4(v4) => Ok(Self::RdnsIpv4Down(v4)),
            IpNet::V6(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv6_down(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V6(v6) => Ok(Self::RdnsIpv6Down(v6)),
            IpNet::V4(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv4_top(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V4(v4) => Ok(Self::RdnsIpv4Top(v4)),
            IpNet::V6(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv6_top(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V6(v6) => Ok(Self::RdnsIpv6Top(v6)),
            IpNet::V4(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv4_bottom(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V4(v4) => Ok(Self::RdnsIpv4Bottom(v4)),
            IpNet::V6(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipv6_bottom(domain_name: &str) -> Result<Self, RdapClientError> {
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        match ipnet {
            IpNet::V6(v6) => Ok(Self::RdnsIpv6Bottom(v6)),
            IpNet::V4(_) => Err(RdapClientError::InvalidQueryValue),
        }
    }

    pub fn rdns_ipstr(ip_address: &str) -> Result<Self, RdapClientError> {
        if let Ok(ip_cidr) = parse_cidr(ip_address) {
            return Ok(match ip_cidr {
                IpCidr::V4(cidr) => {
                    let first = cidr.first_address();
                    let prefix = cidr.network_length();
                    Self::RdnsIpv4(
                        Ipv4Net::new(first, prefix)
                            .map_err(|_e| RdapClientError::InvalidQueryValue)?,
                    )
                }
                IpCidr::V6(cidr) => {
                    let first = cidr.first_address();
                    let prefix = cidr.network_length();
                    Self::RdnsIpv6(
                        Ipv6Net::new(first, prefix)
                            .map_err(|_e| RdapClientError::InvalidQueryValue)?,
                    )
                }
            });
        }
        let ip_addr =
            IpAddr::from_str(ip_address).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        let ipnet = match ip_addr {
            IpAddr::V4(ipv4) => {
                IpNet::V4(Ipv4Net::new(ipv4, 32).map_err(|_e| RdapClientError::InvalidQueryValue)?)
            }
            IpAddr::V6(ipv6) => {
                IpNet::V6(Ipv6Net::new(ipv6, 128).map_err(|_e| RdapClientError::InvalidQueryValue)?)
            }
        };
        Ok(match ipnet {
            IpNet::V4(v4) => Self::RdnsIpv4(v4),
            IpNet::V6(v6) => Self::RdnsIpv6(v6),
        })
    }

    pub fn ns(nameserver: &str) -> Result<Self, RdapClientError> {
        Ok(Self::Nameserver(DomainName::from_str(nameserver)?))
    }

    pub fn autnum(autnum: &str) -> Result<Self, RdapClientError> {
        let value = parse_autnum(autnum)?;
        Ok(Self::AsNumber(value))
    }

    pub fn autnum_up(autnum: &str) -> Result<Self, RdapClientError> {
        let value = parse_autnum(autnum)?;
        Ok(Self::AsNumberUp(value))
    }

    pub fn autnum_down(autnum: &str) -> Result<Self, RdapClientError> {
        let value = parse_autnum(autnum)?;
        Ok(Self::AsNumberDown(value))
    }

    pub fn autnum_top(autnum: &str) -> Result<Self, RdapClientError> {
        let value = parse_autnum(autnum)?;
        Ok(Self::AsNumberTop(value))
    }

    pub fn autnum_bottom(autnum: &str) -> Result<Self, RdapClientError> {
        let value = parse_autnum(autnum)?;
        Ok(Self::AsNumberBottom(value))
    }

    pub fn ipv4(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv4Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV4Addr(value))
    }

    pub fn ipv6(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv6Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV6Addr(value))
    }

    pub fn ipv4cidr(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V4(v4) = value {
            Ok(Self::IpV4Cidr(v4))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv6cidr(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V6(v6) = value {
            Ok(Self::IpV6Cidr(v6))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv4_up(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv4Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV4AddrUp(value))
    }

    pub fn ipv6_up(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv6Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV6AddrUp(value))
    }

    pub fn ipv4cidr_up(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V4(v4) = value {
            Ok(Self::IpV4CidrUp(v4))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv6cidr_up(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V6(v6) = value {
            Ok(Self::IpV6CidrUp(v6))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv4_down(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv4Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV4AddrDown(value))
    }

    pub fn ipv6_down(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv6Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV6AddrDown(value))
    }

    pub fn ipv4cidr_down(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V4(v4) = value {
            Ok(Self::IpV4CidrDown(v4))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv6cidr_down(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V6(v6) = value {
            Ok(Self::IpV6CidrDown(v6))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv4_top(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv4Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV4AddrTop(value))
    }

    pub fn ipv6_top(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv6Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV6AddrTop(value))
    }

    pub fn ipv4cidr_top(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V4(v4) = value {
            Ok(Self::IpV4CidrTop(v4))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv6cidr_top(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V6(v6) = value {
            Ok(Self::IpV6CidrTop(v6))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv4_bottom(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv4Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV4AddrBottom(value))
    }

    pub fn ipv6_bottom(ip: &str) -> Result<Self, RdapClientError> {
        let value = Ipv6Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::IpV6AddrBottom(value))
    }

    pub fn ipv4cidr_bottom(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V4(v4) = value {
            Ok(Self::IpV4CidrBottom(v4))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn ipv6cidr_bottom(cidr: &str) -> Result<Self, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V6(v6) = value {
            Ok(Self::IpV6CidrBottom(v6))
        } else {
            Err(RdapClientError::AmbiguousQueryType)
        }
    }

    pub fn domain_ns_ip_search(ip: &str) -> Result<Self, RdapClientError> {
        let value = IpAddr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::DomainNsIpSearch(value))
    }

    pub fn ns_ip_search(ip: &str) -> Result<Self, RdapClientError> {
        let value = IpAddr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::NameserverIpSearch(value))
    }
}

fn search_query(value: &str, path_query: &str, base_url: &str) -> Result<String, RdapClientError> {
    Ok(format!(
        "{base_url}/{path_query}={}",
        PctString::encode(value.chars(), UriReserved::Any)
    ))
}

impl FromStr for QueryType {
    type Err = RdapClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // if it looks like a HTTP(S) url
        if s.starts_with("http://") || s.starts_with("https://") {
            return Ok(Self::Url(s.to_owned()));
        }

        // if it is an rdap-up query
        if let Some(rest) = s.strip_prefix("up:") {
            if let Ok(ip_addr) = IpAddr::from_str(rest) {
                if ip_addr.is_ipv4() {
                    return Self::ipv4_up(rest);
                } else {
                    return Self::ipv6_up(rest);
                }
            }
            if let Ok(ip_cidr) = parse_cidr(rest) {
                return Ok(match ip_cidr {
                    IpCidr::V4(cidr) => Self::IpV4CidrUp(cidr),
                    IpCidr::V6(cidr) => Self::IpV6CidrUp(cidr),
                });
            }
            if let Ok(asn) = parse_autnum(rest) {
                return Ok(Self::AsNumberUp(asn));
            }
            if let Some(ipnet) = reverse_dns_to_ipnet(rest) {
                return Ok(match ipnet {
                    IpNet::V4(v4) => Self::RdnsIpv4Up(v4),
                    IpNet::V6(v6) => Self::RdnsIpv6Up(v6),
                });
            }
            return Err(RdapClientError::InvalidQueryValue);
        }

        // if it is an rdap-down query
        if let Some(rest) = s.strip_prefix("down:") {
            if let Ok(ip_addr) = IpAddr::from_str(rest) {
                if ip_addr.is_ipv4() {
                    return Self::ipv4_down(rest);
                } else {
                    return Self::ipv6_down(rest);
                }
            }
            if let Ok(ip_cidr) = parse_cidr(rest) {
                return Ok(match ip_cidr {
                    IpCidr::V4(cidr) => Self::IpV4CidrDown(cidr),
                    IpCidr::V6(cidr) => Self::IpV6CidrDown(cidr),
                });
            }
            if let Ok(asn) = parse_autnum(rest) {
                return Ok(Self::AsNumberDown(asn));
            }
            if let Some(ipnet) = reverse_dns_to_ipnet(rest) {
                return Ok(match ipnet {
                    IpNet::V4(v4) => Self::RdnsIpv4Down(v4),
                    IpNet::V6(v6) => Self::RdnsIpv6Down(v6),
                });
            }
            return Err(RdapClientError::InvalidQueryValue);
        }

        // if it is an rdap-top query
        if let Some(rest) = s.strip_prefix("top:") {
            if let Ok(ip_addr) = IpAddr::from_str(rest) {
                if ip_addr.is_ipv4() {
                    return Self::ipv4_top(rest);
                } else {
                    return Self::ipv6_top(rest);
                }
            }
            if let Ok(ip_cidr) = parse_cidr(rest) {
                return Ok(match ip_cidr {
                    IpCidr::V4(cidr) => Self::IpV4CidrTop(cidr),
                    IpCidr::V6(cidr) => Self::IpV6CidrTop(cidr),
                });
            }
            if let Ok(asn) = parse_autnum(rest) {
                return Ok(Self::AsNumberTop(asn));
            }
            if let Some(ipnet) = reverse_dns_to_ipnet(rest) {
                return Ok(match ipnet {
                    IpNet::V4(v4) => Self::RdnsIpv4Top(v4),
                    IpNet::V6(v6) => Self::RdnsIpv6Top(v6),
                });
            }
            return Err(RdapClientError::InvalidQueryValue);
        }

        // if it is an rdap-bottom query
        if let Some(rest) = s.strip_prefix("bottom:") {
            if let Ok(ip_addr) = IpAddr::from_str(rest) {
                if ip_addr.is_ipv4() {
                    return Self::ipv4_bottom(rest);
                } else {
                    return Self::ipv6_bottom(rest);
                }
            }
            if let Ok(ip_cidr) = parse_cidr(rest) {
                return Ok(match ip_cidr {
                    IpCidr::V4(cidr) => Self::IpV4CidrBottom(cidr),
                    IpCidr::V6(cidr) => Self::IpV6CidrBottom(cidr),
                });
            }
            if let Ok(asn) = parse_autnum(rest) {
                return Ok(Self::AsNumberBottom(asn));
            }
            if let Some(ipnet) = reverse_dns_to_ipnet(rest) {
                return Ok(match ipnet {
                    IpNet::V4(v4) => Self::RdnsIpv4Bottom(v4),
                    IpNet::V6(v6) => Self::RdnsIpv6Bottom(v6),
                });
            }
            return Err(RdapClientError::InvalidQueryValue);
        }

        // if looks like an autnum
        if parse_autnum(s).is_ok() {
            return Self::autnum(s);
        }

        // If it's an IP address
        if let Ok(ip_addr) = IpAddr::from_str(s) {
            if ip_addr.is_ipv4() {
                return Self::ipv4(s);
            } else {
                return Self::ipv6(s);
            }
        }

        // if it is a cidr
        if let Ok(ip_cidr) = parse_cidr(s) {
            return Ok(match ip_cidr {
                IpCidr::V4(cidr) => Self::IpV4Cidr(cidr),
                IpCidr::V6(cidr) => Self::IpV6Cidr(cidr),
            });
        }

        // if it looks like a domain name
        if is_domain_name(s) {
            return if is_nameserver(s) {
                Self::ns(s)
            } else if let Some(ipnet) = reverse_dns_to_ipnet(s) {
                Ok(match ipnet {
                    IpNet::V4(v4) => Self::RdnsIpv4(v4),
                    IpNet::V6(v6) => Self::RdnsIpv6(v6),
                })
            } else {
                Self::domain(s)
            };
        }

        // if it is just one word
        if !s.contains(|c: char| c.is_whitespace() || matches!(c, '.' | ',' | '"')) {
            return Ok(Self::Entity(s.to_owned()));
        }

        // The query type cannot be determined.
        Err(RdapClientError::AmbiguousQueryType)
    }
}

fn parse_autnum(s: &str) -> Result<u32, RdapClientError> {
    let autnum = s.trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') });
    autnum
        .parse::<u32>()
        .map_err(|_e| RdapClientError::InvalidQueryValue)
}

fn parse_cidr(s: &str) -> Result<IpCidr, RdapClientError> {
    let Some((prefix, suffix)) = s.split_once('/') else {
        return Err(RdapClientError::InvalidQueryValue);
    };
    if prefix.chars().all(|c: char| c.is_ascii_alphanumeric()) {
        let cidr = cidr::parsers::parse_short_ip_address_as_cidr(prefix)
            .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        IpCidr::new(
            cidr.first_address(),
            suffix
                .parse::<u8>()
                .map_err(|_e| RdapClientError::InvalidQueryValue)?,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)
    } else {
        cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(s, cidr::parsers::parse_loose_ip)
            .map_err(|_e| RdapClientError::InvalidQueryValue)
    }
}

fn is_ldh_domain(text: &str) -> bool {
    static LDH_DOMAIN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(?i)(\.?[a-zA-Z0-9-]+)*\.[a-zA-Z0-9-]+\.?$").unwrap());
    LDH_DOMAIN_RE.is_match(text)
}

fn is_domain_name(text: &str) -> bool {
    text.contains('.') && text.is_unicode_domain_name()
}

fn is_nameserver(text: &str) -> bool {
    static NS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?i)(ns)[a-zA-Z0-9-]*\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.?$").unwrap()
    });
    NS_RE.is_match(text)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;

    use super::*;

    #[test]
    fn test_ipv4_query_type_from_str() {
        // GIVEN
        let s = "129.129.1.1";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV4Addr(_)))
    }

    #[test]
    fn test_ipv6_query_type_from_str() {
        // GIVEN
        let s = "2001::1";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV6Addr(_)))
    }

    #[test]
    fn test_ipv4_cidr_query_type_from_str() {
        // GIVEN
        let s = "129.129.1.1/8";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV4Cidr(_)))
    }

    #[test]
    fn test_ipv6_cidr_query_type_from_str() {
        // GIVEN
        let s = "2001::1/20";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV6Cidr(_)))
    }

    #[test]
    fn test_number_query_type_from_str() {
        // GIVEN
        let s = "16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumber(_)))
    }

    #[test]
    fn test_as_followed_by_number_query_type_from_str() {
        // GIVEN
        let s = "as16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumber(_)))
    }

    #[rstest]
    #[case("example.com")]
    #[case("foo.example.com")]
    #[case("snark.fail")]
    #[case("ns.fail")]
    #[case(".com")]
    fn test_domain_name_query_type_from_str(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Domain(_)))
    }

    #[rstest]
    #[case("ns.example.com")]
    #[case("ns1.example.com")]
    #[case("NS1.example.com")]
    fn test_name_server_query_type_from_str(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Nameserver(_)))
    }

    #[test]
    fn test_single_word_query_type_from_str() {
        // GIVEN
        let s = "foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        let q = q.unwrap();
        assert!(matches!(q, QueryType::Entity(_)))
    }

    #[rstest]
    #[case("https://example.com")]
    #[case("http://foo.example.com")]
    fn test_url_query_type_from_str(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Url(_)))
    }

    #[rstest]
    #[case("ns.foo_bar.com")]
    #[case("ns.foo bar.com")]
    fn test_bad_input_query_type_from_str(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(q.is_err());
    }

    #[rstest]
    #[case("10.0.0.0/8", "10.0.0.0/8")]
    #[case("10.0.0/8", "10.0.0.0/8")]
    #[case("10.0/8", "10.0.0.0/8")]
    #[case("10/8", "10.0.0.0/8")]
    #[case("10.0.0.0/24", "10.0.0.0/24")]
    #[case("10.0.0/24", "10.0.0.0/24")]
    #[case("10.0/24", "10.0.0.0/24")]
    #[case("10/24", "10.0.0.0/24")]
    #[case("129.129.1.1/8", "129.0.0.0/8")]
    #[case("2001::1/32", "2001::/32")]
    fn test_cidr_parse_cidr(#[case] actual: &str, #[case] expected: &str) {
        // GIVEN case input

        // WHEN
        let q = parse_cidr(actual);

        // THEN
        assert_eq!(q.unwrap().to_string(), expected)
    }

    #[test]
    fn test_ipv4addr_query_url() {
        // GIVEN ipv4 addr query
        let q = QueryType::from_str("199.1.1.1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/ip/199.1.1.1")
    }

    #[test]
    fn test_ipv6addr_query_url() {
        // GIVEN
        let q = QueryType::from_str("2000::1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/ip/2000%3A%3A1")
    }

    #[test]
    fn test_ipv4cidr_query_url() {
        // GIVEN
        let q = QueryType::from_str("199.1.1.1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/ip/199.1.0.0/16")
    }

    #[test]
    fn test_ipv6cidr_query_url() {
        // GIVEN
        let q = QueryType::from_str("2000::1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/ip/2000%3A%3A/16")
    }

    #[test]
    fn test_autnum_query_url() {
        // GIVEN
        let q = QueryType::from_str("as16509").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/autnum/16509")
    }

    #[test]
    fn test_domain_query_url() {
        // GIVEN
        let q = QueryType::from_str("example.com").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/domain/example.com")
    }

    #[test]
    fn test_ns_query_url() {
        // GIVEN
        let q = QueryType::from_str("ns.example.com").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/nameserver/ns.example.com")
    }

    #[test]
    fn test_entity_query_url() {
        // GIVEN
        let q = QueryType::from_str("foo").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/entity/foo")
    }

    #[test]
    fn test_entity_name_search_query_url() {
        // GIVEN
        let q = QueryType::EntityNameSearch("foo".to_string());

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/entities?fn=foo")
    }

    #[test]
    fn test_entity_handle_search_query_url() {
        // GIVEN
        let q = QueryType::EntityHandleSearch("foo".to_string());

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/entities?handle=foo")
    }

    #[test]
    fn test_network_handle_search_query_url() {
        // GIVEN
        let q = QueryType::NetworkHandleSearch("foo".to_string());

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/ips?handle=foo")
    }

    #[test]
    fn test_domain_name_search_query_url() {
        // GIVEN
        let q = QueryType::DomainNameSearch("foo".to_string());

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/domains?name=foo")
    }

    #[test]
    fn test_domain_ns_name_search_query_url() {
        // GIVEN
        let q = QueryType::DomainNsNameSearch("foo".to_string());

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/domains?nsLdhName=foo")
    }

    #[test]
    fn test_domain_ns_ip_search_query_url() {
        // GIVEN
        let q = QueryType::DomainNsIpSearch(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/domains?nsIp=1.1.1.1")
    }

    #[test]
    fn test_ns_name_search_query_url() {
        // GIVEN
        let q = QueryType::NameserverNameSearch("foo".to_string());

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/nameservers?name=foo")
    }

    #[test]
    fn test_ns_ip_search_query_url() {
        // GIVEN
        let q = QueryType::NameserverIpSearch(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(actual, "https://example.com/nameservers?ip=1.1.1.1")
    }

    #[test]
    fn test_ipv4addr_up_query_url() {
        // GIVEN
        let q = QueryType::from_str("up:199.1.1.1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-up/199.1.1.1"
        )
    }

    #[test]
    fn test_ipv6addr_up_query_url() {
        // GIVEN
        let q = QueryType::from_str("up:2000::1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-up/2000%3A%3A1"
        )
    }

    #[test]
    fn test_ipv4cidr_up_query_url() {
        // GIVEN
        let q = QueryType::from_str("up:199.1.1.1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-up/199.1.0.0/16"
        )
    }

    #[test]
    fn test_ipv6cidr_up_query_url() {
        // GIVEN
        let q = QueryType::from_str("up:2000::1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-up/2000%3A%3A/16"
        )
    }

    #[test]
    fn test_up_prefix_invalid_input() {
        // GIVEN
        let s = "up:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_ipv4addr_down_query_url() {
        // GIVEN
        let q = QueryType::from_str("down:199.1.1.1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-down/199.1.1.1"
        )
    }

    #[test]
    fn test_ipv6addr_down_query_url() {
        // GIVEN
        let q = QueryType::from_str("down:2000::1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-down/2000%3A%3A1"
        )
    }

    #[test]
    fn test_ipv4cidr_down_query_url() {
        // GIVEN
        let q = QueryType::from_str("down:199.1.1.1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-down/199.1.0.0/16"
        )
    }

    #[test]
    fn test_ipv6cidr_down_query_url() {
        // GIVEN
        let q = QueryType::from_str("down:2000::1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-down/2000%3A%3A/16"
        )
    }

    #[test]
    fn test_down_prefix_invalid_input() {
        // GIVEN
        let s = "down:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_ipv4addr_top_query_url() {
        // GIVEN
        let q = QueryType::from_str("top:199.1.1.1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-top/199.1.1.1"
        )
    }

    #[test]
    fn test_ipv6addr_top_query_url() {
        // GIVEN
        let q = QueryType::from_str("top:2000::1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-top/2000%3A%3A1"
        )
    }

    #[test]
    fn test_ipv4cidr_top_query_url() {
        // GIVEN
        let q = QueryType::from_str("top:199.1.1.1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-top/199.1.0.0/16"
        )
    }

    #[test]
    fn test_ipv6cidr_top_query_url() {
        // GIVEN
        let q = QueryType::from_str("top:2000::1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-top/2000%3A%3A/16"
        )
    }

    #[test]
    fn test_top_prefix_invalid_input() {
        // GIVEN
        let s = "top:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_ipv4addr_bottom_query_url() {
        // GIVEN
        let q = QueryType::from_str("bottom:199.1.1.1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-bottom/199.1.1.1"
        )
    }

    #[test]
    fn test_ipv6addr_bottom_query_url() {
        // GIVEN
        let q = QueryType::from_str("bottom:2000::1").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-bottom/2000%3A%3A1"
        )
    }

    #[test]
    fn test_ipv4cidr_bottom_query_url() {
        // GIVEN
        let q = QueryType::from_str("bottom:199.1.1.1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-bottom/199.1.0.0/16"
        )
    }

    #[test]
    fn test_ipv6cidr_bottom_query_url() {
        // GIVEN
        let q = QueryType::from_str("bottom:2000::1/16").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/ips/rirSearch1/rdap-bottom/2000%3A%3A/16"
        )
    }

    #[test]
    fn test_bottom_prefix_invalid_input() {
        // GIVEN
        let s = "bottom:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_autnum_up_query_url() {
        // GIVEN
        let q = QueryType::from_str("up:AS16509").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/autnums/rirSearch1/rdap-up/16509"
        )
    }

    #[test]
    fn test_autnum_down_query_url() {
        // GIVEN
        let q = QueryType::from_str("down:AS16509").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/autnums/rirSearch1/rdap-down/16509"
        )
    }

    #[test]
    fn test_autnum_top_query_url() {
        // GIVEN
        let q = QueryType::from_str("top:16509").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/autnums/rirSearch1/rdap-top/16509"
        )
    }

    #[test]
    fn test_autnum_bottom_query_url() {
        // GIVEN
        let q = QueryType::from_str("bottom:as16509").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/autnums/rirSearch1/rdap-bottom/16509"
        )
    }

    #[test]
    fn test_autnum_up_from_str() {
        // GIVEN
        let s = "up:16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumberUp(16509)))
    }

    #[test]
    fn test_autnum_down_from_str() {
        // GIVEN
        let s = "down:16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumberDown(16509)))
    }

    #[test]
    fn test_autnum_top_from_str() {
        // GIVEN
        let s = "top:16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumberTop(16509)))
    }

    #[test]
    fn test_autnum_bottom_from_str() {
        // GIVEN
        let s = "bottom:16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumberBottom(16509)))
    }

    #[test]
    fn test_autnum_up_prefix_invalid_input() {
        // GIVEN
        let s = "up:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_autnum_down_prefix_invalid_input() {
        // GIVEN
        let s = "down:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_autnum_top_prefix_invalid_input() {
        // GIVEN
        let s = "top:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_autnum_bottom_prefix_invalid_input() {
        // GIVEN
        let s = "bottom:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv4_up_query_url() {
        // GIVEN
        let q = QueryType::from_str("up:2.0.192.in-addr.arpa").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-up/0.2.0.192.in-addr.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv6_up_query_url() {
        // GIVEN
        let q = QueryType::from_str(
            "up:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        )
        .expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-up/b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv4_down_query_url() {
        // GIVEN
        let q = QueryType::from_str("down:2.0.192.in-addr.arpa").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-down/0.2.0.192.in-addr.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv6_down_query_url() {
        // GIVEN
        let q = QueryType::from_str(
            "down:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        )
        .expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-down/b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv4_top_query_url() {
        // GIVEN
        let q = QueryType::from_str("top:2.0.192.in-addr.arpa").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-top/0.2.0.192.in-addr.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv6_top_query_url() {
        // GIVEN
        let q = QueryType::from_str(
            "top:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        )
        .expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-top/b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv4_bottom_query_url() {
        // GIVEN
        let q = QueryType::from_str("bottom:2.0.192.in-addr.arpa").expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-bottom/0.2.0.192.in-addr.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv6_bottom_query_url() {
        // GIVEN
        let q = QueryType::from_str(
            "bottom:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        )
        .expect("query type");

        // WHEN
        let actual = q.query_url("https://example.com").expect("query url");

        // THEN
        assert_eq!(
            actual,
            "https://example.com/domains/rirSearch1/rdap-bottom/b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        )
    }

    #[test]
    fn test_rdns_ipv4_up_from_str() {
        // GIVEN
        let s = "up:2.0.192.in-addr.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv4Up(_)))
    }

    #[test]
    fn test_rdns_ipv6_up_from_str() {
        // GIVEN
        let s = "up:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv6Up(_)))
    }

    #[test]
    fn test_rdns_ipv4_down_from_str() {
        // GIVEN
        let s = "down:2.0.192.in-addr.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv4Down(_)))
    }

    #[test]
    fn test_rdns_ipv6_down_from_str() {
        // GIVEN
        let s = "down:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv6Down(_)))
    }

    #[test]
    fn test_rdns_ipv4_top_from_str() {
        // GIVEN
        let s = "top:2.0.192.in-addr.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv4Top(_)))
    }

    #[test]
    fn test_rdns_ipv6_top_from_str() {
        // GIVEN
        let s = "top:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv6Top(_)))
    }

    #[test]
    fn test_rdns_ipv4_bottom_from_str() {
        // GIVEN
        let s = "bottom:2.0.192.in-addr.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv4Bottom(_)))
    }

    #[test]
    fn test_rdns_ipv6_bottom_from_str() {
        // GIVEN
        let s = "bottom:b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::RdnsIpv6Bottom(_)))
    }

    #[test]
    fn test_rdns_ipv4_up_prefix_invalid_input() {
        // GIVEN
        let s = "up:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv6_up_prefix_invalid_input() {
        // GIVEN
        let s = "up:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv4_down_prefix_invalid_input() {
        // GIVEN
        let s = "down:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv6_down_prefix_invalid_input() {
        // GIVEN
        let s = "down:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv4_top_prefix_invalid_input() {
        // GIVEN
        let s = "top:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv6_top_prefix_invalid_input() {
        // GIVEN
        let s = "top:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv4_bottom_prefix_invalid_input() {
        // GIVEN
        let s = "bottom:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }

    #[test]
    fn test_rdns_ipv6_bottom_prefix_invalid_input() {
        // GIVEN
        let s = "bottom:foo";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(q.is_err());
    }
}
