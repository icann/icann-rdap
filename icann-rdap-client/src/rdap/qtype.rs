//! Defines the various types of RDAP queries.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::LazyLock,
};

use icann_rdap_common::rdns::{ip_to_reverse_dns, reverse_dns_to_ip};

use {
    cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr},
    icann_rdap_common::{check::StringCheck, dns_types::DomainName},
    pct_str::{PctString, URIReserved},
    regex::Regex,
    strum_macros::Display,
};

use crate::RdapClientError;

/// Defines the various types of RDAP lookups and searches.
#[derive(Display, Debug, Clone)]
pub enum QueryType {
    #[strum(serialize = "IpV4 Address Lookup")]
    IpV4Addr(Ipv4Addr),

    #[strum(serialize = "IpV6 Address Lookup")]
    IpV6Addr(Ipv6Addr),

    #[strum(serialize = "IpV4 CIDR Lookup")]
    IpV4Cidr(Ipv4Cidr),

    #[strum(serialize = "IpV6 CIDR Lookup")]
    IpV6Cidr(Ipv6Cidr),

    #[strum(serialize = "Autonomous System Number Lookup")]
    AsNumber(u32),

    #[strum(serialize = "Domain Lookup")]
    Domain(DomainName),

    #[strum(serialize = "A-Label Domain Lookup")]
    ALabel(DomainName),

    #[strum(serialize = "Reverse DNS Domain Lookup")]
    ReverseDNs(IpAddr),

    #[strum(serialize = "Entity Lookup")]
    Entity(String),

    #[strum(serialize = "Nameserver Lookup")]
    Nameserver(DomainName),

    #[strum(serialize = "Entity Name Search")]
    EntityNameSearch(String),

    #[strum(serialize = "Entity Handle Search")]
    EntityHandleSearch(String),

    #[strum(serialize = "Domain Name Search")]
    DomainNameSearch(String),

    #[strum(serialize = "Domain Nameserver Name Search")]
    DomainNsNameSearch(String),

    #[strum(serialize = "Domain Nameserver IP Address Search")]
    DomainNsIpSearch(IpAddr),

    #[strum(serialize = "Nameserver Name Search")]
    NameserverNameSearch(String),

    #[strum(serialize = "Nameserver IP Address Search")]
    NameserverIpSearch(IpAddr),

    #[strum(serialize = "Server Help Lookup")]
    Help,

    #[strum(serialize = "Explicit URL")]
    Url(String),
}

impl QueryType {
    pub fn query_url(&self, base_url: &str) -> Result<String, RdapClientError> {
        let base_url = base_url.trim_end_matches('/');
        match self {
            Self::IpV4Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV6Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV4Cidr(value) => Ok(format!(
                "{base_url}/ip/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV6Cidr(value) => Ok(format!(
                "{base_url}/ip/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::AsNumber(value) => Ok(format!(
                "{base_url}/autnum/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::Domain(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.trim_leading_dot().chars(), URIReserved)
            )),
            Self::ReverseDNs(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(ip_to_reverse_dns(value).chars(), URIReserved)
            )),
            Self::ALabel(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.to_ascii().chars(), URIReserved),
            )),
            Self::Entity(value) => Ok(format!(
                "{base_url}/entity/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            Self::Nameserver(value) => Ok(format!(
                "{base_url}/nameserver/{}",
                PctString::encode(value.to_ascii().chars(), URIReserved)
            )),
            Self::EntityNameSearch(value) => search_query(value, "entities?fn", base_url),
            Self::EntityHandleSearch(value) => search_query(value, "entities?handle", base_url),
            Self::DomainNameSearch(value) => search_query(value, "domains?name", base_url),
            Self::DomainNsNameSearch(value) => search_query(value, "domains?nsLdhName", base_url),
            Self::DomainNsIpSearch(value) => {
                search_query(&value.to_string(), "domains?nsIp", base_url)
            }
            Self::NameserverNameSearch(value) => search_query(value, "nameservers?name", base_url),
            Self::NameserverIpSearch(value) => {
                search_query(&value.to_string(), "nameservers?ip", base_url)
            }
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

    pub fn rdns(domain_name: &str) -> Result<Self, RdapClientError> {
        let value = reverse_dns_to_ip(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        Ok(Self::ReverseDNs(value))
    }

    pub fn rdns_ipstr(ip_address: &str) -> Result<Self, RdapClientError> {
        let value =
            IpAddr::from_str(ip_address).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::ReverseDNs(value))
    }

    pub fn ns(nameserver: &str) -> Result<Self, RdapClientError> {
        Ok(Self::Nameserver(DomainName::from_str(nameserver)?))
    }

    pub fn autnum(autnum: &str) -> Result<Self, RdapClientError> {
        let value = autnum
            .trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') })
            .parse::<u32>()
            .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(Self::AsNumber(value))
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
        PctString::encode(value.chars(), URIReserved)
    ))
}

impl FromStr for QueryType {
    type Err = RdapClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // if it looks like a HTTP(S) url
        if s.starts_with("http://") || s.starts_with("https://") {
            return Ok(Self::Url(s.to_owned()));
        }

        // if looks like an autnum
        let autnum = s.trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') });
        if u32::from_str(autnum).is_ok() {
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
            } else if let Some(ip) = reverse_dns_to_ip(s) {
                Ok(Self::ReverseDNs(ip))
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
}
