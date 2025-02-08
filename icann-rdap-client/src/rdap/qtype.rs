//! Defines the various types of RDAP queries.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use icann_rdap_common::{check::StringCheck, dns_types::DomainName};
use lazy_static::lazy_static;
use pct_str::{PctString, URIReserved};
use regex::Regex;
use strum_macros::Display;

use crate::RdapClientError;

/// Defines the various types of RDAP lookups and searches.
#[derive(Display, Debug)]
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
            QueryType::IpV4Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            QueryType::IpV6Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            QueryType::IpV4Cidr(value) => Ok(format!(
                "{base_url}/ip/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            QueryType::IpV6Cidr(value) => Ok(format!(
                "{base_url}/ip/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            QueryType::AsNumber(value) => Ok(format!(
                "{base_url}/autnum/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            QueryType::Domain(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.trim_leading_dot().chars(), URIReserved)
            )),
            QueryType::ALabel(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.to_ascii().chars(), URIReserved),
            )),
            QueryType::Entity(value) => Ok(format!(
                "{base_url}/entity/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::Nameserver(value) => Ok(format!(
                "{base_url}/nameserver/{}",
                PctString::encode(value.to_ascii().chars(), URIReserved)
            )),
            QueryType::EntityNameSearch(value) => search_query(value, "entities?fn", base_url),
            QueryType::EntityHandleSearch(value) => {
                search_query(value, "entities?handle", base_url)
            }
            QueryType::DomainNameSearch(value) => search_query(value, "domains?name", base_url),
            QueryType::DomainNsNameSearch(value) => {
                search_query(value, "domains?nsLdhName", base_url)
            }
            QueryType::DomainNsIpSearch(value) => {
                search_query(&value.to_string(), "domains?nsIp", base_url)
            }
            QueryType::NameserverNameSearch(value) => {
                search_query(value, "nameserver?name=", base_url)
            }
            QueryType::NameserverIpSearch(value) => {
                search_query(&value.to_string(), "nameservers?ip", base_url)
            }
            QueryType::Help => Ok(format!("{base_url}/help")),
            QueryType::Url(url) => Ok(url.to_owned()),
        }
    }

    pub fn domain(domain_name: &str) -> Result<QueryType, RdapClientError> {
        Ok(QueryType::Domain(DomainName::from_str(domain_name)?))
    }

    pub fn alabel(alabel: &str) -> Result<QueryType, RdapClientError> {
        Ok(QueryType::ALabel(DomainName::from_str(alabel)?))
    }

    pub fn ns(nameserver: &str) -> Result<QueryType, RdapClientError> {
        Ok(QueryType::Nameserver(DomainName::from_str(nameserver)?))
    }

    pub fn autnum(autnum: &str) -> Result<QueryType, RdapClientError> {
        let value = autnum
            .trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') })
            .parse::<u32>()
            .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(QueryType::AsNumber(value))
    }

    pub fn ipv4(ip: &str) -> Result<QueryType, RdapClientError> {
        let value = Ipv4Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(QueryType::IpV4Addr(value))
    }

    pub fn ipv6(ip: &str) -> Result<QueryType, RdapClientError> {
        let value = Ipv6Addr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(QueryType::IpV6Addr(value))
    }

    pub fn ipv4cidr(cidr: &str) -> Result<QueryType, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V4(v4) = value {
            Ok(QueryType::IpV4Cidr(v4))
        } else {
            Err(RdapClientError::AmbiquousQueryType)
        }
    }

    pub fn ipv6cidr(cidr: &str) -> Result<QueryType, RdapClientError> {
        let value = cidr::parsers::parse_cidr_ignore_hostbits::<IpCidr, _>(
            cidr,
            cidr::parsers::parse_loose_ip,
        )
        .map_err(|_e| RdapClientError::InvalidQueryValue)?;
        if let IpCidr::V6(v6) = value {
            Ok(QueryType::IpV6Cidr(v6))
        } else {
            Err(RdapClientError::AmbiquousQueryType)
        }
    }

    pub fn domain_ns_ip_search(ip: &str) -> Result<QueryType, RdapClientError> {
        let value = IpAddr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(QueryType::DomainNsIpSearch(value))
    }

    pub fn ns_ip_search(ip: &str) -> Result<QueryType, RdapClientError> {
        let value = IpAddr::from_str(ip).map_err(|_e| RdapClientError::InvalidQueryValue)?;
        Ok(QueryType::NameserverIpSearch(value))
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
            return Ok(QueryType::Url(s.to_owned()));
        }

        // if looks like an autnum
        let autnum = s.trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') });
        if let Ok(_autnum) = u32::from_str(autnum) {
            return QueryType::autnum(s);
        }

        // If it's an IP address
        if let Ok(ip_addr) = IpAddr::from_str(s) {
            if ip_addr.is_ipv4() {
                return QueryType::ipv4(s);
            } else {
                return QueryType::ipv6(s);
            }
        }

        // if it is a cidr
        if let Ok(ip_cidr) = parse_cidr(s) {
            return match ip_cidr {
                IpCidr::V4(cidr) => Ok(QueryType::IpV4Cidr(cidr)),
                IpCidr::V6(cidr) => Ok(QueryType::IpV6Cidr(cidr)),
            };
        }

        // if it looks like a domain name
        if is_domain_name(s) {
            if is_nameserver(s) {
                return QueryType::ns(s);
            } else {
                return QueryType::domain(s);
            }
        }

        // if it is just one word
        if !s.contains(|c: char| c.is_whitespace() || c == '.' || c == ',' || c == '"') {
            return Ok(QueryType::Entity(s.to_owned()));
        }

        // The query type cannot be deteremined.
        Err(RdapClientError::AmbiquousQueryType)
    }
}

fn parse_cidr(s: &str) -> Result<IpCidr, RdapClientError> {
    if let Some((prefix, suffix)) = s.split_once('/') {
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
    } else {
        Err(RdapClientError::InvalidQueryValue)
    }
}

fn is_ldh_domain(text: &str) -> bool {
    lazy_static! {
        static ref LDH_DOMAIN_RE: Regex =
            Regex::new(r"^(?i)(\.?[a-zA-Z0-9-]+)*\.[a-zA-Z0-9-]+\.?$").unwrap();
    }
    LDH_DOMAIN_RE.is_match(text)
}

fn is_domain_name(text: &str) -> bool {
    text.contains('.') && text.is_unicode_domain_name()
}

fn is_nameserver(text: &str) -> bool {
    lazy_static! {
        static ref NS_RE: Regex =
            Regex::new(r"^(?i)(ns)[a-zA-Z0-9-]*\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.?$").unwrap();
    }
    NS_RE.is_match(text)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;

    use super::*;

    #[test]
    fn GIVEN_ipv4_WHEN_query_type_from_str_THEN_query_is_ipv4() {
        // GIVEN
        let s = "129.129.1.1";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV4Addr(_)))
    }

    #[test]
    fn GIVEN_ipv6_WHEN_query_type_from_str_THEN_query_is_ipv6() {
        // GIVEN
        let s = "2001::1";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV6Addr(_)))
    }

    #[test]
    fn GIVEN_ipv4_cidr_WHEN_query_type_from_str_THEN_query_is_ipv4_cidr() {
        // GIVEN
        let s = "129.129.1.1/8";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV4Cidr(_)))
    }

    #[test]
    fn GIVEN_ipv6_cidr_WHEN_query_type_from_str_THEN_query_is_ipv6_cidr() {
        // GIVEN
        let s = "2001::1/20";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::IpV6Cidr(_)))
    }

    #[test]
    fn GIVEN_number_WHEN_query_type_from_str_THEN_query_is_autnum() {
        // GIVEN
        let s = "16509";

        // WHEN
        let q = QueryType::from_str(s);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::AsNumber(_)))
    }

    #[test]
    fn GIVEN_as_followed_by_number_WHEN_query_type_from_str_THEN_query_is_autnum() {
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
    fn GIVEN_domain_name_WHEN_query_type_from_str_THEN_query_is_domain(#[case] input: &str) {
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
    fn GIVEN_name_server_WHEN_query_type_from_str_THEN_query_is_nameserver(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Nameserver(_)))
    }

    #[test]
    fn GIVEN_single_word_WHEN_query_type_from_str_THEN_query_is_entity() {
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
    fn GIVEN_url_WHEN_query_type_from_str_THEN_query_is_url(#[case] input: &str) {
        // GIVEN case input

        // WHEN
        let q = QueryType::from_str(input);

        // THEN
        assert!(matches!(q.unwrap(), QueryType::Url(_)))
    }

    #[rstest]
    #[case("ns.foo_bar.com")]
    #[case("ns.foo bar.com")]
    fn GIVEN_bad_input_WHEN_query_type_from_str_THEN_error(#[case] input: &str) {
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
    fn GIVEN_cidr_WHEN_parse_cidr_THEN_error(#[case] actual: &str, #[case] expected: &str) {
        // GIVEN case input

        // WHEN

        let q = parse_cidr(actual);

        // THEN
        assert_eq!(q.unwrap().to_string(), expected)
    }
}
