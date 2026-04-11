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

    #[strum(serialize = "IpV4 Address Rdap-Up Lookup")]
    IpV4AddrUp(Ipv4Addr),

    #[strum(serialize = "IpV6 Address Rdap-Up Lookup")]
    IpV6AddrUp(Ipv6Addr),

    #[strum(serialize = "IpV4 CIDR Rdap-Up Lookup")]
    IpV4CidrUp(Ipv4Cidr),

    #[strum(serialize = "IpV6 CIDR Rdap-Up Lookup")]
    IpV6CidrUp(Ipv6Cidr),

    #[strum(serialize = "IpV4 Address Rdap-Down Lookup")]
    IpV4AddrDown(Ipv4Addr),

    #[strum(serialize = "IpV6 Address Rdap-Down Lookup")]
    IpV6AddrDown(Ipv6Addr),

    #[strum(serialize = "IpV4 CIDR Rdap-Down Lookup")]
    IpV4CidrDown(Ipv4Cidr),

    #[strum(serialize = "IpV6 CIDR Rdap-Down Lookup")]
    IpV6CidrDown(Ipv6Cidr),

    #[strum(serialize = "IpV4 Address Rdap-Top Lookup")]
    IpV4AddrTop(Ipv4Addr),

    #[strum(serialize = "IpV6 Address Rdap-Top Lookup")]
    IpV6AddrTop(Ipv6Addr),

    #[strum(serialize = "IpV4 CIDR Rdap-Top Lookup")]
    IpV4CidrTop(Ipv4Cidr),

    #[strum(serialize = "IpV6 CIDR Rdap-Top Lookup")]
    IpV6CidrTop(Ipv6Cidr),

    #[strum(serialize = "IpV4 Address Rdap-Bottom Search")]
    IpV4AddrBottom(Ipv4Addr),

    #[strum(serialize = "IpV6 Address Rdap-Bottom Search")]
    IpV6AddrBottom(Ipv6Addr),

    #[strum(serialize = "IpV4 CIDR Rdap-Bottom Search")]
    IpV4CidrBottom(Ipv4Cidr),

    #[strum(serialize = "IpV6 CIDR Rdap-Bottom Search")]
    IpV6CidrBottom(Ipv6Cidr),

    #[strum(serialize = "Autonomous System Number Lookup")]
    AsNumber(u32),

    #[strum(serialize = "Autonomous System Number Rdap-Up Lookup")]
    AsNumberUp(u32),

    #[strum(serialize = "Autonomous System Number Rdap-Down Lookup")]
    AsNumberDown(u32),

    #[strum(serialize = "Autonomous System Number Rdap-Top Search")]
    AsNumberTop(u32),

    #[strum(serialize = "Autonomous System Number Rdap-Bottom Search")]
    AsNumberBottom(u32),

    #[strum(serialize = "Domain Lookup")]
    Domain(DomainName),

    #[strum(serialize = "A-Label Domain Lookup")]
    ALabel(DomainName),

    #[strum(serialize = "Reverse DNS Domain Lookup")]
    ReverseDns(IpNet),

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
            Self::IpV4AddrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV6AddrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV4CidrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV6CidrUp(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-up/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV4AddrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV6AddrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV4CidrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV6CidrDown(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-down/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV4AddrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV6AddrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV4CidrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV6CidrTop(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-top/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV4AddrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV6AddrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::IpV4CidrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::IpV6CidrBottom(value) => Ok(format!(
                "{base_url}/ips/rirSearch1/rdap-bottom/{}/{}",
                PctString::encode(value.first_address().to_string().chars(), URIReserved),
                PctString::encode(value.network_length().to_string().chars(), URIReserved)
            )),
            Self::AsNumber(value) => Ok(format!(
                "{base_url}/autnum/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::AsNumberUp(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-up/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::AsNumberDown(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-down/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::AsNumberTop(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-top/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::AsNumberBottom(value) => Ok(format!(
                "{base_url}/autnums/rirSearch1/rdap-bottom/{}",
                PctString::encode(value.to_string().chars(), URIReserved)
            )),
            Self::Domain(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.trim_leading_dot().chars(), URIReserved)
            )),
            Self::ReverseDns(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(ip_to_reverse_dns(&value.network()).chars(), URIReserved)
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
        let ipnet = reverse_dns_to_ipnet(domain_name).ok_or(RdapClientError::InvalidQueryValue)?;
        Ok(Self::ReverseDns(ipnet))
    }

    pub fn rdns_ipstr(ip_address: &str) -> Result<Self, RdapClientError> {
        if let Ok(ip_cidr) = parse_cidr(ip_address) {
            return Ok(match ip_cidr {
                IpCidr::V4(cidr) => {
                    let first = cidr.first_address();
                    let prefix = cidr.network_length();
                    Self::ReverseDns(IpNet::V4(
                        Ipv4Net::new(first, prefix)
                            .map_err(|_e| RdapClientError::InvalidQueryValue)?,
                    ))
                }
                IpCidr::V6(cidr) => {
                    let first = cidr.first_address();
                    let prefix = cidr.network_length();
                    Self::ReverseDns(IpNet::V6(
                        Ipv6Net::new(first, prefix)
                            .map_err(|_e| RdapClientError::InvalidQueryValue)?,
                    ))
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
        Ok(Self::ReverseDns(ipnet))
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
                Ok(Self::ReverseDns(ipnet))
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
}
