use pct_str::{PctString, URIReserved};
use strum_macros::Display;

use crate::RdapClientError;

#[derive(Display, Debug)]
pub enum QueryType {
    #[strum(serialize = "IpV4 Address Lookup")]
    IpV4Addr(String),

    #[strum(serialize = "IpV6 Address Lookup")]
    IpV6Addr(String),

    #[strum(serialize = "IpV4 CIDR Lookup")]
    IpV4Cidr(String),

    #[strum(serialize = "IpV6 CIDR Lookup")]
    IpV6Cidr(String),

    #[strum(serialize = "Autonomous System Number Lookup")]
    AsNumber(String),

    #[strum(serialize = "Domain Lookup")]
    Domain(String),

    #[strum(serialize = "Entity Lookup")]
    Entity(String),

    #[strum(serialize = "Nameserver Lookup")]
    Nameserver(String),

    #[strum(serialize = "Entity Name Search")]
    EntityNameSearch(String),

    #[strum(serialize = "Entity Handle Search")]
    EntityHandleSearch(String),

    #[strum(serialize = "Domain Name Search")]
    DomainNameSearch(String),

    #[strum(serialize = "Domain Nameserver Name Search")]
    DomainNsNameSearch(String),

    #[strum(serialize = "Domain Nameserver IP Address Search")]
    DomainNsIpSearch(String),

    #[strum(serialize = "Nameserver Name Search")]
    NameserverNameSearch(String),

    #[strum(serialize = "Nameserver IP Address Search")]
    NameserverIpSearch(String),

    #[strum(serialize = "Server Help Lookup")]
    Help,
}

impl QueryType {
    pub fn query_url(&self, base_url: &str) -> Result<String, RdapClientError> {
        let base_url = base_url.trim_end_matches('/');
        match self {
            QueryType::IpV4Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::IpV6Addr(value) => Ok(format!(
                "{base_url}/ip/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::IpV4Cidr(value) => ip_cidr_query(value, base_url),
            QueryType::IpV6Cidr(value) => ip_cidr_query(value, base_url),
            QueryType::AsNumber(value) => {
                let autnum =
                    value.trim_start_matches(|c| -> bool { matches!(c, 'a' | 'A' | 's' | 'S') });
                Ok(format!(
                    "{base_url}/autnum/{}",
                    PctString::encode(autnum.chars(), URIReserved)
                ))
            }
            QueryType::Domain(value) => Ok(format!(
                "{base_url}/domain/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::Entity(value) => Ok(format!(
                "{base_url}/entity/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::Nameserver(value) => Ok(format!(
                "{base_url}/nameserver/{}",
                PctString::encode(value.chars(), URIReserved)
            )),
            QueryType::EntityNameSearch(value) => search_query(value, "entities?fn", base_url),
            QueryType::EntityHandleSearch(value) => {
                search_query(value, "entities?handle", base_url)
            }
            QueryType::DomainNameSearch(value) => search_query(value, "domains?name", base_url),
            QueryType::DomainNsNameSearch(value) => {
                search_query(value, "domains?nsLdhName", base_url)
            }
            QueryType::DomainNsIpSearch(value) => search_query(value, "domains?nsIp", base_url),
            QueryType::NameserverNameSearch(value) => {
                search_query(value, "nameserver?name=", base_url)
            }
            QueryType::NameserverIpSearch(value) => search_query(value, "nameservers?ip", base_url),
            QueryType::Help => Ok(format!("{base_url}/help")),
        }
    }
}

fn ip_cidr_query(value: &str, base_url: &str) -> Result<String, RdapClientError> {
    let values = value
        .split_once('/')
        .ok_or(RdapClientError::InvalidQueryValue)?;
    Ok(format!(
        "{base_url}/ip/{}/{}",
        PctString::encode(values.0.chars(), URIReserved),
        PctString::encode(values.1.chars(), URIReserved)
    ))
}

fn search_query(value: &str, path_query: &str, base_url: &str) -> Result<String, RdapClientError> {
    Ok(format!(
        "{base_url}/{path_query}={}",
        PctString::encode(value.chars(), URIReserved)
    ))
}
