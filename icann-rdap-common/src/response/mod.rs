//! RDAP structures for parsing and creating RDAP responses.
use std::any::TypeId;

use cidr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum_macros::Display;
use thiserror::Error;
use types::Extension;

use crate::media_types::RDAP_MEDIA_TYPE;

use self::{
    autnum::Autnum,
    domain::Domain,
    entity::Entity,
    error::Error,
    help::Help,
    nameserver::Nameserver,
    network::Network,
    search::{DomainSearchResults, EntitySearchResults, NameserverSearchResults},
    types::{ExtensionId, Link, Links, RdapConformance},
};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod redacted;
pub mod search;
pub mod types;

#[derive(Debug, Error)]
pub enum RdapResponseError {
    #[error("Wrong JSON type: {0}")]
    WrongJsonType(String),

    #[error("Unknown RDAP response.")]
    UnknownRdapResponse,

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),

    #[error(transparent)]
    CidrParse(#[from] cidr::errors::NetworkParseError),
}

/// The various types of RDAP response.
///
/// It can be parsed from JSON using serde:
///
/// ```rust
/// use icann_rdap_common::response::RdapResponse;
///
/// let json = r#"
///   {
///     "objectClassName": "ip network",
///     "links": [
///       {
///         "value": "http://localhost:3000/rdap/ip/10.0.0.0/16",
///         "rel": "self",
///         "href": "http://localhost:3000/rdap/ip/10.0.0.0/16",
///         "type": "application/rdap+json"
///       }
///     ],
///     "events": [
///       {
///         "eventAction": "registration",
///         "eventDate": "2023-06-16T22:56:49.594173356+00:00"
///       },
///       {
///         "eventAction": "last changed",
///         "eventDate": "2023-06-16T22:56:49.594189140+00:00"
///       }
///     ],
///     "startAddress": "10.0.0.0",
///     "endAddress": "10.0.255.255",
///     "ipVersion": "v4"
///   }
/// "#;
///
/// let rdap: RdapResponse = serde_json::from_str(json).unwrap();
/// assert!(matches!(rdap, RdapResponse::Network(_)));
/// ```
#[derive(Serialize, Deserialize, Clone, Display, PartialEq, Debug)]
#[serde(untagged, try_from = "Value")]
pub enum RdapResponse {
    // Object Classes
    Entity(Entity),
    Domain(Domain),
    Nameserver(Nameserver),
    Autnum(Autnum),
    Network(Network),

    // Search Results
    DomainSearchResults(DomainSearchResults),
    EntitySearchResults(EntitySearchResults),
    NameserverSearchResults(NameserverSearchResults),

    // Error
    ErrorResponse(Error),

    // Help
    Help(Help),
}

impl TryFrom<Value> for RdapResponse {
    type Error = RdapResponseError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let response = if let Some(object) = value.as_object() {
            object
        } else {
            return Err(RdapResponseError::WrongJsonType(
                "response is not an object".to_string(),
            ));
        };

        // if it has an objectClassName
        if let Some(class_name) = response.get("objectClassName") {
            if let Some(name_str) = class_name.as_str() {
                return match name_str {
                    "domain" => Ok(Self::Domain(serde_json::from_value(value)?)),
                    "entity" => Ok(Self::Entity(serde_json::from_value(value)?)),
                    "nameserver" => Ok(Self::Nameserver(serde_json::from_value(value)?)),
                    "autnum" => Ok(Self::Autnum(serde_json::from_value(value)?)),
                    "ip network" => Ok(Self::Network(serde_json::from_value(value)?)),
                    _ => Err(RdapResponseError::UnknownRdapResponse),
                };
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'objectClassName' is not a string".to_string(),
                ));
            }
        };

        // else if it is a domain search result
        if let Some(result) = response.get("domainSearchResults") {
            if result.is_array() {
                return Ok(Self::DomainSearchResults(serde_json::from_value(
                    value,
                )?));
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'domainSearchResults' is not an array".to_string(),
                ));
            }
        }
        // else if it is a entity search result
        if let Some(result) = response.get("entitySearchResults") {
            if result.is_array() {
                return Ok(Self::EntitySearchResults(serde_json::from_value(
                    value,
                )?));
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'entitySearchResults' is not an array".to_string(),
                ));
            }
        }
        // else if it is a nameserver search result
        if let Some(result) = response.get("nameserverSearchResults") {
            if result.is_array() {
                return Ok(Self::NameserverSearchResults(
                    serde_json::from_value(value)?,
                ));
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'nameserverSearchResults' is not an array".to_string(),
                ));
            }
        }

        // else if it has an errorCode
        if let Some(result) = response.get("errorCode") {
            if result.is_u64() {
                return Ok(Self::ErrorResponse(serde_json::from_value(value)?));
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'errorCode' is not an unsigned integer".to_string(),
                ));
            }
        }

        // else if it has a notices then it is help response at this point
        if let Some(result) = response.get("notices") {
            if result.is_array() {
                return Ok(Self::Help(serde_json::from_value(value)?));
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'notices' is not an array".to_string(),
                ));
            }
        }
        Err(RdapResponseError::UnknownRdapResponse)
    }
}

impl RdapResponse {
    pub fn get_type(&self) -> TypeId {
        match self {
            Self::Entity(_) => TypeId::of::<Entity>(),
            Self::Domain(_) => TypeId::of::<Domain>(),
            Self::Nameserver(_) => TypeId::of::<Nameserver>(),
            Self::Autnum(_) => TypeId::of::<Autnum>(),
            Self::Network(_) => TypeId::of::<Network>(),
            Self::DomainSearchResults(_) => TypeId::of::<DomainSearchResults>(),
            Self::EntitySearchResults(_) => TypeId::of::<EntitySearchResults>(),
            Self::NameserverSearchResults(_) => TypeId::of::<NameserverSearchResults>(),
            Self::ErrorResponse(_) => TypeId::of::<crate::response::Error>(),
            Self::Help(_) => TypeId::of::<Help>(),
        }
    }

    pub fn get_links(&self) -> Option<&Links> {
        match self {
            Self::Entity(e) => e.object_common.links.as_ref(),
            Self::Domain(d) => d.object_common.links.as_ref(),
            Self::Nameserver(n) => n.object_common.links.as_ref(),
            Self::Autnum(a) => a.object_common.links.as_ref(),
            Self::Network(n) => n.object_common.links.as_ref(),
            Self::DomainSearchResults(_) |
            Self::EntitySearchResults(_) |
            Self::NameserverSearchResults(_) |
            Self::ErrorResponse(_) |
            Self::Help(_) => None,
        }
    }

    pub fn get_conformance(&self) -> Option<&RdapConformance> {
        match self {
            Self::Entity(e) => e.common.rdap_conformance.as_ref(),
            Self::Domain(d) => d.common.rdap_conformance.as_ref(),
            Self::Nameserver(n) => n.common.rdap_conformance.as_ref(),
            Self::Autnum(a) => a.common.rdap_conformance.as_ref(),
            Self::Network(n) => n.common.rdap_conformance.as_ref(),
            Self::DomainSearchResults(s) => s.common.rdap_conformance.as_ref(),
            Self::EntitySearchResults(s) => s.common.rdap_conformance.as_ref(),
            Self::NameserverSearchResults(s) => s.common.rdap_conformance.as_ref(),
            Self::ErrorResponse(e) => e.common.rdap_conformance.as_ref(),
            Self::Help(h) => h.common.rdap_conformance.as_ref(),
        }
    }

    pub fn has_extension_id(&self, extension_id: ExtensionId) -> bool {
        self.get_conformance().map_or(false, |conformance| {
            conformance.contains(&extension_id.to_extension())
        })
    }

    pub fn has_extension(&self, extension: &str) -> bool {
        self.get_conformance().map_or(false, |conformance| {
            conformance.contains(&Extension::from(extension))
        })
    }

    pub fn is_redirect(&self) -> bool {
        match self {
            Self::ErrorResponse(e) => e.is_redirect(),
            _ => false,
        }
    }
}

impl GetSelfLink for RdapResponse {
    fn get_self_link(&self) -> Option<&Link> {
        self.get_links()
            .and_then(|links| links.iter().find(|link| link.is_relation("self")))

    }
}

pub trait GetSelfLink {
    /// Get's the first self link.
    /// See [crate::response::types::ObjectCommon::get_self_link()].
    fn get_self_link(&self) -> Option<&Link>;
}

pub trait SelfLink: GetSelfLink {
    /// See [crate::response::types::ObjectCommon::get_self_link()].
    fn set_self_link(self, link: Link) -> Self;
}

pub fn get_related_links(rdap_response: &RdapResponse) -> Vec<&str> {
    let Some(links) = rdap_response.get_links() else{
        return vec![];
    };
    let urls: Vec<&str> = links
        .iter()
        .filter(|l| {
            if l.href.as_ref().is_some() {
                if let Some(rel) = &l.rel {
                    if let Some(media_type) = &l.media_type {
                        return rel.eq_ignore_ascii_case("related")
                            && media_type.eq_ignore_ascii_case(RDAP_MEDIA_TYPE)
                    }
                }
            }
            false
        })
        .map(|l| l.href.as_ref().unwrap().as_str())
        .collect::<Vec<&str>>();
    urls
}

pub trait ToChild {
    /// Removes notices and rdapConformance so this object can be a child
    /// of another object.
    fn to_child(self) -> Self;
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use serde_json::Value;

    use super::RdapResponse;

    #[test]
    fn GIVEN_redaction_response_WHEN_try_from_THEN_response_is_lookup_with_redaction() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/lookup_with_redaction.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Domain(_)));
    }

    #[test]
    fn GIVEN_redaction_response_WHEN_has_extension_THEN_true() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/lookup_with_redaction.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(actual.has_extension_id(crate::response::types::ExtensionId::Redacted));
    }

    #[test]
    fn GIVEN_redaction_response_WHEN_try_from_THEN_response_is_domain_search_results_with_redaction(
    ) {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/domain_search_with_redaction.json"))
                .unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::DomainSearchResults(_)));
    }

    #[test]
    fn GIVEN_domain_response_WHEN_try_from_THEN_response_is_domain() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/domain_afnic_fr.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Domain(_)));
    }

    #[test]
    fn GIVEN_entity_response_WHEN_try_from_THEN_response_is_entity() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/entity_arin_hostmaster.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Entity(_)));
    }

    #[test]
    fn GIVEN_nameserver_response_WHEN_try_from_THEN_response_is_nameserver() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/nameserver_ns1_nic_fr.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Nameserver(_)));
    }

    #[test]
    fn GIVEN_autnum_response_WHEN_try_from_THEN_response_is_autnum() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/autnum_16509.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Autnum(_)));
    }

    #[test]
    fn GIVEN_network_response_WHEN_try_from_THEN_response_is_network() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/network_192_198_0_0.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Network(_)));
    }

    #[test]
    fn GIVEN_domain_search_results_WHEN_try_from_THEN_response_is_domain_search_results() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/domains_ldhname_ns1_arin_net.json"))
                .unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::DomainSearchResults(_)));
    }

    #[test]
    fn GIVEN_entity_search_results_WHEN_try_from_THEN_response_is_entity_search_results() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/entities_fn_arin.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::EntitySearchResults(_)));
    }

    #[test]
    fn GIVEN_help_response_WHEN_try_from_THEN_response_is_help() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/help_nic_fr.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Help(_)));
    }

    #[test]
    fn GIVEN_error_response_WHEN_try_from_THEN_response_is_error() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/error_ripe_net.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::ErrorResponse(_)));
    }

    #[test]
    fn GIVEN_entity_search_results_variant_WHEN_to_string_THEN_string_is_entity() {
        // GIVEN
        let entity: Value =
            serde_json::from_str(include_str!("test_files/entities_fn_arin.json")).unwrap();
        let value = RdapResponse::try_from(entity).unwrap();

        // WHEN
        let actual = value.to_string();

        // THEN
        assert_eq!(actual, "EntitySearchResults");
    }
}
