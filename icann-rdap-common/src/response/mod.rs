//! RDAP structures for parsing and creating RDAP responses.
use std::any::TypeId;

use cidr;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum_macros::Display;
use thiserror::Error;

use crate::media_types::RDAP_MEDIA_TYPE;

#[doc(inline)]
pub use autnum::*;
#[doc(inline)]
pub use common::*;
#[doc(inline)]
pub use domain::*;
#[doc(inline)]
pub use entity::*;
#[doc(inline)]
pub use error::*;
#[doc(inline)]
pub use help::*;
#[doc(inline)]
pub use lenient::*;
#[doc(inline)]
pub use nameserver::*;
#[doc(inline)]
pub use network::*;
#[doc(inline)]
pub use obj_common::*;
#[doc(inline)]
pub use search::*;
#[doc(inline)]
pub use types::*;

pub(crate) mod autnum;
pub(crate) mod common;
pub(crate) mod domain;
pub(crate) mod entity;
pub(crate) mod error;
pub(crate) mod help;
pub(crate) mod lenient;
pub(crate) mod nameserver;
pub(crate) mod network;
pub(crate) mod obj_common;
pub mod redacted; // RFC 9537 is not a mainstream extension.
pub(crate) mod search;
pub(crate) mod types;

/// An error caused be processing an RDAP response.
///
/// This is caused because the JSON constituting the
/// RDAP response has a problem that cannot be overcome.
///
/// Do not confuse this with [Rfc9083Error].
#[derive(Debug, Error)]
pub enum RdapResponseError {
    /// The JSON type is incorrect.
    #[error("Wrong JSON type: {0}")]
    WrongJsonType(String),

    /// The type of RDAP response is unknown.
    #[error("Unknown RDAP response.")]
    UnknownRdapResponse,

    /// An error has occurred parsing the JSON.
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    /// An error with parsing an IP address.
    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),

    /// An error caused with parsing a CIDR address.
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
    ErrorResponse(Rfc9083Error),

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
                    "domain" => Ok(RdapResponse::Domain(serde_json::from_value(value)?)),
                    "entity" => Ok(RdapResponse::Entity(serde_json::from_value(value)?)),
                    "nameserver" => Ok(RdapResponse::Nameserver(serde_json::from_value(value)?)),
                    "autnum" => Ok(RdapResponse::Autnum(serde_json::from_value(value)?)),
                    "ip network" => Ok(RdapResponse::Network(serde_json::from_value(value)?)),
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
                return Ok(RdapResponse::DomainSearchResults(serde_json::from_value(
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
                return Ok(RdapResponse::EntitySearchResults(serde_json::from_value(
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
                return Ok(RdapResponse::NameserverSearchResults(
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
                return Ok(RdapResponse::ErrorResponse(serde_json::from_value(value)?));
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'errorCode' is not an unsigned integer".to_string(),
                ));
            }
        }

        // else if it has a notices then it is help response at this point
        if let Some(result) = response.get("notices") {
            if result.is_array() {
                return Ok(RdapResponse::Help(serde_json::from_value(value)?));
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
            RdapResponse::Entity(_) => TypeId::of::<Entity>(),
            RdapResponse::Domain(_) => TypeId::of::<Domain>(),
            RdapResponse::Nameserver(_) => TypeId::of::<Nameserver>(),
            RdapResponse::Autnum(_) => TypeId::of::<Autnum>(),
            RdapResponse::Network(_) => TypeId::of::<Network>(),
            RdapResponse::DomainSearchResults(_) => TypeId::of::<DomainSearchResults>(),
            RdapResponse::EntitySearchResults(_) => TypeId::of::<EntitySearchResults>(),
            RdapResponse::NameserverSearchResults(_) => TypeId::of::<NameserverSearchResults>(),
            RdapResponse::ErrorResponse(_) => TypeId::of::<crate::response::Rfc9083Error>(),
            RdapResponse::Help(_) => TypeId::of::<Help>(),
        }
    }

    pub fn get_links(&self) -> Option<&Links> {
        match self {
            RdapResponse::Entity(e) => e.object_common.links.as_ref(),
            RdapResponse::Domain(d) => d.object_common.links.as_ref(),
            RdapResponse::Nameserver(n) => n.object_common.links.as_ref(),
            RdapResponse::Autnum(a) => a.object_common.links.as_ref(),
            RdapResponse::Network(n) => n.object_common.links.as_ref(),
            RdapResponse::DomainSearchResults(_) => None,
            RdapResponse::EntitySearchResults(_) => None,
            RdapResponse::NameserverSearchResults(_) => None,
            RdapResponse::ErrorResponse(_) => None,
            RdapResponse::Help(_) => None,
        }
    }

    pub fn get_conformance(&self) -> Option<&RdapConformance> {
        match self {
            RdapResponse::Entity(e) => e.common.rdap_conformance.as_ref(),
            RdapResponse::Domain(d) => d.common.rdap_conformance.as_ref(),
            RdapResponse::Nameserver(n) => n.common.rdap_conformance.as_ref(),
            RdapResponse::Autnum(a) => a.common.rdap_conformance.as_ref(),
            RdapResponse::Network(n) => n.common.rdap_conformance.as_ref(),
            RdapResponse::DomainSearchResults(s) => s.common.rdap_conformance.as_ref(),
            RdapResponse::EntitySearchResults(s) => s.common.rdap_conformance.as_ref(),
            RdapResponse::NameserverSearchResults(s) => s.common.rdap_conformance.as_ref(),
            RdapResponse::ErrorResponse(e) => e.common.rdap_conformance.as_ref(),
            RdapResponse::Help(h) => h.common.rdap_conformance.as_ref(),
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
            RdapResponse::ErrorResponse(e) => e.is_redirect(),
            _ => false,
        }
    }
}

impl GetSelfLink for RdapResponse {
    fn get_self_link(&self) -> Option<&Link> {
        if let Some(links) = self.get_links() {
            links.iter().find(|link| link.is_relation("self"))
        } else {
            None
        }
    }
}

/// A trait for converting structs into an appropriate [RdapResponse] variant.
pub trait ToResponse {
    /// Consumes the object and returns an [RdapResponse].
    fn to_response(self) -> RdapResponse;
}

/// Trait for getting a link with a `rel` of "self".
pub trait GetSelfLink {
    /// Get's the first self link.
    /// See [crate::response::ObjectCommon::get_self_link()].
    fn get_self_link(&self) -> Option<&Link>;
}

/// Train for setting a link with a `rel` of "self".
pub trait SelfLink: GetSelfLink {
    /// See [crate::response::ObjectCommon::get_self_link()].
    fn set_self_link(self, link: Link) -> Self;
}

/// Gets the `href` of a link with `rel` of "related" and `type` with the RDAP media type.
pub fn get_related_links(rdap_response: &RdapResponse) -> Vec<&str> {
    if let Some(links) = rdap_response.get_links() {
        let urls: Vec<&str> = links
            .iter()
            .filter(|l| {
                if l.href.as_ref().is_some() {
                    if let Some(rel) = &l.rel {
                        if let Some(media_type) = &l.media_type {
                            rel.eq_ignore_ascii_case("related")
                                && media_type.eq_ignore_ascii_case(RDAP_MEDIA_TYPE)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .map(|l| l.href.as_ref().unwrap().as_str())
            .collect::<Vec<&str>>();
        urls
    } else {
        Vec::new()
    }
}

/// Makes a root object class suitable for being embedded in another object class.
pub trait ToChild {
    /// Removes notices and rdapConformance so this object can be a child
    /// of another object.
    fn to_child(self) -> Self;
}

/// Returns `Some(Vec<T>)` if the vector is not empty, otherwise `None`.
pub fn to_opt_vec<T>(vec: Vec<T>) -> Option<Vec<T>> {
    (!vec.is_empty()).then_some(vec)
}

/// Returns `Vec<T>` if `is_some()` else an empty vector.
pub fn opt_to_vec<T>(opt: Option<Vec<T>>) -> Vec<T> {
    opt.unwrap_or_default()
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
