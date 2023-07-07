use std::any::TypeId;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum_macros::Display;
use thiserror::Error;

use self::{
    autnum::Autnum,
    domain::Domain,
    entity::Entity,
    error::Error,
    help::Help,
    nameserver::Nameserver,
    network::Network,
    search::{DomainSearchResults, EntitySearchResults, NameserverSearchResults},
    types::{Link, Links, RdapConformance},
};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
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
}

/// The various types of RDAP response.
#[derive(Serialize, Deserialize, Clone, Display)]
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
            RdapResponse::ErrorResponse(_) => TypeId::of::<crate::response::Error>(),
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

    pub fn get_self_link(&self) -> Option<&Link> {
        if let Some(links) = self.get_links() {
            links.iter().find(|link| {
                if let Some(rel) = &link.rel {
                    rel == "self"
                } else {
                    false
                }
            })
        } else {
            None
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
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use serde_json::Value;

    use super::RdapResponse;

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
