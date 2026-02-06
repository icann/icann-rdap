//! RDAP structures for parsing and creating RDAP responses.
use std::{any::TypeId, collections::HashSet};

use {
    cidr,
    serde::{Deserialize, Serialize},
    serde_json::Value,
    strum_macros::Display,
    thiserror::Error,
};

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
#[doc(inline)]
pub use values::*;

pub(crate) mod autnum;
pub(crate) mod common;
pub(crate) mod domain;
pub(crate) mod entity;
pub(crate) mod error;
pub(crate) mod help;
pub mod jscontact;
pub(crate) mod lenient;
pub(crate) mod nameserver;
pub(crate) mod network;
pub(crate) mod obj_common;
pub mod redacted; // RFC 9537 is not a mainstream extension.
pub(crate) mod search;
pub(crate) mod types;
pub(crate) mod values; // JSContact is not a mainstream extension, yet.

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

    /// The type of RDAP response is unknown.
    #[error("Network type must either be 'v4' or 'v6'.")]
    InvalidNetworkType,
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
    Entity(Box<Entity>),
    Domain(Box<Domain>),
    Nameserver(Box<Nameserver>),
    Autnum(Box<Autnum>),
    Network(Box<Network>),

    // Search Results
    DomainSearchResults(Box<DomainSearchResults>),
    EntitySearchResults(Box<EntitySearchResults>),
    NameserverSearchResults(Box<NameserverSearchResults>),

    // Error
    ErrorResponse(Box<Rfc9083Error>),

    // Help
    Help(Box<Help>),
    // These are all boxed to keep the variant size aligned.
    // While not completely necessary for all these variants today,
    // this will prevent an API change in the future when new items
    // are added to each variant when supporting future RDAP extensions.
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
                    "domain" => Ok(serde_json::from_value::<Domain>(value)?.to_response()),
                    "entity" => Ok(serde_json::from_value::<Entity>(value)?.to_response()),
                    "nameserver" => Ok(serde_json::from_value::<Nameserver>(value)?.to_response()),
                    "autnum" => Ok(serde_json::from_value::<Autnum>(value)?.to_response()),
                    "ip network" => Ok(serde_json::from_value::<Network>(value)?.to_response()),
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
                return Ok(serde_json::from_value::<DomainSearchResults>(value)?.to_response());
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'domainSearchResults' is not an array".to_string(),
                ));
            }
        }
        // else if it is a entity search result
        if let Some(result) = response.get("entitySearchResults") {
            if result.is_array() {
                return Ok(serde_json::from_value::<EntitySearchResults>(value)?.to_response());
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'entitySearchResults' is not an array".to_string(),
                ));
            }
        }
        // else if it is a nameserver search result
        if let Some(result) = response.get("nameserverSearchResults") {
            if result.is_array() {
                return Ok(serde_json::from_value::<NameserverSearchResults>(value)?.to_response());
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'nameserverSearchResults' is not an array".to_string(),
                ));
            }
        }

        // else if it has an errorCode
        if let Some(result) = response.get("errorCode") {
            if result.is_u64() {
                return Ok(serde_json::from_value::<Rfc9083Error>(value)?.to_response());
            } else {
                return Err(RdapResponseError::WrongJsonType(
                    "'errorCode' is not an unsigned integer".to_string(),
                ));
            }
        }

        // else if it has a notices then it is help response at this point
        if let Some(result) = response.get("notices") {
            if result.is_array() {
                return Ok(serde_json::from_value::<Help>(value)?.to_response());
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
            Self::ErrorResponse(_) => TypeId::of::<crate::response::Rfc9083Error>(),
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
            Self::DomainSearchResults(_)
            | Self::EntitySearchResults(_)
            | Self::NameserverSearchResults(_)
            | Self::ErrorResponse(_)
            | Self::Help(_) => None,
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
        self.get_conformance()
            .is_some_and(|conformance| conformance.contains(&extension_id.to_extension()))
    }

    pub fn has_extension(&self, extension: &str) -> bool {
        self.get_conformance()
            .is_some_and(|conformance| conformance.contains(&Extension::from(extension)))
    }

    pub fn is_redirect(&self) -> bool {
        match self {
            Self::ErrorResponse(e) => e.is_redirect(),
            _ => false,
        }
    }
}

impl GetSelfLink for RdapResponse {
    fn self_link(&self) -> Option<&Link> {
        self.get_links()
            .and_then(|links| links.iter().find(|link| link.is_relation("self")))
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
    /// See [crate::response::ObjectCommon::self_link()].
    fn self_link(&self) -> Option<&Link>;
}

/// Train for setting a link with a `rel` of "self".
pub trait SelfLink: GetSelfLink {
    /// See [crate::response::ObjectCommon::self_link()].
    fn with_self_link(self, link: Link) -> Self;
}

pub fn get_related_links(rdap_response: &RdapResponse) -> Vec<&str> {
    let related = &["related".to_string()];
    get_relationship_links(related, rdap_response)
}

/// Gets the `href` of a link with `rel` of relationships.
///
/// This function will get the `href` from an RDAP object's links where the `rel`
/// is a combination of the given relationships and the `type` is an RDAP media type.
/// If no link with an RDAP media type is found, it will attempt to find a link that
/// is formatted as a known RDAP URL.
pub fn get_relationship_links<'b>(
    relationships: &[String],
    rdap_response: &'b RdapResponse,
) -> Vec<&'b str> {
    let Some(links) = rdap_response.get_links() else {
        return vec![];
    };

    let mut urls: Vec<_> = links
        .iter()
        .filter_map(|l| match (&l.href, &l.rel, &l.media_type) {
            (Some(href), Some(rel), Some(media_type))
                if is_relationship(rel, relationships)
                    && media_type.eq_ignore_ascii_case(RDAP_MEDIA_TYPE) =>
            {
                Some(href.as_str())
            }
            _ => None,
        })
        .collect();

    // if none are found with correct media type, look for something that looks like an RDAP link
    if urls.is_empty() {
        urls = links
            .iter()
            .filter(|l| {
                if let Some(href) = l.href() {
                    if let Some(rel) = l.rel() {
                        is_relationship(rel, relationships) && has_rdap_path(href)
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .map(|l| l.href.as_ref().unwrap().as_str())
            .collect::<Vec<&str>>();
    }
    urls
}

fn is_relationship(rel: &str, relationships: &[String]) -> bool {
    let mut splits: usize = 0;
    let num_found = rel
        .split_whitespace()
        .filter(|r| {
            splits += 1;
            relationships.iter().any(|s| r.eq_ignore_ascii_case(s))
        })
        .count();
    splits == num_found && num_found == relationships.len()
}

/// Returns true if the URL contains an RDAP path as defined by RFC 9082.
pub fn has_rdap_path(url: &str) -> bool {
    if url.contains("/domain/")
        || url.contains("/ip/")
        || url.contains("/autnum/")
        || url.contains("/nameserver/")
        || url.contains("/entity/")
    {
        return true;
    }
    false
}

/// Makes a root object class suitable for being embedded in another object class.
pub trait ToChild {
    /// Removes notices and rdapConformance so this object can be a child
    /// of another object.
    fn to_child(self) -> Self;
}

/// Returns `Some(Vec<T>)` if the vector is not empty; otherwise, `None`.
pub fn to_opt_vec<T>(vec: Vec<T>) -> Option<Vec<T>> {
    (!vec.is_empty()).then_some(vec)
}

/// Returns `Vec<T>` if `is_some()` else an empty vector.
pub fn opt_to_vec<T>(opt: Option<Vec<T>>) -> Vec<T> {
    opt.unwrap_or_default()
}

/// Retrieve the RDAP extensions making up the content of a response.
pub trait ContentExtensions {
    /// Returns a [HashSet] of [ExtensionId].
    ///
    /// The returned value should contain all the extension IDs used
    /// in the instance of the object.
    fn content_extensions(&self) -> HashSet<ExtensionId>;
}

impl ContentExtensions for RdapResponse {
    fn content_extensions(&self) -> HashSet<ExtensionId> {
        match &self {
            Self::Entity(e) => e.content_extensions(),
            Self::Domain(d) => d.content_extensions(),
            Self::Nameserver(n) => n.content_extensions(),
            Self::Autnum(a) => a.content_extensions(),
            Self::Network(n) => n.content_extensions(),
            Self::DomainSearchResults(r) => r.content_extensions(),
            Self::EntitySearchResults(r) => r.content_extensions(),
            Self::NameserverSearchResults(r) => r.content_extensions(),
            Self::ErrorResponse(e) => e.content_extensions(),
            Self::Help(h) => h.content_extensions(),
        }
    }
}

/// Normalizes the extensions in an [RdapResponse].
pub fn normalize_extensions(rdap: RdapResponse) -> RdapResponse {
    let extensions = rdap.content_extensions();
    let rdap_conformance = extensions
        .iter()
        .map(|e| e.to_extension())
        .collect::<Vec<Extension>>();

    match rdap {
        RdapResponse::Entity(e) => Entity {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..e.common
            },
            ..*e
        }
        .to_response(),
        RdapResponse::Domain(d) => Domain {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..d.common
            },
            ..*d
        }
        .to_response(),
        RdapResponse::Nameserver(n) => Nameserver {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..n.common
            },
            ..*n
        }
        .to_response(),
        RdapResponse::Autnum(a) => Autnum {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..a.common
            },
            ..*a
        }
        .to_response(),
        RdapResponse::Network(n) => Network {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..n.common
            },
            ..*n
        }
        .to_response(),
        RdapResponse::DomainSearchResults(r) => DomainSearchResults {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..r.common
            },
            ..*r
        }
        .to_response(),
        RdapResponse::EntitySearchResults(r) => EntitySearchResults {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..r.common
            },
            ..*r
        }
        .to_response(),
        RdapResponse::NameserverSearchResults(r) => NameserverSearchResults {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..r.common
            },
            ..*r
        }
        .to_response(),
        RdapResponse::ErrorResponse(e) => Rfc9083Error {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..e.common
            },
            ..*e
        }
        .to_response(),
        RdapResponse::Help(h) => Help {
            common: Common {
                rdap_conformance: Some(rdap_conformance),
                ..h.common
            },
        }
        .to_response(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::{
        media_types::RDAP_MEDIA_TYPE,
        prelude::{get_relationship_links, ExtensionId},
    };

    use super::{get_related_links, Domain, Link, RdapResponse, ToResponse};

    #[test]
    fn test_redaction_response_gets_object() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/lookup_with_redaction.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Domain(_)));
    }

    #[test]
    fn test_redaction_response_has_extension() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/lookup_with_redaction.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(actual.has_extension_id(ExtensionId::Redacted));
    }

    #[test]
    fn test_redaction_response_domain_search() {
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
    fn test_resopnse_is_domain() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/domain_afnic_fr.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Domain(_)));
    }

    #[test]
    fn test_response_is_entity() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/entity_arin_hostmaster.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Entity(_)));
    }

    #[test]
    fn test_response_is_nameserver() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/nameserver_ns1_nic_fr.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Nameserver(_)));
    }

    #[test]
    fn test_response_is_autnum() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/autnum_16509.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Autnum(_)));
    }

    #[test]
    fn test_response_is_network() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/network_192_198_0_0.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Network(_)));
    }

    #[test]
    fn test_response_is_domain_search_results() {
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
    fn test_response_is_entity_search_results() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/entities_fn_arin.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::EntitySearchResults(_)));
    }

    #[test]
    fn test_response_is_help() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/help_nic_fr.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::Help(_)));
    }

    #[test]
    fn test_response_is_error() {
        // GIVEN
        let expected: Value =
            serde_json::from_str(include_str!("test_files/error_ripe_net.json")).unwrap();

        // WHEN
        let actual = RdapResponse::try_from(expected).unwrap();

        // THEN
        assert!(matches!(actual, RdapResponse::ErrorResponse(_)));
    }

    #[test]
    fn test_string_is_entity_search_results() {
        // GIVEN
        let entity: Value =
            serde_json::from_str(include_str!("test_files/entities_fn_arin.json")).unwrap();
        let value = RdapResponse::try_from(entity).unwrap();

        // WHEN
        let actual = value.to_string();

        // THEN
        assert_eq!(actual, "EntitySearchResults");
    }

    #[test]
    fn test_get_related_for_non_rel_link() {
        // GIVEN
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(
                Link::builder()
                    .rel("not-related")
                    .href("http://example.com")
                    .value("http://example.com")
                    .build(),
            )
            .build()
            .to_response();

        // WHEN
        let links = get_related_links(&rdap);

        // THEN
        assert!(links.is_empty());
    }

    #[test]
    fn test_get_related_for_rel_with_rdap_type_link() {
        // GIVEN
        let link = Link::builder()
            .rel("related")
            .href("http://example.com")
            .value("http://example.com")
            .media_type(RDAP_MEDIA_TYPE)
            .build();
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(link.clone())
            .build()
            .to_response();

        // WHEN
        let links = get_related_links(&rdap);

        // THEN
        assert!(!links.is_empty());
        assert_eq!(links.first().expect("empty links"), &link.href().unwrap());
    }

    #[test]
    fn test_get_related_for_rel_link() {
        // GIVEN
        let link = Link::builder()
            .rel("related")
            .href("http://example.com")
            .value("http://example.com")
            .build();
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(link.clone())
            .build()
            .to_response();

        // WHEN
        let links = get_related_links(&rdap);

        // THEN
        assert!(links.is_empty());
    }

    #[test]
    fn test_get_related_for_rel_link_that_look_like_rdap() {
        // GIVEN
        let link = Link::builder()
            .rel("related")
            .href("http://example.com/domain/foo")
            .value("http://example.com")
            .build();
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(link.clone())
            .build()
            .to_response();

        // WHEN
        let links = get_related_links(&rdap);

        // THEN
        assert!(!links.is_empty());
        assert_eq!(links.first().expect("empty links"), &link.href().unwrap());
    }

    #[test]
    fn test_get_rdap_up_and_rdap_active_link() {
        // GIVEN
        let link = Link::builder()
            .rel("rdap-up rdap-active")
            .href("http://example.com")
            .value("http://example.com")
            .media_type(RDAP_MEDIA_TYPE)
            .build();
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(link.clone())
            .build()
            .to_response();

        // WHEN
        let links =
            get_relationship_links(&["rdap-up".to_string(), "rdap-active".to_string()], &rdap);

        // THEN
        assert!(!links.is_empty());
        assert_eq!(links.first().expect("empty links"), &link.href().unwrap());
    }

    #[test]
    fn test_get_rdap_active_and_rdap_up_link() {
        // GIVEN
        let link = Link::builder()
            .rel("rdap-up rdap-active")
            .href("http://example.com")
            .value("http://example.com")
            .media_type(RDAP_MEDIA_TYPE)
            .build();
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(link.clone())
            .build()
            .to_response();

        // WHEN
        let links =
            get_relationship_links(&["rdap-active".to_string(), "rdap-up".to_string()], &rdap);

        // THEN
        assert!(!links.is_empty());
        assert_eq!(links.first().expect("empty links"), &link.href().unwrap());
    }

    #[test]
    fn test_get_only_one_relationship_link() {
        // GIVEN
        let link = Link::builder()
            .rel("rdap-up rdap-active")
            .href("http://example.com")
            .value("http://example.com")
            .media_type(RDAP_MEDIA_TYPE)
            .build();
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(link.clone())
            .build()
            .to_response();

        // WHEN
        let links = get_relationship_links(&["rdap-up".to_string()], &rdap);

        // THEN
        assert!(links.is_empty());
    }

    #[test]
    fn test_get_too_many_relationship_link() {
        // GIVEN
        let link = Link::builder()
            .rel("rdap-up")
            .href("http://example.com")
            .value("http://example.com")
            .media_type(RDAP_MEDIA_TYPE)
            .build();
        let rdap = Domain::builder()
            .ldh_name("example.com")
            .link(link.clone())
            .build()
            .to_response();

        // WHEN
        let links =
            get_relationship_links(&["rdap-active".to_string(), "rdap-up".to_string()], &rdap);

        // THEN
        assert!(links.is_empty());
    }
}
