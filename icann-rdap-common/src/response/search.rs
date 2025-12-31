//! RDAP Search Results.
use std::collections::HashSet;

use crate::prelude::ContentExtensions;

use {
    crate::prelude::{Common, Extension},
    serde::{Deserialize, Serialize},
};

use super::{domain::Domain, entity::Entity, nameserver::Nameserver, CommonFields, ToResponse};

/// Represents RDAP domain search results.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct DomainSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "domainSearchResults")]
    pub results: Vec<Domain>,
}

#[buildstructor::buildstructor]
impl DomainSearchResults {
    /// Builds a domain search result.
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Domain>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    /// Get the domains in the search.
    pub fn results(&self) -> &[Domain] {
        self.results.as_ref()
    }
}

impl CommonFields for DomainSearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for DomainSearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::DomainSearchResults(Box::new(self))
    }
}

impl ContentExtensions for DomainSearchResults {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        self.results()
            .iter()
            .for_each(|d| exts.extend(d.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}

/// Represents RDAP nameserver search results.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct NameserverSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "nameserverSearchResults")]
    pub results: Vec<Nameserver>,
}

#[buildstructor::buildstructor]
impl NameserverSearchResults {
    /// Builds a nameserver search result.
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Nameserver>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    /// Get the nameservers in the search.
    pub fn results(&self) -> &[Nameserver] {
        self.results.as_ref()
    }
}

impl CommonFields for NameserverSearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for NameserverSearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::NameserverSearchResults(Box::new(self))
    }
}

impl ContentExtensions for NameserverSearchResults {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        self.results()
            .iter()
            .for_each(|n| exts.extend(n.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}

/// Represents RDAP entity search results.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct EntitySearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "entitySearchResults")]
    pub results: Vec<Entity>,
}

#[buildstructor::buildstructor]
impl EntitySearchResults {
    /// Builds an entity search result.
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Entity>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    /// Get the entities in the search.
    pub fn results(&self) -> &[Entity] {
        self.results.as_ref()
    }
}

impl CommonFields for EntitySearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for EntitySearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::EntitySearchResults(Box::new(self))
    }
}

impl ContentExtensions for EntitySearchResults {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        self.results()
            .iter()
            .for_each(|e| exts.extend(e.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}
