//! RDAP Search Results.
use crate::prelude::Common;
use crate::prelude::Extension;
use serde::{Deserialize, Serialize};

use super::{domain::Domain, entity::Entity, nameserver::Nameserver};

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
    #[builder(entry = "basic", visibility = "pub")]
    fn new_basic(results: Vec<Domain>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
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
    #[builder(entry = "basic", visibility = "pub")]
    fn new_basic(results: Vec<Nameserver>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
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
    #[builder(entry = "basic", visibility = "pub")]
    fn new_empty(results: Vec<Entity>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }
}
