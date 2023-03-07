use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{domain::Domain, entity::Entity, nameserver::Nameserver, types::Common};

/// Represents RDAP domain search results.
#[derive(Serialize, Deserialize, Builder)]
pub struct DomainSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "domainSearchResults")]
    pub results: Vec<Domain>,
}

/// Represents RDAP nameserver search results.
#[derive(Serialize, Deserialize, Builder)]
pub struct NameserverSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "nameserverSearchResults")]
    pub results: Vec<Nameserver>,
}

/// Represents RDAP entity search results.
#[derive(Serialize, Deserialize, Builder)]
pub struct EntitySearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "entitySearchResults")]
    pub results: Vec<Entity>,
}
