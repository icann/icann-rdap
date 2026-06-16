//! RDAP RIR Search Results.
use std::collections::HashSet;

use crate::prelude::ContentExtensions;

use {
    crate::prelude::{Common, Extension},
    serde::{Deserialize, Serialize},
};

use super::{CommonFields, ToResponse, autnum::Autnum, network::Network};

/// Represents RDAP IP search results as defined in RFC 9910 Section 4.2.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct IpSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "ipSearchResults")]
    pub results: Vec<Network>,
}

#[buildstructor::buildstructor]
impl IpSearchResults {
    /// Builds an IP search result.
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Network>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    /// Get the networks in the search.
    pub fn results(&self) -> &[Network] {
        self.results.as_ref()
    }
}

impl CommonFields for IpSearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for IpSearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::IpSearchResults(Box::new(self))
    }
}

impl ContentExtensions for IpSearchResults {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(super::ExtensionId::IpSearchResults);
        self.results()
            .iter()
            .for_each(|n| exts.extend(n.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}

/// Represents RDAP autnum search results as defined in RFC 9910 Section 4.3.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
pub struct AutnumSearchResults {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "autnumSearchResults")]
    pub results: Vec<Autnum>,
}

#[buildstructor::buildstructor]
impl AutnumSearchResults {
    /// Builds an autnum search result.
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(results: Vec<Autnum>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0().extensions(extensions).build(),
            results,
        }
    }

    /// Get the autnums in the search.
    pub fn results(&self) -> &[Autnum] {
        self.results.as_ref()
    }
}

impl CommonFields for AutnumSearchResults {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for AutnumSearchResults {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::AutnumSearchResults(Box::new(self))
    }
}

impl ContentExtensions for AutnumSearchResults {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        exts.insert(super::ExtensionId::AutnumSearchResults);
        self.results()
            .iter()
            .for_each(|a| exts.extend(a.content_extensions()));
        exts.extend(self.common().content_extensions());
        exts
    }
}
