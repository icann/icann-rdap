use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use super::{Extension, ExtensionId, Notice, Notices, RdapConformance};

/// Holds those types that are common in all responses.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Common {
    #[serde(rename = "rdapConformance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdap_conformance: Option<RdapConformance>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub notices: Option<Notices>,
}

#[buildstructor::buildstructor]
impl Common {
    #[builder(entry = "level0", visibility = "pub(crate)")]
    fn new_level0(mut extensions: Vec<Extension>, notices: Option<Vec<Notice>>) -> Self {
        let mut standard_extensions = vec![ExtensionId::RdapLevel0.to_extension()];
        extensions.append(&mut standard_extensions);
        Self {
            rdap_conformance: Some(extensions),
            notices,
        }
    }
}

lazy_static! {
    /// Empty Extensions.
    static ref EMPTY_EXTENSIONS: Vec<Extension> = vec![];
    /// Empty Notices.
    static ref EMPTY_NOTICES: Vec<Notice> = vec![];
}

/// Convience methods for fields in  [Common].
pub trait CommonFields {
    /// Getter for [Common].
    fn common(&self) -> &Common;

    /// Getter for Vec of RDAP extensions.
    fn extensions(&self) -> &Vec<Extension> {
        self.common()
            .rdap_conformance
            .as_ref()
            .unwrap_or(&EMPTY_EXTENSIONS)
    }

    /// Getter for Vec of Notices.
    fn notices(&self) -> &Vec<Notice> {
        self.common().notices.as_ref().unwrap_or(&EMPTY_NOTICES)
    }
}
