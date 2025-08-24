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

    #[builder(visibility = "pub(crate)")]
    fn new() -> Self {
        Self {
            rdap_conformance: None,
            notices: None,
        }
    }
}

/// Convience methods for fields in  [Common].
pub trait CommonFields {
    /// Getter for [Common].
    fn common(&self) -> &Common;

    /// Getter for the list of RDAP extensions.
    ///
    /// In valid RDAP, this only appears on the top most object.
    fn extensions(&self) -> &[Extension] {
        self.common()
            .rdap_conformance
            .as_deref()
            .unwrap_or_default()
    }

    /// Getter for the Notices.
    ///
    /// In valid RDAP, this only appears on the top most object.
    fn notices(&self) -> &[Notice] {
        self.common().notices.as_deref().unwrap_or_default()
    }
}
