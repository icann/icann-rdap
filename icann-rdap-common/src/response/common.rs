use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::{Extension, ExtensionId, Notice, Notices, RdapConformance};

/// Holds those types that are common in all responses.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Common {
    #[serde(rename = "rdapConformance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdap_conformance: Option<RdapConformance>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub notices: Option<Notices>,
}

#[buildstructor::buildstructor]
impl Common {
    #[builder(entry = "level0", visibility = "pub")]
    fn new_level0_with_options(
        mut extensions: Vec<Extension>,
        notices: Option<Vec<Notice>>,
    ) -> Self {
        let mut standard_extensions = vec![ExtensionId::RdapLevel0.to_extension()];
        extensions.append(&mut standard_extensions);
        Self {
            rdap_conformance: Some(extensions),
            notices,
        }
    }
}
