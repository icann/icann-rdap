//! Server Help Response.
use std::collections::HashSet;

use crate::prelude::{ContentExtensions, ExtensionId};

use {
    crate::prelude::{Extension, Notice},
    serde::{Deserialize, Serialize},
};

use super::{to_opt_vec, Common, CommonFields, ToResponse};

/// Represents an RDAP help response.
///
/// Use the builders to create one:
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let e = Help::response()
///   .build();
/// ```
///
/// Use the getter functions to access information.
/// See [CommonFields] for common getter functions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Help {
    #[serde(flatten)]
    pub common: Common,
}

#[buildstructor::buildstructor]
impl Help {
    /// Builds a basic help response.
    #[builder(entry = "response", visibility = "pub")]
    fn new_response(notices: Vec<Notice>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(to_opt_vec(notices))
                .build(),
        }
    }
}

impl CommonFields for Help {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for Help {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::Help(Box::new(self))
    }
}

impl ContentExtensions for Help {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        exts.extend(self.common().content_extensions());
        exts.insert(ExtensionId::Cidr0);
        exts.insert(ExtensionId::JsContact);
        exts.insert(ExtensionId::Redacted);
        exts.insert(ExtensionId::SimpleRedaction);
        exts
    }
}
