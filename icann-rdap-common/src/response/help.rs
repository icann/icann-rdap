//! Server Help Response.
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
/// let e = Help::response_obj()
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
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(notices: Vec<Notice>, extensions: Vec<Extension>) -> Self {
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
