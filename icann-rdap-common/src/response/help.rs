//! Server Help Response.
use {
    crate::prelude::{Extension, Notice},
    serde::{Deserialize, Serialize},
};

use super::{to_opt_vec, Common, CommonFields, ToResponse};

/// Represents an RDAP help response.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Help {
    #[serde(flatten)]
    pub common: Common,
}

#[buildstructor::buildstructor]
impl Help {
    /// Builds a basic help response.
    #[builder(visibility = "pub")]
    fn new(notices: Vec<Notice>, extensions: Vec<Extension>) -> Self {
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
