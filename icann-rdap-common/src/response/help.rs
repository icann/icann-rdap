use crate::response::RdapResponseError;
use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::types::Common;

/// Represents an RDAP help response.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
pub struct Help {
    #[serde(flatten)]
    pub common: Common,
}

#[buildstructor::buildstructor]
impl Help {
    #[builder(entry = "basic")]
    pub fn new_help(
        notices: Vec<crate::response::types::Notice>,
    ) -> Result<Self, RdapResponseError> {
        let notices = (!notices.is_empty()).then_some(notices);
        Self::new_help_with_options(notices)
    }

    #[builder(entry = "with_options")]
    pub fn new_help_with_options(
        notices: Option<Vec<crate::response::types::Notice>>,
    ) -> Result<Self, RdapResponseError> {
        Ok(Self {
            common: Common::level0_with_options().and_notices(notices).build(),
        })
    }
}
