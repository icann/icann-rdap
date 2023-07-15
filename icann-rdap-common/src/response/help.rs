use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::types::Common;

/// Represents an RDAP help response.
#[derive(Serialize, Deserialize, Builder, Clone, PartialEq)]
pub struct Help {
    #[serde(flatten)]
    pub common: Common,
}

#[buildstructor::buildstructor]
impl Help {
    #[builder(entry = "basic")]
    pub fn new_basic() -> Self {
        Self {
            common: Common::builder().build(),
        }
    }
}
