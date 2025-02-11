//! Server Help Response.
use crate::prelude::Extension;
use crate::prelude::Notice;
use serde::{Deserialize, Serialize};

use super::to_opt_vec;
use super::Common;

/// Represents an RDAP help response.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Help {
    #[serde(flatten)]
    pub common: Common,
}

#[buildstructor::buildstructor]
impl Help {
    /// Builds a basic help response.
    #[builder(entry = "basic", visibility = "pub")]
    fn new_help(notices: Vec<Notice>, extensions: Vec<Extension>) -> Self {
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(to_opt_vec(notices))
                .build(),
        }
    }
}
