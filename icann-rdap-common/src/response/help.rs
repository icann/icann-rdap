use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::types::Common;

/// Represents an RDAP help response.
#[derive(Serialize, Deserialize, Builder)]
pub struct Help {
    #[serde(flatten)]
    pub common: Common,
}
