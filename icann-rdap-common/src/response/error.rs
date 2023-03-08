use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::types::Common;

/// Represents an RDAP error response.
#[derive(Serialize, Deserialize, Builder)]
pub struct Error {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "errorCode")]
    pub error_code: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
}
