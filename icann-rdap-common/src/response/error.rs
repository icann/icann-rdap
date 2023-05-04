use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use super::types::Common;

/// Represents an RDAP error response.
#[derive(Serialize, Deserialize, Builder, Clone)]
pub struct Error {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "errorCode")]
    pub error_code: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,
}

#[buildstructor::buildstructor]
impl Error {
    #[builder(entry = "basic")]
    pub fn new_error_code(error_code: u16) -> Self {
        Self {
            common: Common::builder().build(),
            error_code,
            title: None,
            description: None,
        }
    }
}
