use buildstructor::Builder;
use serde::{Deserialize, Serialize};

use crate::media_types::RDAP_MEDIA_TYPE;

use super::types::{Common, Link, Notice, NoticeOrRemark};

/// Represents an RDAP error response.
#[derive(Serialize, Deserialize, Builder, Clone, Debug, PartialEq, Eq)]
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
    pub fn new_error_code(error_code: u16, notices: Vec<crate::response::types::Notice>) -> Self {
        let notices = (!notices.is_empty()).then_some(notices);
        Self {
            common: Common::builder().and_notices(notices).build(),
            error_code,
            title: None,
            description: None,
        }
    }

    #[builder(entry = "redirect")]
    pub fn new_redirect(url: String) -> Self {
        let links = vec![Link::builder()
            .href(&url)
            .value(&url)
            .media_type(RDAP_MEDIA_TYPE)
            .rel("related")
            .build()];
        let notices = vec![Notice(NoticeOrRemark::builder().links(links).build())];
        Self {
            common: Common::builder().notices(notices).build(),
            error_code: 307,
            title: None,
            description: None,
        }
    }
}
