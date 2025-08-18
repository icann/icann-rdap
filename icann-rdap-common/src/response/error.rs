//! RFC 9083 Error
use {
    crate::prelude::Extension,
    serde::{Deserialize, Serialize},
};

use crate::media_types::RDAP_MEDIA_TYPE;

use super::{
    types::{Link, Notice, NoticeOrRemark},
    Common, CommonFields, ToResponse,
};

/// Represents an error response from an RDAP server.
///
/// This structure represents the JSON returned by an RDAP server
/// describing an error.
/// See [RFC 9083, Section 6](https://datatracker.ietf.org/doc/html/rfc9083#name-error-response-body).
///
/// Do not confuse this with [crate::response::RdapResponseError].
///
/// Use the builders to create one:
/// ```rust
/// use icann_rdap_common::prelude::*;
///
/// let e = Rfc9083Error::builder()
///   .error_code(500)
///   .build();
/// ```
///
/// Use the getter functions to access information.
/// See [CommonFields] for common getter functions.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let e = Rfc9083Error::builder()
/// #   .error_code(500)
/// #   .build();
/// let error_code = e.error_code();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rfc9083Error {
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
impl Rfc9083Error {
    /// Creates a new RFC 9083 Error for a specific HTTP error code.
    #[builder(visibility = "pub")]
    fn new(error_code: u16, notices: Vec<Notice>, extensions: Vec<Extension>) -> Self {
        let notices = (!notices.is_empty()).then_some(notices);
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(notices)
                .build(),
            error_code,
            title: None,
            description: None,
        }
    }

    /// Creates an RFC 9083 error for an HTTP redirect.
    #[builder(entry = "redirect", visibility = "pub")]
    fn new_redirect(url: String, extensions: Vec<Extension>) -> Self {
        let links = vec![Link::builder()
            .href(&url)
            .value(&url)
            .media_type(RDAP_MEDIA_TYPE)
            .rel("related")
            .build()];
        let notices = vec![Notice(NoticeOrRemark::builder().links(links).build())];
        Self {
            common: Common::level0()
                .extensions(extensions)
                .notices(notices)
                .build(),
            error_code: 307,
            title: None,
            description: None,
        }
    }

    /// Get the errorCode.
    pub fn error_code(&self) -> u16 {
        self.error_code
    }

    /// Get the title.
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Get the description.
    pub fn description(&self) -> &[String] {
        self.description.as_deref().unwrap_or_default()
    }

    /// True if the error is an HTTP redirect.
    pub fn is_redirect(&self) -> bool {
        self.error_code > 299 && self.error_code < 400
    }
}

impl CommonFields for Rfc9083Error {
    fn common(&self) -> &Common {
        &self.common
    }
}

impl ToResponse for Rfc9083Error {
    fn to_response(self) -> super::RdapResponse {
        super::RdapResponse::ErrorResponse(Box::new(self))
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::Rfc9083Error;

    #[test]
    fn GIVEN_error_code_301_WHEN_is_redirect_THEN_true() {
        // GIVEN
        let e = Rfc9083Error::redirect().url("https://foo.example").build();

        // WHEN
        let actual = e.is_redirect();

        // THEN
        assert!(actual);
    }

    #[test]
    fn GIVEN_error_code_404_WHEN_is_redirect_THEN_false() {
        // GIVEN
        let e = Rfc9083Error::builder().error_code(404).build();

        // WHEN
        let actual = e.is_redirect();

        // THEN
        assert!(!actual);
    }
}
