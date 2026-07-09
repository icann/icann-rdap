//! RFC 9083 Error
use std::collections::HashSet;

use {
    crate::prelude::Extension,
    serde::{Deserialize, Serialize},
};

use crate::media_types::RDAP_MEDIA_TYPE;
use crate::prelude::ContentExtensions;

use super::{
    Common, CommonFields, ToResponse,
    types::{Link, Notice, NoticeOrRemark},
};

use super::lenient::{Numberish, Stringish, VectorStringish};

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
/// let e = Rfc9083Error::response_obj()
///   .error_code(500)
///   .build();
/// ```
///
/// Use the getter functions to access information.
/// See [CommonFields] for common getter functions.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let e = Rfc9083Error::response_obj()
/// #   .error_code(500)
/// #   .build();
/// let error_code = e.error_code();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rfc9083Error {
    #[serde(flatten)]
    pub common: Common,

    #[serde(rename = "errorCode")]
    pub error_code: Numberish<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Stringish>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<VectorStringish>,
}

#[buildstructor::buildstructor]
impl Rfc9083Error {
    /// Creates a new RFC 9083 Error for a specific HTTP error code.
    ///
    /// Use this builder to create a generic error:
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let e = Rfc9083Error::response_obj()
    ///   .error_code(500) //required
    ///   .build();
    /// ```
    #[builder(entry = "response_obj", visibility = "pub")]
    fn new_response_obj(
        error_code: u16,
        notices: Vec<Notice>,
        title: Option<String>,
        description: Vec<String>,
        extensions: Vec<Extension>,
    ) -> Self {
        let notices = (!notices.is_empty()).then_some(notices);
        Self {
            common: Common::level0()
                .extensions(extensions)
                .and_notices(notices)
                .build(),
            error_code: Numberish::from(error_code),
            title: title.map(Stringish::from),
            description: Some(VectorStringish::from(description)),
        }
    }

    /// Creates an RFC 9083 error for an HTTP redirect.
    #[builder(entry = "redirect", visibility = "pub")]
    fn new_redirect(url: String, extensions: Vec<Extension>) -> Self {
        let links = vec![
            Link::builder()
                .href(&url)
                .value(&url)
                .media_type(RDAP_MEDIA_TYPE)
                .rel("related")
                .build(),
        ];
        let notices = vec![Notice(NoticeOrRemark::builder().links(links).build())];
        Self {
            common: Common::level0()
                .extensions(extensions)
                .notices(notices)
                .build(),
            error_code: Numberish::from(307u16),
            title: None,
            description: None,
        }
    }

    /// Get the errorCode.
    pub fn error_code(&self) -> u16 {
        self.error_code.as_u16().unwrap_or(0)
    }

    /// Get the title.
    pub fn title(&self) -> Option<&str> {
        self.title.as_ref().map(|s| s.as_ref())
    }

    /// Get the description.
    pub fn description(&self) -> &[String] {
        self.description.as_ref().map_or(&[], |v| v.vec())
    }

    /// True if the error is an HTTP redirect.
    pub fn is_redirect(&self) -> bool {
        let code = self.error_code.as_u16().unwrap_or(0);
        code > 299 && code < 400
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

impl ContentExtensions for Rfc9083Error {
    fn content_extensions(&self) -> std::collections::HashSet<super::ExtensionId> {
        let mut exts = HashSet::new();
        exts.extend(self.common().content_extensions());
        exts
    }
}

#[cfg(test)]
mod tests {
    use super::Rfc9083Error;

    #[test]
    fn error_code_301_is_redirect() {
        // GIVEN
        let e = Rfc9083Error::redirect().url("https://foo.example").build();

        // WHEN
        let actual = e.is_redirect();

        // THEN
        assert!(actual);
    }

    #[test]
    fn error_code_404_is_not_redirect() {
        // GIVEN
        let e = Rfc9083Error::response_obj().error_code(404).build();

        // WHEN
        let actual = e.is_redirect();

        // THEN
        assert!(!actual);
    }

    #[test]
    fn string_error_code_deserialize() {
        // GIVEN
        let json = r#"{"errorCode": "404"}"#;

        // WHEN
        let e: Rfc9083Error = serde_json::from_str(json).unwrap();

        // THEN
        assert_eq!(e.error_code(), 404);
        assert!(e.error_code.is_string());
    }

    #[test]
    fn number_error_code_deserialize() {
        // GIVEN
        let json = r#"{"errorCode": 404}"#;

        // WHEN
        let e: Rfc9083Error = serde_json::from_str(json).unwrap();

        // THEN
        assert_eq!(e.error_code(), 404);
        assert!(!e.error_code.is_string());
    }

    #[test]
    fn string_description_deserialize() {
        // GIVEN
        let json = r#"{"errorCode": 404, "description": "Not found"}"#;

        // WHEN
        let e: Rfc9083Error = serde_json::from_str(json).unwrap();

        // THEN
        assert_eq!(e.description(), &["Not found".to_string()]);
        assert!(e.description.as_ref().unwrap().is_string());
    }

    #[test]
    fn array_description_deserialize() {
        // GIVEN
        let json = r#"{"errorCode": 404, "description": ["Not found", "Resource missing"]}"#;

        // WHEN
        let e: Rfc9083Error = serde_json::from_str(json).unwrap();

        // THEN
        assert_eq!(
            e.description(),
            &["Not found".to_string(), "Resource missing".to_string()]
        );
        assert!(!e.description.as_ref().unwrap().is_string());
    }

    #[test]
    fn number_title_deserialize() {
        // GIVEN
        let json = r#"{"errorCode": 404, "title": 123}"#;

        // WHEN
        let e: Rfc9083Error = serde_json::from_str(json).unwrap();

        // THEN
        assert_eq!(e.title(), Some("123"));
        assert!(e.title.as_ref().unwrap().is_number());
    }

    #[test]
    fn bool_title_deserialize() {
        // GIVEN
        let json = r#"{"errorCode": 404, "title": true}"#;

        // WHEN
        let e: Rfc9083Error = serde_json::from_str(json).unwrap();

        // THEN
        assert_eq!(e.title(), Some("true"));
        assert!(e.title.as_ref().unwrap().is_bool());
    }

    #[test]
    fn string_title_deserialize() {
        // GIVEN
        let json = r#"{"errorCode": 404, "title": "Not Found"}"#;

        // WHEN
        let e: Rfc9083Error = serde_json::from_str(json).unwrap();

        // THEN
        assert_eq!(e.title(), Some("Not Found"));
        assert!(!e.title.as_ref().unwrap().is_number());
        assert!(!e.title.as_ref().unwrap().is_bool());
    }
}
