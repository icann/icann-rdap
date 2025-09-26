//! RFC 9083 Error
use {
    crate::prelude::Extension,
    serde::{Deserialize, Serialize},
};

use super::{ExtensionId, Notice, Notices, RdapConformance, ToResponse};

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
/// let e = Rfc9083Error::response()
///   .error_code(500)
///   .build();
/// ```
///
/// Use the getter functions to access information.
/// ```rust
/// # use icann_rdap_common::prelude::*;
/// # let e = Rfc9083Error::response()
/// #   .error_code(500)
/// #   .build();
/// let error_code = e.error_code();
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Rfc9083Error {
    #[serde(rename = "rdapConformance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdap_conformance: Option<RdapConformance>,

    #[serde(rename = "errorCode")]
    pub error_code: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Vec<String>>,

    #[serde(rename = "extErr_location", skip_serializing_if = "Option::is_none")]
    pub exterr_location: Option<String>,

    #[serde(rename = "extErr_retryAfter", skip_serializing_if = "Option::is_none")]
    pub exterr_retry_after: Option<String>,

    #[serde(rename = "extErr_notices", skip_serializing_if = "Option::is_none")]
    pub exterr_notices: Option<Notices>,
}

#[buildstructor::buildstructor]
impl Rfc9083Error {
    /// Creates a new RFC 9083 Error for a specific HTTP error code.
    ///
    /// Use this builder to create a generic error:
    /// ```rust
    /// use icann_rdap_common::prelude::*;
    ///
    /// let e = Rfc9083Error::response()
    ///   .error_code(500) //required
    ///   .build();
    /// ```
    #[builder(entry = "response", visibility = "pub")]
    fn new_response(
        error_code: u16,
        description: Option<Vec<String>>,
        title: Option<String>,
        mut extensions: Vec<Extension>,
    ) -> Self {
        let mut standard_extensions = vec![ExtensionId::RdapLevel0.to_extension()];
        extensions.append(&mut standard_extensions);
        Self {
            rdap_conformance: Some(extensions),
            error_code,
            title,
            description,
            exterr_location: None,
            exterr_retry_after: None,
            exterr_notices: None,
        }
    }

    /// Creates an RFC 9083 error for an HTTP redirect.
    #[builder(entry = "redirect", visibility = "pub")]
    fn new_redirect(url: String, mut extensions: Vec<Extension>) -> Self {
        let mut standard_extensions = vec![
            ExtensionId::RdapLevel0.to_extension(),
            ExtensionId::ExtendedError.to_extension(),
        ];
        extensions.append(&mut standard_extensions);
        Self {
            rdap_conformance: Some(extensions),
            error_code: 307,
            title: None,
            description: None,
            exterr_location: Some(url),
            exterr_retry_after: None,
            exterr_notices: None,
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

    /// Getter for Extended Error Location
    pub fn exterr_location(&self) -> Option<&str> {
        self.exterr_location.as_deref()
    }

    /// Getter for Extended Error Retry After
    pub fn exterr_retry_after(&self) -> Option<&str> {
        self.exterr_retry_after.as_deref()
    }

    /// Getter for the Extended Error Notices.
    pub fn exterr_notices(&self) -> &[Notice] {
        self.exterr_notices.as_deref().unwrap_or_default()
    }

    /// True if the error is an HTTP redirect.
    pub fn is_redirect(&self) -> bool {
        self.error_code > 299 && self.error_code < 400
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
        let e = Rfc9083Error::response().error_code(404).build();

        // WHEN
        let actual = e.is_redirect();

        // THEN
        assert!(!actual);
    }
}
