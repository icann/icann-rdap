use std::sync::LazyLock;

use {
    axum::{
        response::{IntoResponse, Response},
        Json,
    },
    http::StatusCode,
    icann_rdap_common::{
        media_types::RDAP_MEDIA_TYPE,
        prelude::ToResponse,
        response::{RdapResponse, Rfc9083Error},
    },
    tracing::warn,
};

pub static NOT_FOUND: LazyLock<RdapResponse> = LazyLock::new(|| {
    Rfc9083Error::response()
        .error_code(404)
        .build()
        .to_response()
});
pub static NOT_IMPLEMENTED: LazyLock<RdapResponse> = LazyLock::new(|| {
    Rfc9083Error::response()
        .error_code(501)
        .build()
        .to_response()
});
pub static BAD_REQUEST: LazyLock<RdapResponse> = LazyLock::new(|| {
    Rfc9083Error::response()
        .error_code(400)
        .build()
        .to_response()
});

pub(crate) const RDAP_HEADERS: [(&str, &str); 1] = [("content-type", RDAP_MEDIA_TYPE)];

pub(crate) trait ResponseUtil {
    fn status_code(&self) -> StatusCode;
    fn first_notice_link_href(&self) -> Option<&str>;
    fn response(&self) -> Response;
}

impl ResponseUtil for RdapResponse {
    fn status_code(&self) -> StatusCode {
        if let Self::ErrorResponse(rdap_error) = self {
            StatusCode::from_u16(rdap_error.error_code).unwrap()
        } else {
            StatusCode::OK
        }
    }

    fn first_notice_link_href(&self) -> Option<&str> {
        if let Self::ErrorResponse(rdap_error) = self {
            let href = rdap_error.exterr_location.as_ref()?;
            Some(href)
        } else {
            None
        }
    }

    fn response(&self) -> Response {
        let status_code = self.status_code();
        match status_code {
            StatusCode::MULTIPLE_CHOICES
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::USE_PROXY
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
            | StatusCode::NOT_MODIFIED => {
                let href = self.first_notice_link_href();
                if let Some(href) = href {
                    let headers: [(&str, &str); 2] = [RDAP_HEADERS[0], ("location", href)];
                    (status_code, headers, Json(self)).into_response()
                } else {
                    warn!("redirect does not have an href to use for location header.");
                    (status_code, RDAP_HEADERS, Json(self)).into_response()
                }
            }
            _ => (status_code, RDAP_HEADERS, Json(self)).into_response(),
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {

    use {
        axum::response::IntoResponse,
        http::StatusCode,
        icann_rdap_common::{
            prelude::ToResponse,
            response::{Domain, Rfc9083Error},
        },
    };

    use crate::rdap::response::{ResponseUtil, NOT_FOUND, NOT_IMPLEMENTED};

    #[test]
    fn GIVEN_non_error_WHEN_exec_response_THEN_status_code_is_200() {
        // GIVEN
        let domain = Domain::builder()
            .ldh_name("foo.example")
            .build()
            .to_response();

        // WHEN
        let actual = domain.response();

        // THEN
        assert_eq!(actual.into_response().status(), StatusCode::OK);
    }

    #[test]
    fn GIVEN_not_found_WHEN_exec_response_THEN_status_code_is_501() {
        // GIVEN

        // WHEN
        let actual = NOT_FOUND.response();

        // THEN
        assert_eq!(actual.into_response().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn GIVEN_not_implemented_WHEN_exec_response_THEN_status_code_is_500() {
        // GIVEN

        // WHEN
        let actual = NOT_IMPLEMENTED.response();

        // THEN
        assert_eq!(actual.into_response().status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn GIVEN_rdap_response_with_first_link_WHEN_get_first_link_href_THEN_href_returned() {
        // GIVEN
        let given = Rfc9083Error::redirect()
            .url("https://other.example.com")
            .build()
            .to_response();

        // WHEN
        let actual = given.first_notice_link_href();

        // THEN
        assert_eq!(actual.expect("no href"), "https://other.example.com");
    }
}
