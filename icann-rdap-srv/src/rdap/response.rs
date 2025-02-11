use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use icann_rdap_common::{
    media_types::RDAP_MEDIA_TYPE,
    response::{RdapResponse, Rfc9083Error},
};
use lazy_static::lazy_static;
use tracing::warn;

lazy_static! {
    pub static ref NOT_FOUND: RdapResponse =
        RdapResponse::ErrorResponse(Rfc9083Error::basic().error_code(404).build());
    pub static ref NOT_IMPLEMENTED: RdapResponse =
        RdapResponse::ErrorResponse(Rfc9083Error::basic().error_code(501).build());
    pub static ref BAD_REQUEST: RdapResponse =
        RdapResponse::ErrorResponse(Rfc9083Error::basic().error_code(400).build());
}

pub(crate) const RDAP_HEADERS: [(&str, &str); 1] = [("content-type", RDAP_MEDIA_TYPE)];

pub(crate) trait ResponseUtil {
    fn status_code(&self) -> StatusCode;
    fn first_notice_link_href(&self) -> Option<&str>;
    fn response(&self) -> Response;
}

impl ResponseUtil for RdapResponse {
    fn status_code(&self) -> StatusCode {
        if let RdapResponse::ErrorResponse(rdap_error) = self {
            StatusCode::from_u16(rdap_error.error_code).unwrap()
        } else {
            StatusCode::OK
        }
    }

    fn first_notice_link_href(&self) -> Option<&str> {
        if let RdapResponse::ErrorResponse(rdap_error) = self {
            let notices = rdap_error.common.notices.as_ref()?;
            let first_notice = notices.first()?;
            let links = first_notice.0.links.as_ref()?;
            let first_link = links.first()?;
            let href = first_link.href.as_ref()?;
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

    use axum::response::IntoResponse;
    use http::StatusCode;
    use icann_rdap_common::response::{
        Domain, RdapResponse, Rfc9083Error, {Link, Notice, NoticeOrRemark},
    };

    use crate::rdap::response::{ResponseUtil, NOT_FOUND, NOT_IMPLEMENTED};

    #[test]
    fn GIVEN_non_error_WHEN_exec_response_THEN_status_code_is_200() {
        // GIVEN
        let domain = RdapResponse::Domain(Domain::builder().ldh_name("foo.example").build());

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
        let given = RdapResponse::ErrorResponse(
            Rfc9083Error::basic()
                .error_code(307)
                .notice(Notice(
                    NoticeOrRemark::builder()
                        .links(vec![Link::builder()
                            .href("https://other.example.com")
                            .value("https://other.example.com")
                            .rel("related")
                            .build()])
                        .build(),
                ))
                .build(),
        );

        // WHEN
        let actual = given.first_notice_link_href();

        // THEN
        assert_eq!(actual.expect("no href"), "https://other.example.com");
    }
}
