use std::sync::Arc;

use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use icann_rdap_common::{
    media_types::RDAP_MEDIA_TYPE,
    response::{
        autnum::Autnum,
        domain::Domain,
        entity::Entity,
        error::Error,
        help::Help,
        nameserver::Nameserver,
        network::Network,
        search::{DomainSearchResults, EntitySearchResults, NameserverSearchResults},
        types::Common,
        RdapResponse,
    },
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tracing::warn;

lazy_static! {
    pub static ref NOT_FOUND: RdapServerResponse =
        RdapServerResponse::Arc(ArcRdapResponse::ErrorResponse(Arc::new(
            Error::builder()
                .error_code(404)
                .common(Common::builder().build())
                .build()
        )));
    pub static ref NOT_IMPLEMENTED: RdapServerResponse =
        RdapServerResponse::Arc(ArcRdapResponse::ErrorResponse(Arc::new(
            Error::builder()
                .error_code(501)
                .common(Common::builder().build())
                .build()
        )));
    pub static ref BAD_REQUEST: RdapServerResponse =
        RdapServerResponse::Arc(ArcRdapResponse::ErrorResponse(Arc::new(
            Error::builder()
                .error_code(400)
                .common(Common::builder().build())
                .build()
        )));
}

pub(crate) const RDAP_HEADERS: [(&str, &str); 1] = [("content-type", RDAP_MEDIA_TYPE)];

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum RdapServerResponse {
    NoRef(RdapResponse),
    Arc(ArcRdapResponse),
}

impl RdapServerResponse {
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            RdapServerResponse::NoRef(rdap) => {
                if let RdapResponse::ErrorResponse(rdap_error) = rdap {
                    StatusCode::from_u16(rdap_error.error_code).unwrap()
                } else {
                    StatusCode::OK
                }
            }
            RdapServerResponse::Arc(rdap) => {
                if let ArcRdapResponse::ErrorResponse(rdap_error) = rdap {
                    StatusCode::from_u16(rdap_error.error_code).unwrap()
                } else {
                    StatusCode::OK
                }
            }
        }
    }

    pub(crate) fn first_notice_link_href(&self) -> Option<&str> {
        match self {
            RdapServerResponse::NoRef(rdap) => {
                if let RdapResponse::ErrorResponse(rdap_error) = rdap {
                    let Some(notices) = &rdap_error.common.notices else {return None};
                    let Some(first_notice) = notices.first() else {return None};
                    let Some(links) = &first_notice.0.links else {return None};
                    let Some(first_link) = links.first() else {return None};
                    Some(&first_link.href)
                } else {
                    None
                }
            }
            RdapServerResponse::Arc(rdap) => {
                if let ArcRdapResponse::ErrorResponse(rdap_error) = rdap {
                    let Some(notices) = &rdap_error.common.notices else {return None};
                    let Some(first_notice) = notices.first() else {return None};
                    let Some(links) = &first_notice.0.links else {return None};
                    let Some(first_link) = links.first() else {return None};
                    Some(&first_link.href)
                } else {
                    None
                }
            }
        }
    }

    pub(crate) fn response(&self) -> Response {
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

/// The various types of RDAP response.
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ArcRdapResponse {
    // Object Classes
    Entity(Arc<Entity>),
    Domain(Arc<Domain>),
    Nameserver(Arc<Nameserver>),
    Autnum(Arc<Autnum>),
    Network(Arc<Network>),

    // Search Results
    DomainSearchResults(Arc<DomainSearchResults>),
    EntitySearchResults(Arc<EntitySearchResults>),
    NameserverSearchResults(Arc<NameserverSearchResults>),

    // Error
    ErrorResponse(Arc<Error>),

    // Help
    Help(Arc<Help>),
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use std::sync::Arc;

    use axum::response::IntoResponse;
    use http::StatusCode;
    use icann_rdap_common::response::{
        domain::Domain,
        error::Error,
        types::{Link, Notice, NoticeOrRemark},
        RdapResponse,
    };

    use crate::rdap::response::{NOT_FOUND, NOT_IMPLEMENTED};

    use super::{ArcRdapResponse, RdapServerResponse};

    #[test]
    fn GIVEN_non_error_WHEN_exec_response_THEN_status_code_is_200() {
        // GIVEN
        let domain = RdapServerResponse::NoRef(RdapResponse::Domain(
            Domain::basic().ldh_name("foo.example").build(),
        ));

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
    fn GIVEN_arc_response_WHEN_serialized_THEN_properly_flattened() {
        // GIVEN
        let given = RdapServerResponse::Arc(ArcRdapResponse::ErrorResponse(Arc::new(
            Error::basic().error_code(501).build(),
        )));

        // WHEN
        let json = serde_json::to_string(&given).expect("serializing rdap error");

        // THEN
        assert_eq!(json, r#"{"errorCode":501}"#);
    }

    #[test]
    fn GIVEN_no_ref_response_WHEN_serialized_THEN_properly_flattened() {
        // GIVEN
        let given = RdapServerResponse::NoRef(RdapResponse::ErrorResponse(
            Error::basic().error_code(501).build(),
        ));

        // WHEN
        let json = serde_json::to_string(&given).expect("serializing rdap error");

        // THEN
        assert_eq!(json, r#"{"errorCode":501}"#);
    }

    #[test]
    fn GIVEN_arc_response_with_first_link_WHEN_get_first_link_href_THEN_href_returned() {
        // GIVEN
        let given = RdapServerResponse::Arc(ArcRdapResponse::ErrorResponse(Arc::new(
            Error::basic()
                .error_code(307)
                .notice(Notice(
                    NoticeOrRemark::builder()
                        .links(vec![Link::builder()
                            .href("https://other.example.com")
                            .build()])
                        .build(),
                ))
                .build(),
        )));

        // WHEN
        let actual = given.first_notice_link_href();

        // THEN
        assert_eq!(actual.expect("no href"), "https://other.example.com");
    }

    #[test]
    fn GIVEN_no_ref_response_with_first_link_WHEN_get_first_link_href_THEN_href_returned() {
        // GIVEN
        let given = RdapServerResponse::NoRef(RdapResponse::ErrorResponse(
            Error::basic()
                .error_code(307)
                .notice(Notice(
                    NoticeOrRemark::builder()
                        .links(vec![Link::builder()
                            .href("https://other.example.com")
                            .build()])
                        .build(),
                ))
                .build(),
        ));

        // WHEN
        let actual = given.first_notice_link_href();

        // THEN
        assert_eq!(actual.expect("no href"), "https://other.example.com");
    }
}
