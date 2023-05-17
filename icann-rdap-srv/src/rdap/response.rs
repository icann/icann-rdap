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

    pub(crate) fn response(&self) -> Response {
        let status_code = self.status_code();
        (status_code, RDAP_HEADERS, Json(self)).into_response()
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
    use icann_rdap_common::response::{domain::Domain, error::Error, RdapResponse};

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
}
