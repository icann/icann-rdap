use std::{net::AddrParseError, num::ParseIntError};

use axum::{
    response::{IntoResponse, Response},
    Json,
};
use envmnt::errors::EnvmntError;
use http::StatusCode;
use icann_rdap_client::{iana::IanaResponseError, RdapClientError};
use icann_rdap_common::response::{Common, RdapResponse, RdapResponseError, Rfc9083Error};
use ipnet::PrefixLenError;
use thiserror::Error;

/// Errors from the RDAP Server.
#[derive(Debug, Error)]
pub enum RdapServerError {
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    EnvVar(#[from] std::env::VarError),
    #[error(transparent)]
    IntEnvVar(#[from] ParseIntError),
    #[error["configuration error: {0}"]]
    Config(String),
    #[error(transparent)]
    SqlDb(#[from] sqlx::Error),
    #[error("index data for {0} is missing or empty")]
    EmptyIndexData(String),
    #[error("file at {0} is not JSON")]
    NonJsonFile(String),
    #[error("json file at {0} is valid JSON but is not RDAP")]
    NonRdapJsonFile(String),
    #[error(transparent)]
    AddrParse(#[from] AddrParseError),
    #[error(transparent)]
    PrefixLength(#[from] PrefixLenError),
    #[error(transparent)]
    CidrParse(#[from] ipnet::AddrParseError),
    #[error("RDAP objects do not pass checks.")]
    ErrorOnChecks,
    #[error(transparent)]
    Envmnt(#[from] EnvmntError),
    #[error("Argument parsing error: {0}")]
    ArgParse(String),
    #[error("Invalid argument error: {0}")]
    InvalidArg(String),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    Response(#[from] RdapResponseError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Iana(#[from] IanaResponseError),
    #[error("Bootstrap error: {0}")]
    Bootstrap(String),
    #[error(transparent)]
    RdapClientError(#[from] RdapClientError),
}

impl IntoResponse for RdapServerError {
    fn into_response(self) -> Response {
        let response = RdapResponse::ErrorResponse(
            Rfc9083Error::builder()
                .error_code(500)
                .common(Common::builder().build())
                .build(),
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", r#"application/rdap"#)],
            Json(response),
        )
            .into_response()
    }
}
