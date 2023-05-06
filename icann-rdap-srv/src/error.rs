use std::{num::ParseIntError, sync::Arc};

use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use icann_rdap_common::response::types::Common;
use thiserror::Error;

use crate::rdap::response::{ArcRdapResponse, RdapServerResponse};

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
}

impl IntoResponse for RdapServerError {
    fn into_response(self) -> Response {
        let response = RdapServerResponse::Arc(ArcRdapResponse::ErrorResponse(Arc::new(
            icann_rdap_common::response::error::Error::builder()
                .error_code(500)
                .common(Common::builder().build())
                .build(),
        )));
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", r#"application/rdap"#)],
            Json(response),
        )
            .into_response()
    }
}
