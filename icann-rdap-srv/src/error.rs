use std::num::ParseIntError;

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
}
