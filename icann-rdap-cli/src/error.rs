use std::process::{ExitCode, Termination};

use icann_rdap_client::RdapClientError;
use icann_rdap_common::iana::IanaResponseError;
use minus::MinusError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("No errors encountered")]
    Success,
    #[error(transparent)]
    RdapClient(#[from] RdapClientError),
    #[error(transparent)]
    Termimad(#[from] termimad::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    Minus(#[from] MinusError),
    #[error("Unknown output type")]
    UnknownOutputType,
    #[error("RDAP response failed checks.")]
    ErrorOnChecks,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Iana(#[from] IanaResponseError),
    #[error("Invalid IANA bootsrap file")]
    InvalidBootstrap,
    #[error("Bootstrap not found")]
    BootstrapNotFound,
    #[error("No registrar found")]
    NoRegistrarFound,
}

impl Termination for CliError {
    fn report(self) -> std::process::ExitCode {
        let exit_code: u8 = match self {
            // Success
            CliError::Success => 0,

            // Internal Errors
            CliError::Termimad(_) => 10,
            CliError::Minus(_) => 11,

            // I/O Errors
            CliError::IoError(_) => 40,
            CliError::RdapClient(_) => 41,

            // RDAP Errors
            CliError::Json(_) => 100,
            CliError::Iana(_) => 101,
            CliError::InvalidBootstrap => 102,
            CliError::BootstrapNotFound => 103,
            CliError::NoRegistrarFound => 104,

            // User Errors
            CliError::UnknownOutputType => 200,
            CliError::ErrorOnChecks => 201,
        };
        ExitCode::from(exit_code)
    }
}
