use std::process::{ExitCode, Termination};

use icann_rdap_client::iana_request::IanaResponseError;
use icann_rdap_client::RdapClientError;
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
    #[error("No registry found")]
    NoRegistryFound,
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

            // RDAP Errors
            CliError::Json(_) => 100,
            CliError::Iana(_) => 101,
            CliError::InvalidBootstrap => 102,
            CliError::BootstrapNotFound => 103,
            CliError::NoRegistrarFound => 104,
            CliError::NoRegistryFound => 105,

            // User Errors
            CliError::UnknownOutputType => 200,
            CliError::ErrorOnChecks => 201,

            // RDAP Client Errrors
            CliError::RdapClient(e) => match e {
                // I/O Errors
                RdapClientError::Client(_) => 41,
                RdapClientError::IoError(_) => 42,

                // RDAP Server Errors
                RdapClientError::Response(_) => 60,
                RdapClientError::ParsingError(_) => 62,
                RdapClientError::Json(_) => 63,

                // Bootstrap Errors
                RdapClientError::BootstrapUnavailable => 70,
                RdapClientError::BootstrapError(_) => 71,
                RdapClientError::IanaResponse(_) => 72,

                // User Errors
                RdapClientError::InvalidQueryValue => 202,
                RdapClientError::AmbiquousQueryType => 203,
                RdapClientError::DomainNameError(_) => 204,

                // Internal Errors
                RdapClientError::Poison => 250,
                // _ => 255,
            },
        };
        ExitCode::from(exit_code)
    }
}
