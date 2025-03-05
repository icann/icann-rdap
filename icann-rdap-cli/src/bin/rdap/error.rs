use std::process::{ExitCode, Termination};

use icann_rdap_client::iana::IanaResponseError;
use icann_rdap_client::RdapClientError;
use minus::MinusError;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum RdapCliError {
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

impl RdapCliError {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            // Success
            RdapCliError::Success => 0,

            // Internal Errors
            RdapCliError::Termimad(_) => 10,
            RdapCliError::Minus(_) => 11,

            // I/O Errors
            RdapCliError::IoError(_) => 40,

            // RDAP Errors
            RdapCliError::Json(_) => 100,
            RdapCliError::Iana(_) => 101,
            RdapCliError::InvalidBootstrap => 102,
            RdapCliError::BootstrapNotFound => 103,
            RdapCliError::NoRegistrarFound => 104,
            RdapCliError::NoRegistryFound => 105,

            // User Errors
            RdapCliError::UnknownOutputType => 200,
            RdapCliError::ErrorOnChecks => 201,

            // RDAP Client Errrors
            RdapCliError::RdapClient(e) => match e {
                // I/O Errors
                RdapClientError::Client(ce) => {
                    if ce.is_builder() {
                        match ce.url() {
                            Some(url) if url.scheme() == "http" => 202,
                            _ => 42,
                        }
                    } else {
                        42
                    }
                }
                RdapClientError::IoError(_) => 43,

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
        }
    }
}

impl Termination for RdapCliError {
    fn report(self) -> std::process::ExitCode {
        let exit_code = self.exit_code();
        ExitCode::from(exit_code)
    }
}
