use std::process::{ExitCode, Termination};

use icann_rdap_cli::rt::exec::TestExecutionError;
use icann_rdap_client::iana::IanaResponseError;
use icann_rdap_client::RdapClientError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RdapTestError {
    #[error("No errors encountered")]
    Success,
    #[error("Tests completed with execution errors.")]
    TestsCompletedExecutionErrors,
    #[error("Tests completed, warning checks found.")]
    TestsCompletedWarningsFound,
    #[error("Tests completed, error checks found.")]
    TestsCompletedErrorsFound,
    #[error(transparent)]
    RdapClient(#[from] RdapClientError),
    #[error(transparent)]
    TestExecutionError(#[from] TestExecutionError),
    #[error(transparent)]
    Termimad(#[from] termimad::Error),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Unknown output type")]
    UnknownOutputType,
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

impl Termination for RdapTestError {
    fn report(self) -> std::process::ExitCode {
        let exit_code: u8 = match self {
            // Success
            Self::Success => 0,
            Self::TestsCompletedExecutionErrors => 1,
            Self::TestsCompletedWarningsFound => 2,
            Self::TestsCompletedErrorsFound => 3,

            // Internal Errors
            Self::Termimad(_) => 10,

            // I/O Errors
            Self::IoError(_) => 40,
            Self::TestExecutionError(_) => 40,

            // RDAP Errors
            Self::Json(_) => 100,
            Self::Iana(_) => 101,
            Self::InvalidBootstrap => 102,
            Self::BootstrapNotFound => 103,
            Self::NoRegistrarFound => 104,
            Self::NoRegistryFound => 105,

            // User Errors
            Self::UnknownOutputType => 200,

            // RDAP Client Errrors
            Self::RdapClient(e) => match e {
                // I/O Errors
                RdapClientError::Client(_) => 42,
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
        };
        ExitCode::from(exit_code)
    }
}
