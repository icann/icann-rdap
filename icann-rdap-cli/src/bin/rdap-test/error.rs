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
            RdapTestError::Success => 0,
            RdapTestError::TestsCompletedExecutionErrors => 1,
            RdapTestError::TestsCompletedWarningsFound => 2,
            RdapTestError::TestsCompletedErrorsFound => 3,

            // Internal Errors
            RdapTestError::Termimad(_) => 10,

            // I/O Errors
            RdapTestError::IoError(_) => 40,
            RdapTestError::TestExecutionError(_) => 40,

            // RDAP Errors
            RdapTestError::Json(_) => 100,
            RdapTestError::Iana(_) => 101,
            RdapTestError::InvalidBootstrap => 102,
            RdapTestError::BootstrapNotFound => 103,
            RdapTestError::NoRegistrarFound => 104,
            RdapTestError::NoRegistryFound => 105,

            // User Errors
            RdapTestError::UnknownOutputType => 200,

            // RDAP Client Errrors
            RdapTestError::RdapClient(e) => match e {
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
