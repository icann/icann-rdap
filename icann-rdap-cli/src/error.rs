use icann_rdap_client::RdapClientError;
use icann_rdap_common::iana::IanaResponseError;
use minus::MinusError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
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
}
