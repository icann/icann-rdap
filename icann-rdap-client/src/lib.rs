use icann_rdap_common::response::RdapResponseError;
use thiserror::Error;

pub mod check;
pub mod client;
pub mod md;
pub mod query;

#[derive(Error, Debug)]
pub enum RdapClientError {
    #[error("Query value is not valid.")]
    InvalidQueryValue,
    #[error("Ambiquous query type.")]
    AmbiquousQueryType,
    #[error(transparent)]
    Response(#[from] RdapResponseError),
    #[error(transparent)]
    Client(#[from] reqwest::Error),
}
