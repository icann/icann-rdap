use std::fmt::Display;

use icann_rdap_common::response::RdapResponseError;
use reqwest::Url;
use thiserror::Error;

pub mod check;
pub mod client;
pub mod md;
pub mod query;
pub mod request;

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
    #[error("Error parsing response")]
    ParsingError(Box<ParsingErrorInfo>),
}

#[derive(Debug)]
pub struct ParsingErrorInfo {
    pub text: String,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub url: Url,
    pub error: serde_json::Error,
}

impl Display for ParsingErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error: {}\n,Content Length: {}\nContent Type: {}\nUrl: {}\nText:\n{}\n",
            self.error,
            self.content_length
                .map_or("No content length given".to_string(), |n| n.to_string()),
            self.content_type
                .clone()
                .unwrap_or("No content type given".to_string()),
            self.url,
            self.text
        )
    }
}
