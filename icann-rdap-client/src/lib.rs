#![allow(dead_code)] // TODO remove this at some point
#![allow(rustdoc::bare_urls)]
#![doc = include_str!("../README.md")]
use std::fmt::Display;

use icann_rdap_common::{cache::HttpData, response::RdapResponseError};
use reqwest::Url;
use thiserror::Error;

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
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct ParsingErrorInfo {
    pub text: String,
    pub http_data: HttpData,
    pub error: serde_json::Error,
}

impl Display for ParsingErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error: {}\n,Content Length: {}\nContent Type: {}\nUrl: {}\nText:\n{}\n",
            self.error,
            self.http_data
                .content_length
                .map_or("No content length given".to_string(), |n| n.to_string()),
            self.http_data
                .content_type
                .clone()
                .unwrap_or("No content type given".to_string()),
            self.http_data.host,
            self.text
        )
    }
}
