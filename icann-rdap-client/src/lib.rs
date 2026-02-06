#![allow(dead_code)] // TODO remove this at some point
#![allow(rustdoc::bare_urls)]
#![doc = include_str!("../README.md")]
use std::{fmt::Display, sync::PoisonError};

use {
    iana::iana_request::IanaResponseError,
    icann_rdap_common::{
        dns_types::DomainNameError, httpdata::HttpData, iana::BootstrapRegistryError,
        response::RdapResponseError,
    },
    thiserror::Error,
};

pub mod gtld;
pub mod http;
pub mod iana;
pub mod md;
pub mod rdap;
pub mod rpsl;

/// Basics necesasry for a simple clients.
pub mod prelude {
    #[doc(inline)]
    pub use crate::http::create_client;
    #[doc(inline)]
    pub use crate::http::ClientConfig;
    #[doc(inline)]
    pub use crate::iana::MemoryBootstrapStore;
    #[doc(inline)]
    pub use crate::rdap::rdap_bootstrapped_request;
    #[doc(inline)]
    pub use crate::rdap::rdap_request;
    #[doc(inline)]
    pub use crate::rdap::rdap_url_request;
    #[doc(inline)]
    pub use crate::rdap::QueryType;
    #[doc(inline)]
    pub use crate::RdapClientError;
}

/// Error returned by RDAP client functions and methods.
#[derive(Error, Debug)]
pub enum RdapClientError {
    #[error("Query value is not valid.")]
    InvalidQueryValue,

    #[error("Ambiguous query type.")]
    AmbiguousQueryType,

    #[error(transparent)]
    Response(#[from] RdapResponseError),

    #[error(transparent)]
    Client(#[from] reqwest::Error),

    #[error("Error parsing response")]
    ParsingError(Box<ParsingErrorInfo>),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("RwLock Poison Error")]
    Poison,

    #[error("Bootstrap unavailable")]
    BootstrapUnavailable,

    #[error(transparent)]
    BootstrapError(#[from] BootstrapRegistryError),

    #[error(transparent)]
    IanaResponse(#[from] IanaResponseError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    DomainNameError(#[from] DomainNameError),
}

impl<T> From<PoisonError<T>> for RdapClientError {
    fn from(_err: PoisonError<T>) -> Self {
        Self::Poison
    }
}

/// Describes the error that occurs when parsing RDAP responses.
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
