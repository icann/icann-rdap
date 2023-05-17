use icann_rdap_common::check::Checks;
use serde::{Deserialize, Serialize};
use strum_macros::Display;

use crate::query::request::ResponseData;

#[derive(Serialize, Deserialize, Display, Clone, Copy)]
pub enum SourceType {
    #[strum(serialize = "Domain Registry")]
    DomainRegistry,
    #[strum(serialize = "Domain Registrar")]
    DomainRegistrar,
    #[strum(serialize = "Regional Internet Registry")]
    RegionalInternetRegistry,
    #[strum(serialize = "Local Internet Registry")]
    LocalInternetRegistry,
    #[strum(serialize = "Uncategorized Registry")]
    UncategorizedRegistry,
}

/// Represents meta data about the request.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct RequestData<'a> {
    /// The request number. That is, request 1, request 2, etc...
    pub req_number: usize,

    /// A human-friendly name to identify the source of the information.
    /// Examples might be "registry", "registrar", etc...
    pub source_host: &'a str,

    /// Represents the type of source.
    pub source_type: SourceType,
}

#[derive(Clone, Serialize)]
pub struct RequestResponse<'a> {
    pub req_data: &'a RequestData<'a>,
    pub res_data: &'a ResponseData,
    pub checks: Checks<'a>,
}

pub type RequestResponses<'a> = Vec<RequestResponse<'a>>;
