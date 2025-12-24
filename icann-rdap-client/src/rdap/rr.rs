//! Structures that describe a request/response.

use serde::{Deserialize, Serialize};

use crate::rdap::request::ResponseData;

/// Represents meta data about the request.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct RequestData<'a> {
    /// The request number. That is, request 1, request 2, etc...
    pub req_number: usize,

    /// False if the request does target the information being sought.
    ///
    /// In many RDAP scenarios, an RDAP server must be queried to get
    /// a referral to the target server containing the information being sought
    /// by the user. This data can be used when determing thing such
    /// as what data to output, etc...
    pub req_target: bool,

    /// A human-friendly name to identify the source of the information.
    /// Examples might be "registry", "registrar", etc...
    pub source_host: &'a str,
}

/// Structure for serializing request and response data.
#[derive(Clone, Serialize)]
pub struct RequestResponse<'a> {
    pub req_data: &'a RequestData<'a>,
    pub res_data: &'a ResponseData,
}

/// The primary purpose for this struct is to allow deserialization for testing.
/// If somebody can help get #[serde(borrow)] to work for the non-owned version,
/// that would be awesome.
#[derive(Clone, Deserialize)]
pub struct RequestResponseOwned<'a> {
    #[serde(borrow)]
    pub req_data: RequestData<'a>,
    pub res_data: ResponseData,
}

/// A [Vec] of [RequestResponse].
pub type RequestResponses<'a> = Vec<RequestResponse<'a>>;
