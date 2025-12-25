//! Structures that describe a request/response.

use serde::{Deserialize, Serialize};

use crate::rdap::request::ResponseData;

/// Represents meta data about the request.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct RequestData {
    /// The request number. That is, request 1, request 2, etc...
    pub req_number: usize,

    /// False if the request does target the information being sought.
    ///
    /// In many RDAP scenarios, an RDAP server must be queried to get
    /// a referral to the target server containing the information being sought
    /// by the user. This data can be used when determing thing such
    /// as what data to output, etc...
    pub req_target: bool,
}

/// The primary purpose for this struct is to allow deserialization for testing.
#[derive(Clone, Deserialize, Serialize)]
pub struct RequestResponse {
    pub req_data: RequestData,
    pub res_data: ResponseData,
}
