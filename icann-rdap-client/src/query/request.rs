use icann_rdap_common::response::RdapResponse;
use reqwest::Client;
use serde_json::Value;

use crate::RdapClientError;

use super::qtype::QueryType;

pub async fn rdap_request(
    base_url: &str,
    query_type: &QueryType,
    client: &Client,
) -> Result<RdapResponse, RdapClientError> {
    let url = query_type.query_url(base_url)?;
    let result: Value = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let rdap_response = RdapResponse::try_from(result)?;
    Ok(rdap_response)
}
