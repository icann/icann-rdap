use icann_rdap_common::{cache::HttpData, response::RdapResponse};
use reqwest::{
    header::{CACHE_CONTROL, CONTENT_TYPE, EXPIRES},
    Client,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::RdapClientError;

use super::qtype::QueryType;

pub async fn rdap_request(
    base_url: &str,
    query_type: &QueryType,
    client: &Client,
) -> Result<ResponseData, RdapClientError> {
    let url = query_type.query_url(base_url)?;
    let response = client.get(url).send().await?.error_for_status()?;
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|value| value.to_str().unwrap().to_string());
    let expires = response
        .headers()
        .get(EXPIRES)
        .map(|value| value.to_str().unwrap().to_string());
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .map(|value| value.to_str().unwrap().to_string());
    let content_length = response.content_length();
    let url = response.url().to_owned();
    let text = response.text().await?;
    let json: Result<Value, serde_json::Error> = serde_json::from_str(&text);
    if let Ok(rdap_json) = json {
        let rdap = RdapResponse::try_from(rdap_json)?;
        let http_data = HttpData::now()
            .and_content_length(content_length)
            .and_content_type(content_type)
            .host(
                url.host_str()
                    .expect("URL has no host. This shouldn't happen.")
                    .to_owned(),
            )
            .and_expires(expires)
            .and_cache_control(cache_control)
            .build();
        Ok(ResponseData {
            http_data,
            rdap_type: rdap.to_string(),
            rdap,
        })
    } else {
        Err(RdapClientError::ParsingError(Box::new(
            crate::ParsingErrorInfo {
                text,
                content_length,
                content_type,
                url,
                error: json.err().unwrap(),
            },
        )))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResponseData {
    pub rdap: RdapResponse,
    pub rdap_type: String,
    pub http_data: HttpData,
}
