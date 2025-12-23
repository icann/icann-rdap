use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use icann_rdap_client::{
    md::redacted::replace_redacted_items, rdap::redacted::simplify_redactions,
};

use {
    icann_rdap_client::{
        http::Client,
        rdap::{rdap_url_request, QueryType, ResponseData},
    },
    icann_rdap_common::{httpdata::HttpData, response::GetSelfLink},
    pct_str::{PctString, URIReserved},
    tracing::{debug, info},
};

use crate::{
    dirs::rdap_cache_path,
    error::RdapCliError,
    query::{ProcessingParams, RedactionFlag},
};

/// This function handles making requests and caching.
pub(crate) async fn do_request(
    base_url: &str,
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
) -> Result<ResponseData, RdapCliError> {
    if processing_params.no_cache {
        info!("Cache has been disabled.")
    }
    let query_url = query_type.query_url(base_url)?;
    if !processing_params.no_cache {
        let file_name = format!(
            "{}.cache",
            PctString::encode(query_url.chars(), URIReserved)
        );
        let path = rdap_cache_path().join(&file_name);
        if path.exists() {
            let input = File::open(path)?;
            let buf = BufReader::new(input);
            let mut lines = vec![];
            for line in buf.lines() {
                lines.push(line?)
            }
            let cache_data = HttpData::from_lines(&lines)?;
            if !cache_data
                .0
                .is_expired(processing_params.max_cache_age as i64)
            {
                debug!("Returning response from cache file {file_name}");
                let response: ResponseData = serde_json::from_str(&cache_data.1.join(""))?;
                return Ok(response);
            }
        }
    }
    let response = rdap_url_request(&query_url, client).await?;
    if !processing_params.no_cache {
        if response.http_data.should_cache() {
            let data = serde_json::to_string_pretty(&response)?;
            let cache_contents = response.http_data.to_lines(&data)?;
            let query_url = query_type.query_url(base_url)?;
            let file_name = format!(
                "{}.cache",
                PctString::encode(query_url.chars(), URIReserved)
            );
            debug!("Saving query response to cache file {file_name}");
            let path = rdap_cache_path().join(file_name);
            fs::write(path, &cache_contents)?;
            if let Some(self_link) = response.rdap.get_self_link() {
                if let Some(self_link_href) = &self_link.href {
                    if query_url != *self_link_href {
                        let file_name = format!(
                            "{}.cache",
                            PctString::encode(self_link_href.chars(), URIReserved)
                        );
                        debug!("Saving object with self link to cache file {file_name}");
                        let path = rdap_cache_path().join(file_name);
                        fs::write(path, &cache_contents)?;
                    }
                }
            }
        } else {
            debug!("Not caching data according to server policy.");
            debug!("Expires header: {:?}", &response.http_data.expires);
            debug!(
                "Cache-control header: {:?}",
                &response.http_data.cache_control
            );
        }
    }
    Ok(response)
}

/// This function issues request and does processing on the responses.
pub(crate) async fn request_and_process(
    base_url: &str,
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
) -> Result<ResponseData, RdapCliError> {
    let response = do_request(base_url, query_type, processing_params, client).await;
    if let Ok(response) = response {
        let rdap = if processing_params
            .redaction_flags
            .contains(RedactionFlag::DoRfc9537Redactions)
        {
            replace_redacted_items(response.rdap.clone())
        } else {
            response.rdap.clone()
        };
        let rdap = if !processing_params
            .redaction_flags
            .contains(RedactionFlag::DoNotSimplifyRfc9537)
        {
            simplify_redactions(rdap, false)
        } else {
            rdap
        };
        let response = ResponseData {
            rdap,
            // copy other fields from `response`
            ..response.clone()
        };
        Ok(response)
    } else {
        response
    }
}
