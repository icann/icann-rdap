use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use icann_rdap_client::query::{
    qtype::QueryType,
    request::{rdap_url_request, ResponseData},
};
use icann_rdap_common::{cache::HttpData, response::GetSelfLink};
use pct_str::PctString;
use pct_str::URIReserved;
use reqwest::Client;
use tracing::{debug, info};

use crate::{dirs::rdap_cache_path, error::CliError, query::ProcessingParams};

pub(crate) async fn do_request(
    base_url: &str,
    query_type: &QueryType,
    processing_params: &ProcessingParams,
    client: &Client,
) -> Result<ResponseData, CliError> {
    if processing_params.no_cache {
        info!("Cache has been disabled.")
    }
    let query_url = query_type.query_url(base_url)?;
    debug!("Requesting RDAP URL {query_url}");
    if !processing_params.no_cache {
        let file_name = format!(
            "{}.cache",
            PctString::encode(query_url.chars(), URIReserved)
        );
        let path = rdap_cache_path().join(&file_name);
        if path.exists() {
            let input = File::open(path)?;
            let buf = BufReader::new(input);
            let mut lines = Vec::new();
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
