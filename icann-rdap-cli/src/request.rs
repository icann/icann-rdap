use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
};

use icann_rdap_client::{
    cache::CacheData,
    query::{
        qtype::QueryType,
        request::{rdap_request, ResponseData},
    },
};
use pct_str::PctString;
use pct_str::URIReserved;
use reqwest::Client;
use simplelog::{debug, info};

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
    if !processing_params.no_cache {
        let query_url = query_type.query_url(base_url)?;
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
            let cache_data = CacheData::from_lines(&lines)?;
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
    let response = rdap_request(base_url, query_type, client).await?;
    if !processing_params.no_cache {
        if let Some(self_link) = response.rdap.get_self_link() {
            let cache_data = CacheData::now()
                .host(response.host.to_owned())
                .and_content_length(response.content_length)
                .and_expires(response.expires.to_owned())
                .and_cache_control(response.cache_control.to_owned())
                .and_content_type(response.content_type.to_owned())
                .build();
            if cache_data.should_cache() {
                let data = serde_json::to_string_pretty(&response)?;
                let cache_contents = cache_data.to_lines(&data)?;
                let query_url = query_type.query_url(base_url)?;
                let file_name = format!(
                    "{}.cache",
                    PctString::encode(query_url.chars(), URIReserved)
                );
                debug!("Saving response to cache file {file_name}");
                let path = rdap_cache_path().join(file_name);
                fs::write(path, &cache_contents)?;
                if query_url != self_link.href {
                    let file_name = format!(
                        "{}.cache",
                        PctString::encode(self_link.href.chars(), URIReserved)
                    );
                    debug!("Saving response to cache file {file_name}");
                    let path = rdap_cache_path().join(file_name);
                    fs::write(path, &cache_contents)?;
                }
            }
        }
    }
    Ok(response)
}
