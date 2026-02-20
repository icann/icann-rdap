use http::HeaderMap;
use icann_rdap_common::prelude::normalize_extensions;
use serde::Deserialize;
use std::net::IpAddr;
use tracing::debug;

use axum::{
    extract::{Query, State},
    response::Response,
};

use crate::{
    error::RdapServerError,
    rdap::{
        jscontact_conversion, parse_extensions,
        response::{ResponseUtil, BAD_REQUEST},
    },
    server::DynServiceState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct NameserversParams {
    name: Option<String>,
    ip: Option<String>,
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn nameservers(
    Query(params): Query<NameserversParams>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    Ok(if let Some(name) = params.name {
        let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
        debug!("exts_list = \'{}\'", exts_list.join(" "));

        let storage = state.get_storage().await?;
        let results = storage.search_nameservers_by_name(&name).await?;
        let results = jscontact_conversion(results, state.get_jscontact_conversion(), &exts_list);
        let results = normalize_extensions(results);
        results.response()
    } else if let Some(ip_str) = params.ip {
        let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
        debug!("exts_list = \'{}\'", exts_list.join(" "));

        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return Ok(BAD_REQUEST.response()),
        };

        let storage = state.get_storage().await?;
        let results = storage.search_nameservers_by_ip(ip).await?;
        let results = jscontact_conversion(results, state.get_jscontact_conversion(), &exts_list);
        let results = normalize_extensions(results);
        results.response()
    } else {
        super::response::NOT_IMPLEMENTED.response()
    })
}

#[cfg(test)]
mod tests {

    use {axum::response::IntoResponse, http::StatusCode};

    use crate::rdap::response::{ResponseUtil, BAD_REQUEST};

    #[test]
    fn test_invalid_ip_parse() {
        let ip_str = "not_an_ip";
        let ip_result: Result<std::net::IpAddr, _> = ip_str.parse();
        assert!(ip_result.is_err());
    }

    #[test]
    fn test_valid_ipv4_parse() {
        let ip_str = "192.0.2.1";
        let ip_result: Result<std::net::IpAddr, _> = ip_str.parse();
        assert!(ip_result.is_ok());
        assert!(ip_result.unwrap().is_ipv4());
    }

    #[test]
    fn test_valid_ipv6_parse() {
        let ip_str = "2001:db8::1";
        let ip_result: Result<std::net::IpAddr, _> = ip_str.parse();
        assert!(ip_result.is_ok());
        assert!(ip_result.unwrap().is_ipv6());
    }

    #[test]
    fn test_bad_request_status() {
        let response = BAD_REQUEST.response();
        assert_eq!(response.into_response().status(), StatusCode::BAD_REQUEST);
    }
}
