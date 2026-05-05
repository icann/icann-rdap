use axum::{
    extract::{Path, Query, State},
    response::Response,
};

use http::HeaderMap;
use icann_rdap_common::{
    prelude::{normalize_extensions, normalize_extensions_with, ExtensionId},
    response::RdapResponse,
};
use serde::Deserialize;
use std::net::IpAddr;
use tracing::debug;

use crate::{
    error::RdapServerError,
    rdap::{jscontact_conversion, parse_extensions, response::ResponseUtil, ToBootStrap},
    server::DynServiceState,
};

use super::response::{BAD_REQUEST, NOT_IMPLEMENTED};

fn add_rfc9910_extensions(rdap: RdapResponse) -> RdapResponse {
    if matches!(rdap, RdapResponse::DomainSearchResults(_)) {
        normalize_extensions_with(rdap, [ExtensionId::RirSearch1])
    } else {
        normalize_extensions(rdap)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct DomainsParams {
    name: Option<String>,

    #[serde(rename = "nsLdhName")]
    ns_ldh_name: Option<String>,

    #[serde(rename = "nsIp")]
    ns_ip: Option<String>,
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn domains(
    Query(params): Query<DomainsParams>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    Ok(if let Some(name) = params.name {
        let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
        debug!("exts_list = \'{}\'", exts_list.join(" "));

        let storage = state.get_storage().await?;
        let results = storage.search_domains_by_name(&name).await?;
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = normalize_extensions(results);
        results.response()
    } else if let Some(ns_ldh_name) = params.ns_ldh_name {
        let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
        debug!("exts_list = \'{}\'", exts_list.join(" "));

        let storage = state.get_storage().await?;
        let results = storage.search_domains_by_ns_ldh_name(&ns_ldh_name).await?;
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = normalize_extensions(results);
        results.response()
    } else if let Some(ip_str) = params.ns_ip {
        let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
        debug!("exts_list = \'{}\'", exts_list.join(" "));

        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return Ok(BAD_REQUEST.response()),
        };

        let storage = state.get_storage().await?;
        let results = storage.search_domains_by_ns_ip(ip).await?;
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = normalize_extensions(results);
        results.response()
    } else {
        NOT_IMPLEMENTED.response()
    })
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn domain_rdap_up(
    Path(ldh_name): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-up for domain {ldh_name}");

    let results = storage.search_domain_rdap_up_by_ldh(&ldh_name).await?;

    if state.get_common_config().bootstrap {
        Ok(results.to_domain_bootstrap(&ldh_name).response())
    } else {
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = add_rfc9910_extensions(results);
        Ok(results.response())
    }
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn domain_rdap_top(
    Path(ldh_name): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-top for domain {ldh_name}");

    let results = storage.search_domain_rdap_top_by_ldh(&ldh_name).await?;

    if state.get_common_config().bootstrap {
        Ok(results.to_domain_bootstrap(&ldh_name).response())
    } else {
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = add_rfc9910_extensions(results);
        Ok(results.response())
    }
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn domain_rdap_down(
    Path(ldh_name): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-down for domain {ldh_name}");

    let results = storage.search_domain_rdap_down_by_ldh(&ldh_name).await?;

    let results = jscontact_conversion(
        results,
        state.get_common_config().jscontact_conversion,
        &exts_list,
    );
    let results = add_rfc9910_extensions(results);
    Ok(results.response())
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn domain_rdap_bottom(
    Path(ldh_name): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-bottom for domain {ldh_name}");

    let results = storage.search_domain_rdap_bottom_by_ldh(&ldh_name).await?;

    let results = jscontact_conversion(
        results,
        state.get_common_config().jscontact_conversion,
        &exts_list,
    );
    let results = add_rfc9910_extensions(results);
    Ok(results.response())
}
