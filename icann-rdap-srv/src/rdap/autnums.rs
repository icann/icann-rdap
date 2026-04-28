use std::str::FromStr;

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
use tracing::debug;

use crate::{
    error::RdapServerError,
    rdap::{
        jscontact_conversion, parse_extensions,
        response::{ResponseUtil, BAD_REQUEST},
        ToBootStrap,
    },
    server::DynServiceState,
};

fn add_rfc9910_extensions(rdap: RdapResponse) -> RdapResponse {
    if matches!(
        rdap,
        RdapResponse::Autnum(_) | RdapResponse::AutnumSearchResults(_)
    ) {
        normalize_extensions_with(
            rdap,
            [ExtensionId::AutnumSearchResults, ExtensionId::RirSearch1],
        )
    } else {
        normalize_extensions(rdap)
    }
}

fn parse_as_path(as_path: &str) -> Result<(u32, Option<u32>), ()> {
    if let Some((start_str, end_str)) = as_path.split_once('-') {
        let start = u32::from_str(start_str).map_err(|_| ())?;
        let end = u32::from_str(end_str).map_err(|_| ())?;
        Ok((start, Some(end)))
    } else {
        let single = u32::from_str(as_path).map_err(|_| ())?;
        Ok((single, None))
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AutnumsParams {
    handle: Option<String>,
    name: Option<String>,
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn autnums(
    Query(params): Query<AutnumsParams>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = '{}'", exts_list.join(" "));

    let storage = state.get_storage().await?;
    let results = if let Some(handle) = params.handle {
        storage.search_autnums_by_handle(&handle).await?
    } else if let Some(name) = params.name {
        storage.search_autnums_by_name(&name).await?
    } else {
        return Ok(BAD_REQUEST.response());
    };

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
pub(crate) async fn autnum_rdap_up(
    Path(as_path): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-up for autnum {as_path}");
    let (start, end) = match parse_as_path(&as_path) {
        Ok(v) => v,
        Err(()) => return Ok(BAD_REQUEST.response()),
    };

    let results = if let Some(end) = end {
        storage.search_autnum_rdap_up_by_range(start, end).await?
    } else {
        storage.search_autnum_rdap_up_by_num(start).await?
    };

    if state.get_common_config().bootstrap {
        Ok(results.to_autnum_bootstrap(start).response())
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
pub(crate) async fn autnum_rdap_top(
    Path(as_path): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-top for autnum {as_path}");
    let (start, end) = match parse_as_path(&as_path) {
        Ok(v) => v,
        Err(()) => return Ok(BAD_REQUEST.response()),
    };

    let results = if let Some(end) = end {
        storage.search_autnum_rdap_top_by_range(start, end).await?
    } else {
        storage.search_autnum_rdap_top_by_num(start).await?
    };

    if state.get_common_config().bootstrap {
        Ok(results.to_autnum_bootstrap(start).response())
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
pub(crate) async fn autnum_rdap_down(
    Path(as_path): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-down for autnum {as_path}");
    let (start, end) = match parse_as_path(&as_path) {
        Ok(v) => v,
        Err(()) => return Ok(BAD_REQUEST.response()),
    };

    let results = if let Some(end) = end {
        storage.search_autnum_rdap_down_by_range(start, end).await?
    } else {
        storage.search_autnum_rdap_down_by_num(start).await?
    };

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
pub(crate) async fn autnum_rdap_bottom(
    Path(as_path): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    debug!("getting rdap-bottom for autnum {as_path}");
    let (start, end) = match parse_as_path(&as_path) {
        Ok(v) => v,
        Err(()) => return Ok(BAD_REQUEST.response()),
    };

    let results = if let Some(end) = end {
        storage
            .search_autnum_rdap_bottom_by_range(start, end)
            .await?
    } else {
        storage.search_autnum_rdap_bottom_by_num(start).await?
    };

    let results = jscontact_conversion(
        results,
        state.get_common_config().jscontact_conversion,
        &exts_list,
    );
    let results = add_rfc9910_extensions(results);
    Ok(results.response())
}
