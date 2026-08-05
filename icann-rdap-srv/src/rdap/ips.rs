use std::net::IpAddr;

use ipnet::IpNet;

use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use http::HeaderMap;
use icann_rdap_common::{
    prelude::{ExtensionId, normalize_extensions, normalize_extensions_with},
    response::RdapResponse,
};
use serde::Deserialize;
use tracing::debug;

use crate::{
    error::RdapServerError,
    rdap::{
        ToBootStrap, jscontact_conversion,
        response::{BAD_REQUEST, ResponseUtil},
    },
    server::DynServiceState,
};

#[derive(Debug, Deserialize)]
pub(crate) struct IpsParams {
    handle: Option<String>,
    name: Option<String>,
}

fn add_rfc9910_extensions(rdap: RdapResponse) -> RdapResponse {
    if matches!(rdap, RdapResponse::Network(_)) || matches!(rdap, RdapResponse::IpSearchResults(_))
    {
        normalize_extensions_with(rdap, [ExtensionId::Ips, ExtensionId::RirSearch1])
    } else {
        normalize_extensions(rdap)
    }
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn ip_rdap_up(
    Path(ip_or_cidr): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = super::parse_exts_list_from_headers(&headers);

    let storage = state.get_storage().await?;

    if ip_or_cidr.contains('/') {
        debug!("getting rdap-up for cidr {ip_or_cidr}");
        let net: Result<IpNet, _> = ip_or_cidr.parse();
        if net.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let network = storage.search_ip_rdap_up_by_cidr(&ip_or_cidr).await?;
        if state.get_common_config().bootstrap {
            Ok(network.to_ip_bootstrap(&ip_or_cidr).response())
        } else {
            let network = jscontact_conversion(
                network,
                state.get_common_config().jscontact_conversion,
                &exts_list,
            );
            let network = add_rfc9910_extensions(network);
            Ok(network.response())
        }
    } else {
        debug!("getting rdap-up for ip address {ip_or_cidr}");
        let ip: Result<IpAddr, _> = ip_or_cidr.parse();
        if ip.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let network = storage.search_ip_rdap_up_by_ipaddr(&ip_or_cidr).await?;
        if state.get_common_config().bootstrap {
            Ok(network.to_ip_bootstrap(&ip_or_cidr).response())
        } else {
            let network = jscontact_conversion(
                network,
                state.get_common_config().jscontact_conversion,
                &exts_list,
            );
            let network = add_rfc9910_extensions(network);
            Ok(network.response())
        }
    }
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn ip_rdap_top(
    Path(ip_or_cidr): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = super::parse_exts_list_from_headers(&headers);

    let storage = state.get_storage().await?;

    if ip_or_cidr.contains('/') {
        debug!("getting rdap-top for cidr {ip_or_cidr}");
        let net: Result<IpNet, _> = ip_or_cidr.parse();
        if net.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let network = storage.search_ip_rdap_top_by_cidr(&ip_or_cidr).await?;
        if state.get_common_config().bootstrap {
            Ok(network.to_ip_bootstrap(&ip_or_cidr).response())
        } else {
            let network = jscontact_conversion(
                network,
                state.get_common_config().jscontact_conversion,
                &exts_list,
            );
            let network = add_rfc9910_extensions(network);
            Ok(network.response())
        }
    } else {
        debug!("getting rdap-top for ip address {ip_or_cidr}");
        let ip: Result<IpAddr, _> = ip_or_cidr.parse();
        if ip.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let network = storage.search_ip_rdap_top_by_ipaddr(&ip_or_cidr).await?;
        if state.get_common_config().bootstrap {
            Ok(network.to_ip_bootstrap(&ip_or_cidr).response())
        } else {
            let network = jscontact_conversion(
                network,
                state.get_common_config().jscontact_conversion,
                &exts_list,
            );
            let network = add_rfc9910_extensions(network);
            Ok(network.response())
        }
    }
}

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn ip_rdap_down(
    Path(ip_or_cidr): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = super::parse_exts_list_from_headers(&headers);

    let storage = state.get_storage().await?;

    if ip_or_cidr.contains('/') {
        debug!("getting rdap-down for cidr {ip_or_cidr}");
        let net: Result<IpNet, _> = ip_or_cidr.parse();
        if net.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let results = storage.search_ip_rdap_down_by_cidr(&ip_or_cidr).await?;
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = add_rfc9910_extensions(results);
        Ok(results.response())
    } else {
        debug!("getting rdap-down for ip address {ip_or_cidr}");
        let ip: Result<IpAddr, _> = ip_or_cidr.parse();
        if ip.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let results = storage.search_ip_rdap_down_by_ipaddr(&ip_or_cidr).await?;
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
pub(crate) async fn ip_rdap_bottom(
    Path(ip_or_cidr): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = super::parse_exts_list_from_headers(&headers);

    let storage = state.get_storage().await?;

    if ip_or_cidr.contains('/') {
        debug!("getting rdap-bottom for cidr {ip_or_cidr}");
        let net: Result<IpNet, _> = ip_or_cidr.parse();
        if net.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let results = storage.search_ip_rdap_bottom_by_cidr(&ip_or_cidr).await?;
        let results = jscontact_conversion(
            results,
            state.get_common_config().jscontact_conversion,
            &exts_list,
        );
        let results = add_rfc9910_extensions(results);
        Ok(results.response())
    } else {
        debug!("getting rdap-bottom for ip address {ip_or_cidr}");
        let ip: Result<IpAddr, _> = ip_or_cidr.parse();
        if ip.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let results = storage.search_ip_rdap_bottom_by_ipaddr(&ip_or_cidr).await?;
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
pub(crate) async fn networks(
    Query(params): Query<IpsParams>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = super::parse_exts_list_from_headers(&headers);

    let storage = state.get_storage().await?;
    let results = if let Some(handle) = params.handle {
        storage.search_networks_by_handle(&handle).await?
    } else if let Some(name) = params.name {
        storage.search_networks_by_name(&name).await?
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
