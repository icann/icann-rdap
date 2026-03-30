use std::net::IpAddr;

use axum::{
    extract::{Path, State},
    response::Response,
};
use http::HeaderMap;
use icann_rdap_common::prelude::normalize_extensions;
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

#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn ip_rdap_up(
    Path(ip_or_cidr): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let storage = state.get_storage().await?;

    if ip_or_cidr.contains('/') {
        debug!("getting rdap-up for cidr {ip_or_cidr}");
        let ip: Result<IpAddr, _> = ip_or_cidr.parse();
        if ip.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let network = storage.search_ip_rdap_up_by_cidr(&ip_or_cidr).await?;
        if state.get_bootstrap() {
            Ok(network.to_ip_bootstrap(&ip_or_cidr).response())
        } else {
            let network =
                jscontact_conversion(network, state.get_jscontact_conversion(), &exts_list);
            let network = normalize_extensions(network);
            Ok(network.response())
        }
    } else {
        debug!("getting rdap-up for ip address {ip_or_cidr}");
        let ip: Result<IpAddr, _> = ip_or_cidr.parse();
        if ip.is_err() {
            return Ok(BAD_REQUEST.response());
        }
        let network = storage.search_ip_rdap_up_by_ipaddr(&ip_or_cidr).await?;
        if state.get_bootstrap() {
            Ok(network.to_ip_bootstrap(&ip_or_cidr).response())
        } else {
            let network =
                jscontact_conversion(network, state.get_jscontact_conversion(), &exts_list);
            let network = normalize_extensions(network);
            Ok(network.response())
        }
    }
}
