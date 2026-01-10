use std::{net::IpAddr, str::FromStr};

use http::HeaderMap;
use icann_rdap_common::prelude::normalize_extensions;

use {
    axum::{
        extract::{Path, State},
        response::Response,
    },
    cidr::IpInet,
    tracing::debug,
};

use crate::{
    error::RdapServerError,
    rdap::{
        jscontact_conversion, parse_extensions,
        response::{ResponseUtil, BAD_REQUEST},
        ToBootStrap,
    },
    server::DynServiceState,
};

/// Gets a network object by the address path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn network_by_netid(
    Path(netid): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    if netid.contains('/') {
        debug!("getting network by cidr {netid}");
        if let Ok(cidr) = IpInet::from_str(&netid) {
            let storage = state.get_storage().await?;
            let network = storage.get_network_by_cidr(&cidr.to_string()).await?;
            if state.get_bootstrap() {
                Ok(network.to_ip_bootstrap(&netid).response())
            } else {
                let network =
                    jscontact_conversion(network, state.get_jscontact_conversion(), &exts_list);
                let network = normalize_extensions(network);
                Ok(network.response())
            }
        } else {
            Ok(BAD_REQUEST.response())
        }
    } else {
        debug!("getting network by ip address {netid}");
        let ip: Result<IpAddr, _> = netid.parse();
        if ip.is_err() {
            Ok(BAD_REQUEST.response())
        } else {
            let storage = state.get_storage().await?;
            let network = storage.get_network_by_ipaddr(&netid).await?;
            if state.get_bootstrap() {
                Ok(network.to_ip_bootstrap(&netid).response())
            } else {
                let network =
                    jscontact_conversion(network, state.get_jscontact_conversion(), &exts_list);
                let network = normalize_extensions(network);
                Ok(network.response())
            }
        }
    }
}
