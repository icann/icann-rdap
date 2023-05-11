use std::net::IpAddr;

use axum::{
    extract::{Path, State},
    response::Response,
};
use cidr_utils::cidr::IpCidr;
use tracing::debug;

use crate::{error::RdapServerError, rdap::response::BAD_REQUEST, server::DynStoreState};

/// Gets a network object by the address path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn network_by_netid(
    Path(netid): Path<String>,
    state: State<DynStoreState>,
) -> Result<Response, RdapServerError> {
    if netid.contains('/') {
        debug!("getting network by cidr {netid}");
        if !IpCidr::is_ip_cidr(&netid) {
            Ok(BAD_REQUEST.response())
        } else {
            let storage = state.get_storage().await?;
            let network = storage.get_network_by_cidr(&netid).await?;
            Ok(network.response())
        }
    } else {
        debug!("getting network by ip address {netid}");
        let ip: Result<IpAddr, _> = netid.parse();
        if ip.is_err() {
            Ok(BAD_REQUEST.response())
        } else {
            let storage = state.get_storage().await?;
            let network = storage.get_network_by_ipaddr(&netid).await?;
            Ok(network.response())
        }
    }
}
