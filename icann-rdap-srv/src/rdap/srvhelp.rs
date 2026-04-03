use icann_rdap_common::prelude::{normalize_extensions, normalize_extensions_with, ExtensionId};

use {
    axum::{extract::State, response::Response},
    axum_extra::typed_header::TypedHeader,
    headers::Host,
    icann_rdap_common::response::RdapResponse,
};

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynServiceState};

/// Get server help.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn srvhelp(
    host: Option<TypedHeader<Host>>,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let storage = state.get_storage().await?;
    let host_name = host.as_ref().map(|h| h.hostname());

    let mut srv_help = storage.get_srv_help(host_name).await?;

    if !matches!(srv_help, RdapResponse::Help(_)) {
        srv_help = storage.get_srv_help(None).await?;
    }

    let config = state.get_common_config();
    let srv_help = if config.ip_rdap_up_enable || config.ip_rdap_top_enable || config.ip_rdap_down_enable || config.ip_rdap_bottom_enable {
        normalize_extensions_with(
            srv_help,
            [
                ExtensionId::Ips,
                ExtensionId::RirSearch1,
                ExtensionId::IpSearchResults,
            ],
        )
    } else {
        normalize_extensions(srv_help)
    };
    Ok(srv_help.response())
}
