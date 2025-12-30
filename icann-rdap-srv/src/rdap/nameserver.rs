use http::HeaderMap;
use icann_rdap_common::prelude::normalize_extensions;
use tracing::debug;

use {
    axum::{
        extract::{Path, State},
        response::Response,
    },
    icann_rdap_common::response::RdapResponse,
};

use crate::{
    error::RdapServerError,
    rdap::{jscontact_conversion, parse_extensions, response::ResponseUtil},
    server::DynServiceState,
};

use super::{response::BAD_REQUEST, ToBootStrap};

/// Gets a nameserver object by the name path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn nameserver_by_name(
    Path(ns_name): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

    let count = ns_name.chars().filter(|c| *c == '.').count();
    // if the nameserver name does not have at least 2 'dot' characters, return bad request.
    if count < 2 {
        return Ok(BAD_REQUEST.response());
    }
    let storage = state.get_storage().await?;
    let nameserver = storage.get_nameserver_by_ldh(&ns_name).await?;

    if state.get_bootstrap()
        && !matches!(nameserver, RdapResponse::Nameserver(_))
        && !nameserver.is_redirect()
    {
        let mut ns_slice = ns_name.as_str();
        while let Some(less_specific) = ns_slice.split_once('.') {
            // this needs to be domain because that is where redirects will be for domain
            // like things.
            let found = storage.get_domain_by_ldh(less_specific.1).await?;
            if found.is_redirect() {
                return Ok(found.to_nameserver_bootstrap(&ns_name).response());
            } else {
                ns_slice = less_specific.1;
            }
        }
    }

    let nameserver = jscontact_conversion(nameserver, state.get_jscontact_conversion(), &exts_list);
    let nameserver = normalize_extensions(nameserver);
    Ok(nameserver.response())
}
