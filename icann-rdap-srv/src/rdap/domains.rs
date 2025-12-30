use axum::{
    extract::{Query, State},
    response::Response,
};

use http::HeaderMap;
use icann_rdap_common::prelude::normalize_extensions;
use serde::Deserialize;
use tracing::debug;

use crate::{
    error::RdapServerError,
    rdap::{jscontact_conversion, parse_extensions, response::ResponseUtil},
    server::DynServiceState,
};

use super::response::NOT_IMPLEMENTED;

#[derive(Debug, Deserialize)]
pub(crate) struct DomainsParams {
    name: Option<String>,

    #[serde(rename = "nsLdhName")]
    _ns_ldh_name: Option<String>,

    #[serde(rename = "nsIp")]
    _ns_ip: Option<String>,
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
        let results = jscontact_conversion(results, state.get_jscontact_conversion(), &exts_list);
        let results = normalize_extensions(results);
        results.response()
    } else {
        NOT_IMPLEMENTED.response()
    })
}
