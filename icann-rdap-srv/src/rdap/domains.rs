use axum::{
    extract::{Query, State},
    response::Response,
};

use serde::Deserialize;

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynServiceState};

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
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    Ok(if let Some(name) = params.name {
        let storage = state.get_storage().await?;
        let results = storage.search_domains_by_name(&name).await?;
        results.response()
    } else {
        NOT_IMPLEMENTED.response()
    })
}
