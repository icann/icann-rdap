use axum::{
    extract::{Path, State},
    response::Response,
};

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynStoreState};

use super::response::BAD_REQUEST;

/// Gets a nameserver object by the name path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn nameserver_by_name(
    Path(ns_name): Path<String>,
    state: State<DynStoreState>,
) -> Result<Response, RdapServerError> {
    let count = ns_name.chars().filter(|c| *c == '.').count();
    // if the nameserver name does not have at least 2 'dot' characters, return bad request.
    if count < 2 {
        Ok(BAD_REQUEST.response())
    } else {
        let storage = state.get_storage().await?;
        let nameserver = storage.get_nameserver_by_ldh(&ns_name).await?;
        Ok(nameserver.response())
    }
}
