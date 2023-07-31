use axum::{
    extract::{Path, State},
    response::Response,
};

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynServiceState};

/// Gets an entity object by the handle path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn entity_by_handle(
    Path(handle): Path<String>,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let storage = state.get_storage().await?;
    let entity = storage.get_entity_by_handle(&handle).await?;
    Ok(entity.response())
}
