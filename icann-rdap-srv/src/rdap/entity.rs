use icann_rdap_common::prelude::normalize_extensions;

use {
    axum::{
        extract::{Path, State},
        response::Response,
    },
    icann_rdap_common::response::RdapResponse,
};

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynServiceState};

use super::ToBootStrap;

/// Gets an entity object by the handle path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn entity_by_handle(
    Path(handle): Path<String>,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let storage = state.get_storage().await?;
    let entity = storage.get_entity_by_handle(&handle).await?;

    if state.get_bootstrap() && !matches!(entity, RdapResponse::Entity(_)) && !entity.is_redirect()
    {
        if let Some(tag) = handle.rsplit_once('-') {
            let found = storage
                .get_entity_by_handle(&format!("-{}", tag.1.to_ascii_uppercase()))
                .await?;
            if found.is_redirect() {
                return Ok(found.to_entity_bootstrap(&handle).response());
            }
        }
    }

    let entity = normalize_extensions(entity);
    Ok(entity.response())
}
