use axum::{
    extract::{Path, State},
    response::Response,
};

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynServiceState};

use super::ToBootStrap;

/// Gets an autnum object by the number path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn autnum_by_num(
    Path(as_num): Path<u32>,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let storage = state.get_storage().await?;
    let autnum = storage.get_autnum_by_num(as_num).await?;
    if state.get_bootstrap() {
        Ok(autnum.to_autnum_bootstrap(as_num).response())
    } else {
        Ok(autnum.response())
    }
}
