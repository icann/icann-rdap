use axum::{
    extract::{Path, State},
    response::Response,
};
use icann_rdap_common::prelude::normalize_extensions;

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
    Ok(if state.get_bootstrap() {
        autnum.to_autnum_bootstrap(as_num).response()
    } else {
        let autnum = normalize_extensions(autnum);
        autnum.response()
    })
}
