use axum::{
    extract::{Path, State},
    response::Response,
};

use crate::{error::RdapServerError, server::DynStoreState};

#[axum_macros::debug_handler]
pub(crate) async fn domain_by_name(
    Path(domain_name): Path<String>,
    state: State<DynStoreState>,
) -> Result<Response, RdapServerError> {
    let storage = state.get_storage().await?;
    let domain = storage.get_domain_by_ldh(&domain_name).await?;
    Ok(domain.response())
}
