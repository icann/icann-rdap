use axum::{
    extract::{Path, State},
    response::Response,
};

use crate::{error::RdapServerError, server::DynStoreState};

/// Gets a domain object by the name path, which can be either A-label or U-lable
/// according to RFC 9082.
#[axum_macros::debug_handler]
pub(crate) async fn domain_by_name(
    Path(domain_name): Path<String>,
    state: State<DynStoreState>,
) -> Result<Response, RdapServerError> {
    // TODO verify it looks like a domain name and return BAD REQUEST if it does not.
    let storage = state.get_storage().await?;
    let domain = storage.get_domain_by_ldh(&domain_name).await?;
    Ok(domain.response())
}