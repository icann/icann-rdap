use axum::{
    extract::{Path, State},
    response::Response,
};

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynServiceState};

/// Gets a domain object by the name path, which can be either A-label or U-lable
/// according to RFC 9082.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn domain_by_name(
    Path(domain_name): Path<String>,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    // canonicalize the domain name by removing a trailing ".", trimming any whitespace,
    // and lower casing any ASCII characters.
    // Addresses issues #13 and #16.
    let domain_name = domain_name
        .trim_end_matches('.')
        .trim()
        .to_ascii_lowercase();

    // TODO add option to verify it looks like a domain name and return BAD REQUEST if it does not.
    // not all servers may want to enforce that it has multiple labels, such as an IANA server.
    let storage = state.get_storage().await?;
    let domain = storage.get_domain_by_ldh(&domain_name).await?;

    // TODO put logic only for bootstrapping here
    if state.get_bootstrap() {}

    Ok(domain.response())
}
