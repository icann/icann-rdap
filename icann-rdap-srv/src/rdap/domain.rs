use axum::{
    extract::{Path, State},
    response::Response,
};
use icann_rdap_common::response::RdapResponse;

use crate::{error::RdapServerError, rdap::response::ResponseUtil, server::DynServiceState};

use super::ToBootStrap;

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

    if state.get_bootstrap() && !matches!(domain, RdapResponse::Domain(_)) && !domain.is_redirect()
    {
        let mut dn_slice = domain_name.as_str();
        while let Some(less_specific) = dn_slice.split_once('.') {
            let found = storage.get_domain_by_ldh(less_specific.1).await?;
            if found.is_redirect() {
                return Ok(found.to_domain_bootstrap(&domain_name).response());
            } else {
                dn_slice = less_specific.1;
            }
        }
    }

    Ok(domain.response())
}
