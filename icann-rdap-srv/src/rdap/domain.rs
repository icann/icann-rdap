use http::HeaderMap;
use icann_rdap_common::{prelude::normalize_extensions, rdns::reverse_dns_to_ip};
use tracing::debug;

use {
    axum::{
        extract::{Path, State},
        response::Response,
    },
    icann_rdap_common::response::RdapResponse,
};

use crate::{
    error::RdapServerError,
    rdap::{jscontact_conversion, parse_extensions, response::ResponseUtil},
    server::DynServiceState,
};

use super::ToBootStrap;

/// Gets a domain object by the name path, which can be either A-label or U-label
/// according to RFC 9082.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn domain_by_name(
    Path(domain_name): Path<String>,
    headers: HeaderMap,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    let exts_list = parse_extensions(headers.get("accept").unwrap().to_str().unwrap());
    debug!("exts_list = \'{}\'", exts_list.join(" "));

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
    let mut domain = storage.get_domain_by_ldh(&domain_name).await?;

    // if not found in domain names, check if it is an IDN
    if !matches!(domain, RdapResponse::Domain(_)) && !domain.is_redirect() {
        domain = storage.get_domain_by_unicode(&domain_name).await?;
    }

    if state.get_bootstrap() && !matches!(domain, RdapResponse::Domain(_)) && !domain.is_redirect()
    {
        if let Some(ip) = reverse_dns_to_ip(domain_name.as_str()) {
            let network = storage.get_network_by_ipaddr(&ip.to_string()).await?;
            return Ok(network.to_domain_bootstrap(&domain_name).response());
        } else {
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
    }

    let domain = jscontact_conversion(domain, state.get_jscontact_conversion(), &exts_list);
    let domain = normalize_extensions(domain);
    Ok(domain.response())
}
