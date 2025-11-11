//! Changes RFC 9537 redactions to simple redactions

use icann_rdap_common::prelude::{RdapResponse, ToResponse};

/// Takes in an RDAP response and creates Simple Redactions
/// from the RFC 9537 redactions.
///
/// # Arguments
///
/// * `rdap` is the [RdapResponse] which is altered.
/// * `only_pre_path` does not create Simple Redactions if no path expression is given or the prePath expression is present.
pub fn simplify_redactions(rdap: RdapResponse, _only_pre_path: bool) -> RdapResponse {
    match rdap {
        RdapResponse::Entity(entity) => {
            // no registered redactions are on plain entities. They must all
            // have roles.
            entity.to_response()
        }
        RdapResponse::Domain(domain) => domain.to_response(),
        RdapResponse::Nameserver(nameserver) => {
            // no registered redactions on nameservers.
            nameserver.to_response()
        }
        RdapResponse::Autnum(autnum) => {
            // no registered redactions on autnums.
            autnum.to_response()
        }
        RdapResponse::Network(network) => {
            // no registered redactons on networks
            network.to_response()
        }
        _ => {
            // do nothing as RFC 9537 does not explain how or if its redacted
            // directives work against search results or other, non-object class responses.
            rdap
        }
    }
}

/// Removes RFC 9537 redactions from an RDAP response.
pub fn removed_rfc9537(rdap: RdapResponse) -> RdapResponse {
    rdap
}
