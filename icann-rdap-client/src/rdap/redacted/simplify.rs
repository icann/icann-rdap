//! Changes RFC 9537 redactions to simple redactions

use std::str::FromStr;

use icann_rdap_common::prelude::{Domain, RdapResponse, ToResponse};

use crate::rdap::redacted::RedactedName;

/// Takes in an RDAP response and creates Simple Redactions
/// from the RFC 9537 redactions.
///
/// # Arguments
///
/// * `rdap` is the [RdapResponse] which is altered.
/// * `only_pre_path` does not create Simple Redactions if no path expression is given or the prePath expression is present.
pub fn simplify_redactions(rdap: RdapResponse, only_pre_path: bool) -> RdapResponse {
    match rdap {
        RdapResponse::Entity(entity) => {
            // no registered redactions are on plain entities. They must all
            // have roles.
            entity.to_response()
        }
        RdapResponse::Domain(domain) => simplify_domain_redactions(domain, only_pre_path),
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

fn simplify_domain_redactions(domain: Box<Domain>, _only_pre_path: bool) -> RdapResponse {
    let redactions = domain.object_common.redacted.as_deref().unwrap_or_default();
    for redaction in redactions {
        if redaction.pre_path().is_some()
            || (redaction.post_path().is_none() && redaction.replacement_path().is_none())
        {
            continue;
        }
        if let Some(r_type) = redaction.name().type_field() {
            let r_name = RedactedName::from_str(r_type);
            if let Ok(_registered_redaction) = r_name {
                // TODO match on redactions
            }
        }
    }
    domain.to_response()
}

/// Removes RFC 9537 redactions from an RDAP response.
pub fn removed_rfc9537(rdap: RdapResponse) -> RdapResponse {
    rdap
}
