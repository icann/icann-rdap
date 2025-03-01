use icann_rdap_common::{
    prelude::ToResponse,
    response::{RdapResponse, Rfc9083Error},
};

pub mod autnum;
pub mod domain;
pub mod domains;
pub mod entity;
pub mod ip;
pub mod nameserver;
pub mod response;
pub mod router;
pub mod srvhelp;

trait ToBootStrap {
    fn to_ip_bootstrap(self, ip_id: &str) -> RdapResponse;
    fn to_domain_bootstrap(self, domain_id: &str) -> RdapResponse;
    fn to_autnum_bootstrap(self, autnum_id: u32) -> RdapResponse;
    fn to_entity_bootstrap(self, entity_id: &str) -> RdapResponse;
    fn to_nameserver_bootstrap(self, nameserver_id: &str) -> RdapResponse;
}

impl ToBootStrap for RdapResponse {
    fn to_ip_bootstrap(self, ip_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(*e, "ip", ip_id),
            _ => self,
        }
    }

    fn to_domain_bootstrap(self, domain_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(*e, "domain", domain_id),
            _ => self,
        }
    }

    fn to_autnum_bootstrap(self, autnum_id: u32) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => {
                bootstrap_redirect(*e, "autnum", &autnum_id.to_string())
            }
            _ => self,
        }
    }

    fn to_entity_bootstrap(self, entity_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(*e, "entity", entity_id),
            _ => self,
        }
    }

    fn to_nameserver_bootstrap(self, nameserver_id: &str) -> RdapResponse {
        match self {
            RdapResponse::ErrorResponse(e) => bootstrap_redirect(*e, "nameserver", nameserver_id),
            _ => self,
        }
    }
}

fn bootstrap_redirect(error: Rfc9083Error, path: &str, id: &str) -> RdapResponse {
    let Some(ref notices) = error.common.notices else {
        return error.to_response();
    };
    let Some(notice) = notices.first() else {
        return error.to_response();
    };
    let Some(links) = &notice.links else {
        return error.to_response();
    };
    let Some(link) = links.first() else {
        return error.to_response();
    };
    let Some(href) = &link.href else {
        return error.to_response();
    };
    let href = format!("{}{path}/{id}", href);
    let redirect = Rfc9083Error::redirect().url(href).build();
    redirect.to_response()
}
