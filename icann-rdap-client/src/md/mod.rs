use icann_rdap_common::response::RdapResponse;

use crate::check::CheckType;

pub mod domain;
pub mod types;

pub(crate) const CODE_INDENT: &str = "    ";

pub trait ToMd {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType]) -> String;
}

impl ToMd for RdapResponse {
    fn to_md(&self, heading_level: usize, check_types: &[CheckType]) -> String {
        match &self {
            RdapResponse::Entity(_) => todo!(),
            RdapResponse::Domain(domain) => domain.to_md(heading_level, check_types),
            RdapResponse::Nameserver(_) => todo!(),
            RdapResponse::Autnum(_) => todo!(),
            RdapResponse::Network(_) => todo!(),
            RdapResponse::DomainSearchResults(_) => todo!(),
            RdapResponse::EntitySearchResults(_) => todo!(),
            RdapResponse::NameserverSearchResults(_) => todo!(),
            RdapResponse::ErrorResponse(_) => todo!(),
            RdapResponse::Help(_) => todo!(),
        }
    }
}

pub(crate) fn to_em(str: &str) -> String {
    format!("_{str}_")
}

pub(crate) fn to_bold(str: &str) -> String {
    format!("__{str}__")
}

pub(crate) fn to_header(str: &str, level: usize) -> String {
    format!("{} {str}", "#".repeat(level))
}
