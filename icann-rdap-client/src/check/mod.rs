use icann_rdap_common::response::RdapResponse;
use serde::{Deserialize, Serialize};
use strum_macros::Display;

pub mod domain;
pub mod entity;
pub mod types;

/// Describes the check types to be included in the markdown rendering.
#[derive(Debug, Display, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckType {
    #[strum(serialize = "Info")]
    Informational,
    #[strum(serialize = "Spec")]
    SpecificationCompliance,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Checks<'a> {
    pub struct_name: &'a str,
    pub items: Vec<CheckItem>,
    pub sub_checks: Vec<Checks<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckItem {
    pub check_type: CheckType,
    pub message: String,
}

pub trait GetChecks {
    fn get_checks(&self) -> Checks;
}

impl GetChecks for RdapResponse {
    fn get_checks(&self) -> Checks {
        match &self {
            RdapResponse::Entity(_) => todo!(),
            RdapResponse::Domain(domain) => domain.get_checks(),
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
