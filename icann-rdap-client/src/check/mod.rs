use icann_rdap_common::response::RdapResponse;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumMessage};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod search;
pub mod types;

/// Describes the calls of checks.
#[derive(Debug, Display, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckClass {
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
    pub check_class: CheckClass,
    pub check: Check,
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

#[derive(Debug, EnumMessage, Serialize, Deserialize)]
pub enum Check {
    // Links
    #[strum(message = "'value' property not found in Link structure as required by RFC 7083")]
    LinkMissingValueProperty,
    #[strum(message = "'rel' property not found in Link structure as required by RFC 7083")]
    LinkMissingRelProperty,
}
