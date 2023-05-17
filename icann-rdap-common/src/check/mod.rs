use std::any::TypeId;

use crate::response::RdapResponse;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumMessage};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod nameserver;
pub mod network;
pub mod search;
pub mod types;

lazy_static! {
    pub static ref CHECK_CLASS_LEN: usize = CheckClass::iter()
        .max_by_key(|x| x.to_string().len())
        .map_or(8, |x| x.to_string().len());
}

/// Describes the calls of checks.
#[derive(
    EnumIter, Debug, Display, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone, Copy,
)]
pub enum CheckClass {
    #[strum(serialize = "Info")]
    Informational,
    #[strum(serialize = "SpecWarn")]
    SpecificationWarning,
    #[strum(serialize = "SpecErr")]
    SpecificationError,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct Checks<'a> {
    pub struct_name: &'a str,
    pub items: Vec<CheckItem>,
    pub sub_checks: Vec<Checks<'a>>,
}

impl<'a> Checks<'a> {
    pub fn sub(&self, struct_name: &str) -> Option<&Self> {
        self.sub_checks
            .iter()
            .find(|check| check.struct_name.eq_ignore_ascii_case(struct_name))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckItem {
    pub check_class: CheckClass,
    pub check: Check,
}

pub trait GetChecks {
    fn get_checks(&self, params: CheckParams) -> Checks;
}

#[derive(Clone, Copy)]
pub struct CheckParams<'a> {
    pub do_subchecks: bool,
    pub root: &'a RdapResponse,
    pub parent_type: TypeId,
}

impl<'a> CheckParams<'a> {
    pub fn from_parent(&self, parent_type: TypeId) -> Self {
        CheckParams {
            do_subchecks: self.do_subchecks,
            root: self.root,
            parent_type,
        }
    }
}

impl GetChecks for RdapResponse {
    fn get_checks(&self, params: CheckParams) -> Checks {
        match &self {
            RdapResponse::Entity(e) => e.get_checks(params),
            RdapResponse::Domain(d) => d.get_checks(params),
            RdapResponse::Nameserver(n) => n.get_checks(params),
            RdapResponse::Autnum(a) => a.get_checks(params),
            RdapResponse::Network(n) => n.get_checks(params),
            RdapResponse::DomainSearchResults(r) => r.get_checks(params),
            RdapResponse::EntitySearchResults(r) => r.get_checks(params),
            RdapResponse::NameserverSearchResults(r) => r.get_checks(params),
            RdapResponse::ErrorResponse(e) => e.get_checks(params),
            RdapResponse::Help(h) => h.get_checks(params),
        }
    }
}

pub trait GetSubChecks {
    fn get_sub_checks(&self, params: CheckParams) -> Vec<Checks>;
}

#[derive(
    Debug, EnumMessage, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Ord, Clone, Copy,
)]
pub enum Check {
    // RDAP Conformance
    #[strum(message = "'rdapConformance' can only appear at the top of response.")]
    InvalidRdapConformanceParent,

    // Links
    #[strum(message = "'value' property not found in Link structure as required by RFC 9083")]
    LinkMissingValueProperty,
    #[strum(message = "'rel' property not found in Link structure as required by RFC 9083")]
    LinkMissingRelProperty,
    #[strum(message = "ambguous follow because related link has no 'type' property")]
    RelatedLinkHasNoType,
    #[strum(message = "ambguous follow because related link does not have RDAP media type")]
    RelatedLinkIsNotRdap,
    #[strum(message = "self link has no 'type' property")]
    SelfLinkHasNoType,
    #[strum(message = "self link does not have RDAP media type")]
    SelfLinkIsNotRdap,
    #[strum(message = "RFC 9083 recommends self links for all object classes")]
    ObjectClassHasNoSelfLink,

    // Variants
    #[strum(message = "empty domain variant is ambiguous")]
    EmptyDomainVariant,

    // Events
    #[strum(message = "event date is not RFC 3339 compliant")]
    EventDateIsNotRfc3339,
}
