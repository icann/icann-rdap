use std::any::TypeId;

use crate::response::RdapResponse;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumMessage};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod items;
pub mod nameserver;
pub mod network;
pub mod search;
pub mod string;
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

impl std::fmt::Display for CheckItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{} : {}",
            self.check_class,
            self.check
                .get_message()
                .unwrap_or("[Check has no description]"),
        ))
    }
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

/// Traverse the checks, and return true if one is found.
pub fn traverse_checks<F>(
    checks: &Checks<'_>,
    classes: &[CheckClass],
    parent_tree: Option<String>,
    f: &mut F,
) -> bool
where
    F: FnMut(&str, &CheckItem),
{
    let mut found = false;
    let struct_tree = format!(
        "{}/{}",
        parent_tree.unwrap_or_else(|| "[ROOT]".to_string()),
        checks.struct_name
    );
    for item in &checks.items {
        if classes.contains(&item.check_class) {
            f(&struct_tree, item);
            found = true;
        }
    }
    for sub_checks in &checks.sub_checks {
        if traverse_checks(sub_checks, classes, Some(struct_tree.clone()), f) {
            found = true
        }
    }
    found
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
    #[strum(message = "ambiguous follow because related link has no 'type' property")]
    RelatedLinkHasNoType,
    #[strum(message = "ambiguous follow because related link does not have RDAP media type")]
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

    // Handle
    #[strum(message = "handle appears to be empty or only whitespace")]
    HandleIsEmpty,

    // Status
    #[strum(message = "status appears to be empty or only whitespace")]
    StatusIsEmpty,

    // Roles
    #[strum(message = "roles appears to be empty or only whitespace")]
    RolesAreEmpty,

    // LDH Name
    #[strum(message = "ldhName does not appear to be an LDH name")]
    InvalidLdhName,
    #[strum(message = "Documentation domain name. See RFC 6761")]
    DocumentataionName,

    // Network or Autnum Name
    #[strum(message = "name appears to be empty or only whitespace")]
    NameIsEmpty,

    // Network or Autnum Type
    #[strum(message = "type appears to be empty or only whitespace")]
    TypeIsEmpty,

    // IP Address
    #[strum(message = "start or end IP address is missing")]
    MissingIpAddress,
    #[strum(message = "IP address is malformed")]
    MalformedIpAddress,
    #[strum(message = "end IP address comes before start IP address")]
    EndIpBeforeStartIp,
    #[strum(message = "IP version does not match IP address")]
    IpVersionMismatch,
    #[strum(message = "IP version is malformed")]
    MalformedIPVersion,
    #[strum(message = "IP address list is empty")]
    IpAddressListIsEmpty,
    #[strum(message = "\"This network.\" See RFC 791")]
    ThisNetwork,
    #[strum(message = "Private use. See RFC 1918")]
    PrivateUseIp,
    #[strum(message = "Shared NAT network. See RFC 6598")]
    SharedNatIp,
    #[strum(message = "Loopback network. See RFC 1122")]
    Loopback,
    #[strum(message = "Link local network. See RFC 3927")]
    LinkLocal,
    #[strum(message = "Unique local network. See RFC 8190")]
    UniqueLocal,
    #[strum(message = "Documentation network. See RFC 5737")]
    DocumentationNet,
    #[strum(message = "Reserved network. See RFC 1112")]
    ReservedNet,

    // Autnum
    #[strum(message = "start or end autnum is missing")]
    MissingAutnum,
    #[strum(message = "end AS number comes before start AS number")]
    EndAutnumBeforeStartAutnum,
    #[strum(message = "Private use. See RFC 6996")]
    PrivateUseAutnum,
    #[strum(message = "Documentation AS number. See RFC 5398")]
    DocumentationAutnum,
    #[strum(message = "Reserved AS number. See RFC 6996")]
    ReservedAutnum,

    // VCard
    #[strum(message = "vCard array does not contain a vCard")]
    VcardArrayIsEmpty,
    #[strum(message = "vCard has not fn property")]
    VcardHasNoFn,
    #[strum(message = "vCard fn property is empty")]
    VcardFnIsEmpty,
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::{traverse_checks, Check, CheckClass, CheckItem, Checks};

    #[test]
    fn GIVEN_info_checks_WHEN_traversed_for_info_THEN_found() {
        // GIVEN
        let checks = Checks {
            struct_name: "foo",
            items: vec![CheckItem {
                check_class: CheckClass::Informational,
                check: Check::EmptyDomainVariant,
            }],
            sub_checks: vec![],
        };

        // WHEN
        let found = traverse_checks(
            &checks,
            &[CheckClass::Informational],
            None,
            &mut |struct_tree, check_item| println!("{struct_tree} -> {check_item}"),
        );

        // THEN
        assert!(found);
    }

    #[test]
    fn GIVEN_specwarn_checks_WHEN_traversed_for_info_THEN_not_found() {
        // GIVEN
        let checks = Checks {
            struct_name: "foo",
            items: vec![CheckItem {
                check_class: CheckClass::SpecificationWarning,
                check: Check::EmptyDomainVariant,
            }],
            sub_checks: vec![],
        };

        // WHEN
        let found = traverse_checks(
            &checks,
            &[CheckClass::Informational],
            None,
            &mut |struct_tree, check_item| println!("{struct_tree} -> {check_item}"),
        );

        // THEN
        assert!(!found);
    }

    #[test]
    fn GIVEN_info_subchecks_WHEN_traversed_for_info_THEN_found() {
        // GIVEN
        let checks = Checks {
            struct_name: "foo",
            items: vec![],
            sub_checks: vec![Checks {
                struct_name: "bar",
                items: vec![CheckItem {
                    check_class: CheckClass::Informational,
                    check: Check::EmptyDomainVariant,
                }],
                sub_checks: vec![],
            }],
        };

        // WHEN
        let found = traverse_checks(
            &checks,
            &[CheckClass::Informational],
            None,
            &mut |struct_tree, check_item| println!("{struct_tree} -> {check_item}"),
        );

        // THEN
        assert!(found);
    }

    #[test]
    fn GIVEN_specwarn_subchecks_WHEN_traversed_for_info_THEN_not_found() {
        // GIVEN
        let checks = Checks {
            struct_name: "foo",
            items: vec![],
            sub_checks: vec![Checks {
                struct_name: "bar",
                items: vec![CheckItem {
                    check_class: CheckClass::SpecificationWarning,
                    check: Check::EmptyDomainVariant,
                }],
                sub_checks: vec![],
            }],
        };

        // WHEN
        let found = traverse_checks(
            &checks,
            &[CheckClass::Informational],
            None,
            &mut |struct_tree, check_item| println!("{struct_tree} -> {check_item}"),
        );

        // THEN
        assert!(!found);
    }

    #[test]
    fn GIVEN_checks_and_subchecks_WHEN_traversed_THEN_tree_structure_shows_tree() {
        // GIVEN
        let checks = Checks {
            struct_name: "foo",
            items: vec![CheckItem {
                check_class: CheckClass::Informational,
                check: Check::InvalidRdapConformanceParent,
            }],
            sub_checks: vec![Checks {
                struct_name: "bar",
                items: vec![CheckItem {
                    check_class: CheckClass::Informational,
                    check: Check::EmptyDomainVariant,
                }],
                sub_checks: vec![],
            }],
        };

        // WHEN
        let mut structs: Vec<String> = vec![];
        let found = traverse_checks(
            &checks,
            &[CheckClass::Informational],
            None,
            &mut |struct_tree, _check_item| structs.push(struct_tree.to_string()),
        );

        // THEN
        assert!(found);
        assert!(structs.contains(&"[ROOT]/foo".to_string()));
        assert!(structs.contains(&"[ROOT]/foo/bar".to_string()));
    }
}
