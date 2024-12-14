//! Conformance checks of RDAP structures.

use std::any::TypeId;

use crate::response::RdapResponse;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use strum::{EnumMessage, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumMessage, EnumString, FromRepr};

pub mod autnum;
pub mod domain;
pub mod entity;
pub mod error;
pub mod help;
pub mod httpdata;
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
    EnumIter,
    EnumString,
    Debug,
    Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Clone,
    Copy,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CheckClass {
    /// Informational
    ///
    /// This class represents informational items.
    #[strum(serialize = "Info")]
    Informational,

    /// Specification Note
    ///
    /// This class represents notes about the RDAP response with respect to
    /// the various RDAP and RDAP related specifications.
    #[strum(serialize = "SpecNote")]
    SpecificationNote,

    /// STD 95 Warnings
    ///
    /// This class represents warnings that may cause some clients to be unable
    /// to conduct some operations.
    #[strum(serialize = "StdWarn")]
    StdWarning,

    /// STD 95 Errors
    ///
    /// This class represetns errors in the RDAP with respect to STD 95.
    #[strum(serialize = "StdErr")]
    StdError,

    /// Cidr0 Errors
    ///
    /// This class represents errors with respect to CIDR0.
    #[strum(serialize = "Cidr0Err")]
    Cidr0Error,

    /// ICANN Profile Errors
    ///
    /// This class represents errors with respect to the gTLD RDAP profile.
    #[strum(serialize = "IcannErr")]
    IcannError,
}

/// Represents the name of an RDAP structure for which a check appears.
///
/// An RDAP data structure is not the same as a Rust struct in that RDAP
/// data structures may consist of arrays and sometimes structured data
/// within a string.
#[derive(
    Debug, Serialize, Deserialize, Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Display, EnumString,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RdapStructure {
    Autnum,
    Cidr0,
    Domain,
    DomainSearchResults,
    Entity,
    EntitySearchResults,
    Events,
    Error,
    Help,
    Handle,
    HttpData,
    IpNetwork,
    Link,
    Links,
    Nameserver,
    NameserverSearchResults,
    NoticeOrRemark,
    Notices,
    PublidIds,
    Port43,
    RdapConformance,
    Redacted,
    Remarks,
    Status,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct Checks {
    pub rdap_struct: RdapStructure,
    pub items: Vec<CheckItem>,
    pub sub_checks: Vec<Checks>,
}

impl Checks {
    pub fn sub(&self, rdap_struct: RdapStructure) -> Option<&Self> {
        self.sub_checks
            .iter()
            .find(|check| check.rdap_struct == rdap_struct)
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
            "{}:({:0>4}) {}",
            self.check_class,
            self.check as usize,
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

impl CheckParams<'_> {
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
    checks: &Checks,
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
        checks.rdap_struct
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
    Debug,
    EnumMessage,
    EnumString,
    Display,
    Serialize,
    Deserialize,
    PartialEq,
    PartialOrd,
    Eq,
    Ord,
    Clone,
    Copy,
    FromRepr,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Check {
    // RDAP Conformance 100 - 199
    #[strum(message = "RFC 9083 requires 'rdapConformance' on the root object.")]
    RdapConformanceMissing = 100,
    #[strum(message = "'rdapConformance' can only appear at the top of response.")]
    RdapConformanceInvalidParent = 101,
    #[strum(message = "declared extension may not be registered.")]
    UnknownExtention = 102,

    // Link 200 - 299
    #[strum(message = "'value' property not found in Link structure as required by RFC 9083")]
    LinkMissingValueProperty = 200,
    #[strum(message = "'rel' property not found in Link structure as required by RFC 9083")]
    LinkMissingRelProperty = 201,
    #[strum(message = "ambiguous follow because related link has no 'type' property")]
    LinkRelatedHasNoType = 202,
    #[strum(message = "ambiguous follow because related link does not have RDAP media type")]
    LinkRelatedIsNotRdap = 203,
    #[strum(message = "self link has no 'type' property")]
    LinkSelfHasNoType = 204,
    #[strum(message = "self link does not have RDAP media type")]
    LinkSelfIsNotRdap = 205,
    #[strum(message = "RFC 9083 recommends self links for all object classes")]
    LinkObjectClassHasNoSelf = 206,
    #[strum(message = "'href' property not found in Link structure as required by RFC 9083")]
    LinkMissingHrefProperty = 207,

    // Domain Variant 300 - 399
    #[strum(message = "empty domain variant is ambiguous")]
    VariantEmptyDomain = 300,

    // Event 400 - 499
    #[strum(message = "event date is absent")]
    EventDateIsAbsent = 400,
    #[strum(message = "event date is not RFC 3339 compliant")]
    EventDateIsNotRfc3339 = 401,
    #[strum(message = "event action is absent")]
    EventActionIsAbsent = 402,

    // Notice Or Remark 500 - 599
    #[strum(message = "RFC 9083 requires a description in a notice or remark")]
    NoticeOrRemarkDescriptionIsAbsent = 500,
    #[strum(message = "RFC 9083 requires a description to be an array of strings")]
    NoticeOrRemarkDescriptionIsString = 501,

    // Handle 600 - 699
    #[strum(message = "handle appears to be empty or only whitespace")]
    HandleIsEmpty = 600,

    // Status 700 - 799
    #[strum(message = "status appears to be empty or only whitespace")]
    StatusIsEmpty = 700,

    // Role 800 - 899
    #[strum(message = "role appears to be empty or only whitespace")]
    RoleIsEmpty = 800,

    // LDH Name 900 - 999
    #[strum(message = "ldhName does not appear to be an LDH name")]
    LdhNameInvalid = 900,
    #[strum(message = "Documentation domain name. See RFC 6761")]
    LdhNameDocumentation = 901,
    #[strum(message = "Unicode name does not match LDH")]
    LdhNameDoesNotMatchUnicode = 902,

    // Unicode Nmae 1000 - 1099
    #[strum(message = "unicodeName does not appear to be a domain name")]
    UnicodeNameInvalidDomain = 1000,
    #[strum(message = "unicodeName does not appear to be valid Unicode")]
    UnicodeNameInvalidUnicode = 1001,

    // Network Or Autnum Name 1100 - 1199
    #[strum(message = "name appears to be empty or only whitespace")]
    NetworkOrAutnumNameIsEmpty = 1100,

    // Network or Autnum Type 1200 - 1299
    #[strum(message = "type appears to be empty or only whitespace")]
    NetworkOrAutnumTypeIsEmpty = 1200,

    // IP Address 1300 - 1399
    #[strum(message = "start or end IP address is missing")]
    IpAddressMissing = 1300,
    #[strum(message = "IP address is malformed")]
    IpAddressMalformed = 1301,
    #[strum(message = "end IP address comes before start IP address")]
    IpAddressEndBeforeStart = 1302,
    #[strum(message = "IP version does not match IP address")]
    IpAddressVersionMismatch = 1303,
    #[strum(message = "IP version is malformed")]
    IpAddressMalformedVersion = 1304,
    #[strum(message = "IP address list is empty")]
    IpAddressListIsEmpty = 1305,
    #[strum(message = "\"This network.\" See RFC 791")]
    IpAddressThisNetwork = 1306,
    #[strum(message = "Private use. See RFC 1918")]
    IpAddressPrivateUse = 1307,
    #[strum(message = "Shared NAT network. See RFC 6598")]
    IpAddressSharedNat = 1308,
    #[strum(message = "Loopback network. See RFC 1122")]
    IpAddressLoopback = 1309,
    #[strum(message = "Link local network. See RFC 3927")]
    IpAddressLinkLocal = 1310,
    #[strum(message = "Unique local network. See RFC 8190")]
    IpAddressUniqueLocal = 1311,
    #[strum(message = "Documentation network. See RFC 5737")]
    IpAddressDocumentationNet = 1312,
    #[strum(message = "Reserved network. See RFC 1112")]
    IpAddressReservedNet = 1313,

    // Autnum 1400 - 1499
    #[strum(message = "start or end autnum is missing")]
    AutnumMissing = 1400,
    #[strum(message = "end AS number comes before start AS number")]
    AutnumEndBeforeStart = 1401,
    #[strum(message = "Private use. See RFC 6996")]
    AutnumPrivateUse = 1402,
    #[strum(message = "Documentation AS number. See RFC 5398")]
    AutnumDocumentation = 1403,
    #[strum(message = "Reserved AS number. See RFC 6996")]
    AutnumReserved = 1404,

    // Vcard 1500 - 1599
    #[strum(message = "vCard array does not contain a vCard")]
    VcardArrayIsEmpty = 1500,
    #[strum(message = "vCard has no fn property")]
    VcardHasNoFn = 1501,
    #[strum(message = "vCard fn property is empty")]
    VcardFnIsEmpty = 1502,

    // Port 43 1600 - 1699
    #[strum(message = "port43 appears to be empty or only whitespace")]
    Port43IsEmpty = 1600,

    // Public Id 1700 - 1799
    #[strum(message = "publicId type is absent")]
    PublicIdTypeIsAbsent = 1700,
    #[strum(message = "publicId identifier is absent")]
    PublicIdIdentifierIsAbsent = 1701,

    // HTTP 1800 - 1899
    #[strum(message = "Use of access-control-allow-origin is recommended.")]
    CorsAllowOriginRecommended = 1800,
    #[strum(message = "Use of access-control-allow-origin with asterisk is recommended.")]
    CorsAllowOriginStarRecommended = 1801,
    #[strum(message = "Use of access-control-allow-credentials is not recommended.")]
    CorsAllowCredentialsNotRecommended = 1802,
    #[strum(message = "No content-type header received.")]
    ContentTypeIsAbsent = 1803,
    #[strum(message = "Content-type is not application/rdap+json.")]
    ContentTypeIsNotRdap = 1804,

    // Cidr0 1900 - 1999
    #[strum(message = "Cidr0 v4 prefix is absent")]
    Cidr0V4PrefixIsAbsent = 1900,
    #[strum(message = "Cidr0 v4 length is absent")]
    Cidr0V4LengthIsAbsent = 1901,
    #[strum(message = "Cidr0 v6 prefix is absent")]
    Cidr0V6PrefixIsAbsent = 1902,
    #[strum(message = "Cidr0 v6 length is absent")]
    Cidr0V6LengthIsAbsent = 1903,

    // ICANN Profile 2000 - 2099
    #[strum(message = "RDAP Service Must use HTTPS.")]
    MustUseHttps = 2000,
    #[strum(message = "access-control-allow-origin is not asterisk")]
    AllowOriginNotStar = 2001,
}

impl Check {
    fn check_item(self) -> CheckItem {
        let check_class = match self {
            Check::RdapConformanceMissing => CheckClass::StdError,
            Check::RdapConformanceInvalidParent => CheckClass::StdError,
            Check::UnknownExtention => CheckClass::StdWarning,

            Check::LinkMissingValueProperty => CheckClass::StdError,
            Check::LinkMissingRelProperty => CheckClass::StdError,
            Check::LinkRelatedHasNoType => CheckClass::StdWarning,
            Check::LinkRelatedIsNotRdap => CheckClass::StdWarning,
            Check::LinkSelfHasNoType => CheckClass::StdWarning,
            Check::LinkSelfIsNotRdap => CheckClass::StdWarning,
            Check::LinkObjectClassHasNoSelf => CheckClass::SpecificationNote,
            Check::LinkMissingHrefProperty => CheckClass::StdError,

            Check::VariantEmptyDomain => CheckClass::StdWarning,

            Check::EventDateIsAbsent => CheckClass::StdError,
            Check::EventDateIsNotRfc3339 => CheckClass::StdError,
            Check::EventActionIsAbsent => CheckClass::StdError,

            Check::NoticeOrRemarkDescriptionIsAbsent => CheckClass::StdError,
            Check::NoticeOrRemarkDescriptionIsString => CheckClass::StdError,

            Check::HandleIsEmpty => CheckClass::StdWarning,

            Check::StatusIsEmpty => CheckClass::StdError,

            Check::RoleIsEmpty => CheckClass::StdError,

            Check::LdhNameInvalid => CheckClass::StdError,
            Check::LdhNameDocumentation => CheckClass::Informational,
            Check::LdhNameDoesNotMatchUnicode => CheckClass::StdWarning,

            Check::UnicodeNameInvalidDomain => CheckClass::StdError,
            Check::UnicodeNameInvalidUnicode => CheckClass::StdError,

            Check::NetworkOrAutnumNameIsEmpty => CheckClass::StdWarning,

            Check::NetworkOrAutnumTypeIsEmpty => CheckClass::StdWarning,

            Check::IpAddressMissing => CheckClass::StdWarning,
            Check::IpAddressMalformed => CheckClass::StdError,
            Check::IpAddressEndBeforeStart => CheckClass::StdWarning,
            Check::IpAddressVersionMismatch => CheckClass::StdWarning,
            Check::IpAddressMalformedVersion => CheckClass::StdError,
            Check::IpAddressListIsEmpty => CheckClass::StdError,
            Check::IpAddressThisNetwork => CheckClass::Informational,
            Check::IpAddressPrivateUse => CheckClass::Informational,
            Check::IpAddressSharedNat => CheckClass::Informational,
            Check::IpAddressLoopback => CheckClass::Informational,
            Check::IpAddressLinkLocal => CheckClass::Informational,
            Check::IpAddressUniqueLocal => CheckClass::Informational,
            Check::IpAddressDocumentationNet => CheckClass::Informational,
            Check::IpAddressReservedNet => CheckClass::Informational,

            Check::AutnumMissing => CheckClass::StdWarning,
            Check::AutnumEndBeforeStart => CheckClass::StdWarning,
            Check::AutnumPrivateUse => CheckClass::Informational,
            Check::AutnumDocumentation => CheckClass::Informational,
            Check::AutnumReserved => CheckClass::Informational,

            Check::VcardArrayIsEmpty => CheckClass::StdError,
            Check::VcardHasNoFn => CheckClass::StdError,
            Check::VcardFnIsEmpty => CheckClass::SpecificationNote,

            Check::Port43IsEmpty => CheckClass::StdError,

            Check::PublicIdTypeIsAbsent => CheckClass::StdError,
            Check::PublicIdIdentifierIsAbsent => CheckClass::StdError,

            Check::CorsAllowOriginRecommended => CheckClass::StdWarning,
            Check::CorsAllowOriginStarRecommended => CheckClass::StdWarning,
            Check::CorsAllowCredentialsNotRecommended => CheckClass::StdWarning,
            Check::ContentTypeIsAbsent => CheckClass::StdError,
            Check::ContentTypeIsNotRdap => CheckClass::StdError,

            Check::Cidr0V4PrefixIsAbsent => CheckClass::Cidr0Error,
            Check::Cidr0V4LengthIsAbsent => CheckClass::Cidr0Error,
            Check::Cidr0V6PrefixIsAbsent => CheckClass::Cidr0Error,
            Check::Cidr0V6LengthIsAbsent => CheckClass::Cidr0Error,

            Check::MustUseHttps => CheckClass::IcannError,
            Check::AllowOriginNotStar => CheckClass::IcannError,
        };
        CheckItem {
            check_class,
            check: self,
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::check::RdapStructure;

    use super::{traverse_checks, Check, CheckClass, CheckItem, Checks};

    #[test]
    fn GIVEN_info_checks_WHEN_traversed_for_info_THEN_found() {
        // GIVEN
        let checks = Checks {
            rdap_struct: RdapStructure::Entity,
            items: vec![CheckItem {
                check_class: CheckClass::Informational,
                check: Check::VariantEmptyDomain,
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
            rdap_struct: RdapStructure::Entity,
            items: vec![CheckItem {
                check_class: CheckClass::StdWarning,
                check: Check::VariantEmptyDomain,
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
            rdap_struct: RdapStructure::Entity,
            items: vec![],
            sub_checks: vec![Checks {
                rdap_struct: RdapStructure::Autnum,
                items: vec![CheckItem {
                    check_class: CheckClass::Informational,
                    check: Check::VariantEmptyDomain,
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
            rdap_struct: RdapStructure::Entity,
            items: vec![],
            sub_checks: vec![Checks {
                rdap_struct: RdapStructure::Autnum,
                items: vec![CheckItem {
                    check_class: CheckClass::StdWarning,
                    check: Check::VariantEmptyDomain,
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
            rdap_struct: RdapStructure::Entity,
            items: vec![CheckItem {
                check_class: CheckClass::Informational,
                check: Check::RdapConformanceInvalidParent,
            }],
            sub_checks: vec![Checks {
                rdap_struct: RdapStructure::Autnum,
                items: vec![CheckItem {
                    check_class: CheckClass::Informational,
                    check: Check::VariantEmptyDomain,
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
        dbg!(&structs);
        assert!(structs.contains(&"[ROOT]/entity".to_string()));
        assert!(structs.contains(&"[ROOT]/entity/autnum".to_string()));
    }
}
