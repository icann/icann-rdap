//! Conformance checks of RDAP structures.

use std::{any::TypeId, sync::LazyLock};

use {
    crate::response::RdapResponse,
    serde::{Deserialize, Serialize},
    strum::{EnumMessage, IntoEnumIterator},
    strum_macros::{Display, EnumIter, EnumMessage, EnumString, FromRepr},
};

#[doc(inline)]
pub use string::*;

mod autnum;
mod domain;
mod entity;
mod error;
mod help;
mod httpdata;
mod nameserver;
mod network;
pub mod process;
mod search;
mod string;
mod types;

/// The max length of the check class string representations.
pub static CHECK_CLASS_LEN: LazyLock<usize> = LazyLock::new(|| {
    CheckClass::iter()
        .max_by_key(|x| x.to_string().len())
        .map_or(8, |x| x.to_string().len())
});

/// Describes the classes of checks.
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
    #[strum(serialize = "Std95Warn")]
    Std95Warning,

    /// STD 95 Errors
    ///
    /// This class represetns errors in the RDAP with respect to STD 95.
    #[strum(serialize = "Std95Err")]
    Std95Error,

    /// Cidr0 Errors
    ///
    /// This class represents errors with respect to CIDR0.
    #[strum(serialize = "Cidr0Err")]
    Cidr0Error,

    /// Gtld Profile Errors
    ///
    /// This class represents errors with respect to the gTLD RDAP profile.
    #[strum(serialize = "GtldProfileErr")]
    GtldProfileError,
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
    SecureDns,
    Status,
}

/// Contains many [CheckItem] structures and sub checks.
///
/// Checks are found on object classes and structures defined in [RdapStructure].
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

/// A specific check item.
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

/// Trait for an item that can get checks.
pub trait GetChecks {
    fn get_checks(&self, params: CheckParams) -> Checks;
}

/// Parameters for finding checks.
#[derive(Clone, Copy)]
pub struct CheckParams<'a> {
    pub root: &'a RdapResponse,
    pub parent_type: TypeId,
    pub allow_unreg_ext: bool,
}

impl CheckParams<'_> {
    pub fn from_parent(&self, parent_type: TypeId) -> Self {
        Self {
            root: self.root,
            parent_type,
            allow_unreg_ext: self.allow_unreg_ext,
        }
    }

    pub fn for_rdap(rdap: &RdapResponse) -> CheckParams<'_> {
        CheckParams {
            root: rdap,
            parent_type: rdap.get_type(),
            allow_unreg_ext: false,
        }
    }
}

impl GetChecks for RdapResponse {
    fn get_checks(&self, params: CheckParams) -> Checks {
        match &self {
            Self::Entity(e) => e.get_checks(params),
            Self::Domain(d) => d.get_checks(params),
            Self::Nameserver(n) => n.get_checks(params),
            Self::Autnum(a) => a.get_checks(params),
            Self::Network(n) => n.get_checks(params),
            Self::DomainSearchResults(r) => r.get_checks(params),
            Self::EntitySearchResults(r) => r.get_checks(params),
            Self::NameserverSearchResults(r) => r.get_checks(params),
            Self::ErrorResponse(e) => e.get_checks(params),
            Self::Help(h) => h.get_checks(params),
        }
    }
}

/// Trait to get checks for groups of data structures such as those
/// related to [crate::response::Common] and [crate::response::ObjectCommon].
pub trait GetGroupChecks {
    fn get_group_checks(&self, params: CheckParams) -> Vec<Checks>;
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

// Is a check found in any check or subcheck.
pub fn contains_check(check: Check, checks: &Checks) -> bool {
    checks.items.iter().any(|c| c.check == check)
        || checks.sub_checks.iter().any(|c| contains_check(check, c))
}

/// Returns true if the check is in a check list
pub fn is_checked(check: Check, checks: &[Checks]) -> bool {
    checks.iter().any(|c| is_checked_item(check, c))
}

/// Returns true if the check is in a list of check items.
pub fn is_checked_item(check: Check, checks: &Checks) -> bool {
    checks.items.iter().any(|c| c.check == check)
}

/// The variant check types.
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
    #[strum(message = "ambiguous follow because the 'href' may not contain an RDAP URL")]
    LinkRelatedNotToRdap = 208,

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
    #[strum(message = "handle is not a string")]
    HandleIsNotString = 601,
    #[strum(message = "parent handle is not a string")]
    ParentHandleIsNotString = 602,

    // Status 700 - 799
    #[strum(message = "status appears to be empty or only whitespace")]
    StatusIsEmpty = 700,
    #[strum(message = "status value not registered")]
    StatusValueUnknown = 701,

    // Role 800 - 899
    #[strum(message = "role appears to be empty or only whitespace")]
    RoleIsEmpty = 800,
    #[strum(message = "entity role may not be registered")]
    UnknownRole = 801,
    #[strum(message = "role is a string, not array of strings")]
    RoleIsString = 802,

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
    #[strum(message = "name is not a string")]
    NetworkOrAutnumNameIsNotString = 1101,

    // Network or Autnum Type 1200 - 1299
    #[strum(message = "type appears to be empty or only whitespace")]
    NetworkOrAutnumTypeIsEmpty = 1200,
    #[strum(message = "type is not a string")]
    NetworkOrAutnumTypeIsNotString = 1201,

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
    #[strum(message = "IP address array is a string.")]
    IpAddressArrayIsString = 1314,
    #[strum(message = "IP version is not a string")]
    IpVersionIsNotString = 1315,

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
    #[strum(message = "publicId type is not a string")]
    PublicIdTypeIsNotString = 1702,
    #[strum(message = "publicId identifier is not a string")]
    PublicIdIdentifierIsNotString = 1703,

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

    // Gtld Profile 2000 - 2099
    #[strum(message = "RDAP Service Must use HTTPS.")]
    MustUseHttps = 2000,
    #[strum(message = "access-control-allow-origin is not asterisk")]
    AllowOriginNotStar = 2001,

    // Explicit Testing Errors 2100 - 2199
    #[strum(message = "CNAME without A records.")]
    CnameWithoutARecords = 2100,
    #[strum(message = "CNAME without AAAA records.")]
    CnameWithoutAAAARecords = 2101,
    #[strum(message = "No A records.")]
    NoARecords = 2102,
    #[strum(message = "No AAAA records.")]
    NoAAAARecords = 2103,
    #[strum(message = "Expected extension not found.")]
    ExpectedExtensionNotFound = 2104,
    #[strum(message = "IPv6 Support Required.")]
    Ipv6SupportRequiredByGtldProfile = 2105,

    // Secure DNS 2200 - 2299
    #[strum(message = "delegationSigned is a string not a bool.")]
    DelegationSignedIsString = 2200,
    #[strum(message = "zoneSigned is a string not a bool.")]
    ZoneSignedIsString = 2201,
    #[strum(message = "maxSigLife is a string not a number.")]
    MaxSigLifeIsString = 2202,
    // key data
    #[strum(message = "keyData algorithm is a string not a number.")]
    KeyDatumAlgorithmIsString = 2203,
    #[strum(message = "keyData algorithm is out of range.")]
    KeyDatumAlgorithmIsOutOfRange = 2204,
    #[strum(message = "keyData flags is a string not a number.")]
    KeyDatumFlagsIsString = 2205,
    #[strum(message = "keyData flags is out of range.")]
    KeyDatumFlagsIsOutOfRange = 2206,
    #[strum(message = "keyData protocol is a string not a number.")]
    KeyDatumProtocolIsString = 2207,
    #[strum(message = "keyData protocol is out of range.")]
    KeyDatumProtocolIsOutOfRange = 2208,
    // ds data
    #[strum(message = "dsData algorithm is a string not a number.")]
    DsDatumAlgorithmIsString = 2213,
    #[strum(message = "dsData algorithm is out of range.")]
    DsDatumAlgorithmIsOutOfRange = 2214,
    #[strum(message = "dsData keyTag is a string not a number.")]
    DsDatumKeyTagIsString = 2215,
    #[strum(message = "dsData keyTag is out of range.")]
    DsDatumKeyTagIsOutOfRange = 2216,
    #[strum(message = "dsData digestType is a string not a number.")]
    DsDatumDigestTypeIsString = 2217,
    #[strum(message = "dsData digestType is out of range.")]
    DsDatumDigestTypeIsOutOfRange = 2218,

    // Network or Autnum Country 2300 - 2399
    #[strum(message = "country is not a string")]
    NetworkOrAutnumCountryIsNotString = 2300,
}

impl Check {
    pub fn check_item(self) -> CheckItem {
        let check_class = match self {
            Self::RdapConformanceMissing | Self::RdapConformanceInvalidParent => {
                CheckClass::Std95Error
            }
            Self::UnknownExtention => CheckClass::Std95Warning,

            Self::LinkMissingValueProperty | Self::LinkMissingRelProperty => CheckClass::Std95Error,
            Self::LinkRelatedHasNoType
            | Self::LinkRelatedIsNotRdap
            | Self::LinkSelfHasNoType
            | Self::LinkSelfIsNotRdap => CheckClass::Std95Warning,
            Self::LinkObjectClassHasNoSelf => CheckClass::SpecificationNote,
            Self::LinkMissingHrefProperty => CheckClass::Std95Error,
            Self::LinkRelatedNotToRdap => CheckClass::Std95Warning,

            Self::VariantEmptyDomain => CheckClass::Std95Warning,

            Self::EventDateIsAbsent
            | Self::EventDateIsNotRfc3339
            | Self::EventActionIsAbsent
            | Self::NoticeOrRemarkDescriptionIsAbsent
            | Self::NoticeOrRemarkDescriptionIsString => CheckClass::Std95Error,

            Self::HandleIsEmpty => CheckClass::Std95Warning,
            Self::HandleIsNotString => CheckClass::Std95Error,
            Self::ParentHandleIsNotString => CheckClass::Std95Error,

            Self::StatusIsEmpty | Self::RoleIsEmpty => CheckClass::Std95Error,
            Self::StatusValueUnknown => CheckClass::Std95Warning,
            Self::UnknownRole => CheckClass::Std95Warning,
            Self::RoleIsString | Self::LdhNameInvalid => CheckClass::Std95Error,
            Self::LdhNameDocumentation => CheckClass::Informational,
            Self::LdhNameDoesNotMatchUnicode => CheckClass::Std95Warning,

            Self::UnicodeNameInvalidDomain | Self::UnicodeNameInvalidUnicode => {
                CheckClass::Std95Error
            }

            Self::NetworkOrAutnumNameIsEmpty => CheckClass::Std95Warning,
            Self::NetworkOrAutnumNameIsNotString => CheckClass::Std95Error,
            Self::NetworkOrAutnumTypeIsEmpty => CheckClass::Std95Warning,
            Self::NetworkOrAutnumTypeIsNotString => CheckClass::Std95Error,
            Self::IpAddressMissing => CheckClass::Std95Warning,
            Self::IpAddressMalformed => CheckClass::Std95Error,
            Self::IpAddressEndBeforeStart | Self::IpAddressVersionMismatch => {
                CheckClass::Std95Warning
            }
            Self::IpAddressMalformedVersion | Self::IpAddressListIsEmpty => CheckClass::Std95Error,
            Self::IpAddressThisNetwork
            | Self::IpAddressPrivateUse
            | Self::IpAddressSharedNat
            | Self::IpAddressLoopback
            | Self::IpAddressLinkLocal
            | Self::IpAddressUniqueLocal
            | Self::IpAddressDocumentationNet
            | Self::IpAddressReservedNet => CheckClass::Informational,
            Self::IpAddressArrayIsString => CheckClass::Std95Error,
            Self::IpVersionIsNotString => CheckClass::Std95Error,

            Self::AutnumMissing | Self::AutnumEndBeforeStart => CheckClass::Std95Warning,
            Self::AutnumPrivateUse | Self::AutnumDocumentation | Self::AutnumReserved => {
                CheckClass::Informational
            }

            Self::VcardArrayIsEmpty | Self::VcardHasNoFn => CheckClass::Std95Error,
            Self::VcardFnIsEmpty => CheckClass::SpecificationNote,

            Self::Port43IsEmpty | Self::PublicIdTypeIsAbsent | Self::PublicIdIdentifierIsAbsent => {
                CheckClass::Std95Error
            }
            Self::PublicIdTypeIsNotString => CheckClass::Std95Error,
            Self::PublicIdIdentifierIsNotString => CheckClass::Std95Error,

            Self::CorsAllowOriginRecommended
            | Self::CorsAllowOriginStarRecommended
            | Self::CorsAllowCredentialsNotRecommended => CheckClass::Std95Warning,
            Self::ContentTypeIsAbsent | Self::ContentTypeIsNotRdap => CheckClass::Std95Error,

            Self::Cidr0V4PrefixIsAbsent
            | Self::Cidr0V4LengthIsAbsent
            | Self::Cidr0V6PrefixIsAbsent
            | Self::Cidr0V6LengthIsAbsent => CheckClass::Cidr0Error,

            Self::MustUseHttps | Self::AllowOriginNotStar => CheckClass::GtldProfileError,

            Self::CnameWithoutARecords | Self::CnameWithoutAAAARecords => CheckClass::Std95Error,
            Self::NoARecords | Self::NoAAAARecords => CheckClass::SpecificationNote,
            Self::ExpectedExtensionNotFound => CheckClass::Std95Error,
            Self::Ipv6SupportRequiredByGtldProfile => CheckClass::GtldProfileError,

            Self::DelegationSignedIsString
            | Self::ZoneSignedIsString
            | Self::MaxSigLifeIsString
            | Self::KeyDatumAlgorithmIsString
            | Self::KeyDatumAlgorithmIsOutOfRange
            | Self::KeyDatumFlagsIsString
            | Self::KeyDatumFlagsIsOutOfRange
            | Self::KeyDatumProtocolIsString
            | Self::KeyDatumProtocolIsOutOfRange
            | Self::DsDatumAlgorithmIsString
            | Self::DsDatumAlgorithmIsOutOfRange
            | Self::DsDatumKeyTagIsString
            | Self::DsDatumKeyTagIsOutOfRange
            | Self::DsDatumDigestTypeIsString
            | Self::DsDatumDigestTypeIsOutOfRange => CheckClass::Std95Error,

            Self::NetworkOrAutnumCountryIsNotString => CheckClass::Std95Error,
        };
        CheckItem {
            check_class,
            check: self,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::check::RdapStructure;

    use super::{contains_check, traverse_checks, Check, CheckClass, CheckItem, Checks};

    #[test]
    fn test_traverse_info_checks() {
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
    fn test_traverse_specwarn_checks_for_info() {
        // GIVEN
        let checks = Checks {
            rdap_struct: RdapStructure::Entity,
            items: vec![CheckItem {
                check_class: CheckClass::Std95Warning,
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
    fn test_traverse_info_subchecks() {
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
    fn test_traverse_specwarn_subchecks_for_info() {
        // GIVEN
        let checks = Checks {
            rdap_struct: RdapStructure::Entity,
            items: vec![],
            sub_checks: vec![Checks {
                rdap_struct: RdapStructure::Autnum,
                items: vec![CheckItem {
                    check_class: CheckClass::Std95Warning,
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
    fn test_traverse_checks_and_subchecks() {
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

    #[test]
    fn test_contains_check_with_item() {
        // GIVEN check structure
        let checks = Checks {
            rdap_struct: RdapStructure::Autnum,
            items: vec![Check::RdapConformanceMissing.check_item()],
            sub_checks: vec![],
        };

        // WHEN
        let found = contains_check(Check::RdapConformanceMissing, &checks);

        // THEN
        assert!(found);
    }

    #[test]
    fn test_contains_check_with_subchecks() {
        // GIVEN check structure
        let sub_check = Checks {
            rdap_struct: RdapStructure::Entity,
            items: vec![Check::RdapConformanceInvalidParent.check_item()],
            sub_checks: vec![],
        };
        let checks = Checks {
            rdap_struct: RdapStructure::Autnum,
            items: vec![],
            sub_checks: vec![sub_check],
        };

        // WHEN
        let found = contains_check(Check::RdapConformanceInvalidParent, &checks);

        // THEN
        assert!(found);
    }

    #[test]
    fn test_not_contains_check_with_item() {
        // GIVEN check structure
        let checks = Checks {
            rdap_struct: RdapStructure::Autnum,
            items: vec![],
            sub_checks: vec![],
        };

        // WHEN
        let found = contains_check(Check::RdapConformanceMissing, &checks);

        // THEN
        assert!(!found);
    }
}
