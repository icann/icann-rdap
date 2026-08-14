//! Filter module for extracting fields from RDAP responses.
//!
//! This module provides a way to extract selected fields from any RDAP response
//! into a typed array of name/value pairs suitable for CSV serialization.
//!
//! # Example
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//! use icann_rdap_common::filter::*;
//!
//! let domain = Domain::builder()
//!     .ldh_name("example.com")
//!     .handle("EXAMPLE-DOM")
//!     .status("active")
//!     .build();
//!
//! let filters = vec![Filter::LdhName, Filter::Handle, Filter::Status];
//! let results = extract(&domain, &filters);
//! ```

pub mod autnum;
pub mod autnum_search_results;
pub mod domain;
pub mod domain_search_results;
pub mod entity;
pub mod entity_search_results;
pub mod ip_search_results;
pub mod nameserver;
pub mod nameserver_search_results;
pub mod network;

use std::{
    collections::{HashMap, VecDeque},
    sync::LazyLock,
};

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::response::{Entity, EntityRole, ObjectCommonFields};

/// Represents a filterable field on an RDAP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Filter {
    // Object class common (all types)
    Handle,
    Status,
    ObjectClassName,
    Event,
    RdapConformance,

    // Domain-specific
    LdhName,
    UnicodeName,
    Nameserver,
    PublicId,

    // Nameservers
    IpAddress,

    // Entity-specific
    Role,
    Email,
    FullName,
    Voice,
    Fax,
    ContactUri,
    CountryName,
    CountryCode,

    // Autnum-specific
    StartAutnum,
    EndAutnum,

    // Network-specific
    StartIpAddress,
    EndIpAddress,
    IpVersion,
    Cidr,

    // Generic
    Name,
    Type,
    ParentHandle,
    RegistrantEmail,
    RegistrantFullName,
    RegistrantVoice,
    RegistrantFax,
    RegistrantContactUri,
    RegistrantCountryName,
    RegistrantCountryCode,
    AbuseEmail,
    AbuseFullName,
    AbuseVoice,
    AbuseFax,
    AbuseContactUri,
    AbuseCountryName,
    AbuseCountryCode,
    TechnicalEmail,
    TechnicalFullName,
    TechnicalVoice,
    TechnicalFax,
    TechnicalContactUri,
    TechnicalCountryName,
    TechnicalCountryCode,
    RegistrarEmail,
    RegistrarFullName,
    RegistrarVoice,
    RegistrarFax,
    RegistrarContactUri,
    RegistrarCountryName,
    RegistrarCountryCode,
}

/// The extracted value from a filter operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    StringVal(String),
    StringArray(Vec<String>),
    HashMapVal(HashMap<String, FilterValue>),
    IntVal(i64),
    IntArray(Vec<i64>),
    BoolVal(bool),
    Null,
}

static EMPTY_HASHMAP: LazyLock<HashMap<String, FilterValue>> = LazyLock::new(HashMap::new);

impl FilterValue {
    /// Returns a reference to the string if this is `StringVal`, otherwise `None`.
    pub fn string_value(&self) -> Option<&str> {
        match self {
            FilterValue::StringVal(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the owned string if this is `StringVal`, otherwise `None`.
    pub fn into_string_value(self) -> Option<String> {
        match self {
            FilterValue::StringVal(s) => Some(s),
            _ => None,
        }
    }

    /// Returns a reference to the string array if this is `StringArray`, otherwise an empty slice.
    pub fn string_values(&self) -> &[String] {
        match self {
            FilterValue::StringArray(v) => v,
            _ => &[],
        }
    }

    /// Returns the owned string array if this is `StringArray`, otherwise an empty vec.
    pub fn into_string_values(self) -> Vec<String> {
        match self {
            FilterValue::StringArray(v) => v,
            _ => Vec::new(),
        }
    }

    /// Returns the int value if this is `IntVal`, otherwise `None`.
    pub fn int_value(&self) -> Option<i64> {
        match self {
            FilterValue::IntVal(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns a reference to the int array if this is `IntArray`, otherwise an empty slice.
    pub fn int_values(&self) -> &[i64] {
        match self {
            FilterValue::IntArray(v) => v,
            _ => &[],
        }
    }

    /// Returns the owned int array if this is `IntArray`, otherwise an empty vec.
    pub fn into_int_values(self) -> Vec<i64> {
        match self {
            FilterValue::IntArray(v) => v,
            _ => Vec::new(),
        }
    }

    /// Returns the bool value if this is `BoolVal`, otherwise `None`.
    pub fn bool_value(&self) -> Option<bool> {
        match self {
            FilterValue::BoolVal(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns a reference to the HashMap if this is `HashMapVal`, otherwise an empty map.
    pub fn hash_map(&self) -> &HashMap<String, FilterValue> {
        match self {
            FilterValue::HashMapVal(m) => m,
            _ => &EMPTY_HASHMAP,
        }
    }

    /// Returns the owned HashMap if this is `HashMapVal`, otherwise an empty map.
    pub fn into_hash_map(self) -> HashMap<String, FilterValue> {
        match self {
            FilterValue::HashMapVal(m) => m,
            _ => HashMap::new(),
        }
    }

    /// Returns `true` if this is `Null`.
    pub fn is_null(&self) -> bool {
        matches!(self, FilterValue::Null)
    }

    /// Returns `true` if this is `Null` or an empty collection.
    pub fn is_empty(&self) -> bool {
        match self {
            FilterValue::Null => true,
            FilterValue::StringArray(v) => v.is_empty(),
            FilterValue::IntArray(v) => v.is_empty(),
            FilterValue::HashMapVal(m) => m.is_empty(),
            _ => false,
        }
    }

    /// Converts this value to a display-friendly string, suitable for CSV or console output.
    ///
    /// - `StringVal` -> the string itself
    /// - `StringArray` -> values joined by `|`
    /// - `HashMapVal` -> `key=value` pairs joined by `|`
    /// - `IntVal` -> integer as string
    /// - `IntArray` -> values joined by `|`
    /// - `BoolVal` -> "true" or "false"
    /// - `Null` -> empty string
    pub fn to_display_string(&self) -> String {
        match self {
            FilterValue::StringVal(s) => s.clone(),
            FilterValue::StringArray(arr) => arr.join("|"),
            FilterValue::HashMapVal(hm) => hm
                .iter()
                .map(|(k, v)| format!("{}={}", k, v.to_display_string()))
                .collect::<Vec<_>>()
                .join("|"),
            FilterValue::IntVal(i) => i.to_string(),
            FilterValue::IntArray(arr) => arr
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("|"),
            FilterValue::BoolVal(b) => b.to_string(),
            FilterValue::Null => String::new(),
        }
    }
}

/// A single filter output with a filter identifier and extracted value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterOutput {
    pub filter: Filter,
    pub value: FilterValue,
}

impl FilterOutput {
    /// Returns the string value if the inner `FilterValue` is `StringVal`, otherwise `None`.
    pub fn string_value(&self) -> Option<&str> {
        self.value.string_value()
    }

    /// Returns `true` if the inner `FilterValue` is `Null`.
    pub fn is_null(&self) -> bool {
        self.value.is_null()
    }
}

/// The result type for filter operations — a vector of filter outputs.
pub type FilterResult = Vec<FilterOutput>;

/// Trait for types that can be filtered.
pub trait Filterable {
    /// Extract the requested filters from this response.
    fn filter(&self, filters: &[Filter]) -> FilterResult;
}

/// Convenience function to extract filters from any filterable type.
pub fn extract<T: Filterable>(response: &T, filters: &[Filter]) -> FilterResult {
    response.filter(filters)
}

/// Convert an `Option<T>` (where T: Display) into a `FilterValue::StringVal` or `Null`.
///
/// This eliminates the common pattern:
/// ```ignore
/// self.handle()
///     .map(|h| FilterValue::StringVal(h.to_string()))
///     .unwrap_or(FilterValue::Null)
/// ```
/// in favor of:
/// ```ignore
/// opt_to_string(self.handle())
/// ```
pub fn opt_to_string<T: std::fmt::Display>(opt: Option<T>) -> FilterValue {
    opt.map(|v| FilterValue::StringVal(v.to_string()))
        .unwrap_or(FilterValue::Null)
}

/// Convert an `Option<u32>` into a `FilterValue::IntVal` or `Null`.
pub fn opt_to_i64(opt: Option<u32>) -> FilterValue {
    opt.map(|v| FilterValue::IntVal(v as i64))
        .unwrap_or(FilterValue::Null)
}

pub(crate) fn find_entity_email_by_role(entities: &[Entity], role: EntityRole) -> Option<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string())
            && let Some(contact) = entity.contact()
            && let Some(email) = contact.email().map(|e| e.email().to_string())
        {
            return Some(email);
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    None
}

pub(crate) fn find_entity_full_name_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Option<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string())
            && let Some(contact) = entity.contact()
            && let Some(name) = contact.full_name().map(|n| n.to_string())
        {
            return Some(name);
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    None
}

pub(crate) fn find_entity_voice_phone_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Option<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string())
            && let Some(contact) = entity.contact()
            && let Some(phone) = contact.voice_phone().map(|p| p.phone().to_string())
        {
            return Some(phone);
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    None
}

pub(crate) fn find_entity_fax_phone_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Option<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string())
            && let Some(contact) = entity.contact()
            && let Some(phone) = contact.fax_phone().map(|p| p.phone().to_string())
        {
            return Some(phone);
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    None
}

pub(crate) fn find_entity_contact_uris_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Vec<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string())
            && let Some(contact) = entity.contact()
        {
            return contact
                .contact_uris()
                .iter()
                .map(|u| u.to_string())
                .collect();
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    Vec::new()
}

pub(crate) fn find_entity_country_names_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Vec<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string())
            && let Some(contact) = entity.contact()
        {
            return contact
                .postal_addresses()
                .iter()
                .filter_map(|a| a.country_name())
                .map(|n| n.to_string())
                .collect();
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    Vec::new()
}

pub(crate) fn find_entity_country_codes_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Vec<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string())
            && let Some(contact) = entity.contact()
        {
            return contact
                .postal_addresses()
                .iter()
                .filter_map(|a| a.country_code())
                .map(|c| c.to_string())
                .collect();
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    Vec::new()
}

/// Handles all entity role filter arms (Registrant*, Abuse*, Technical*, Registrar*).
/// Returns Some(FilterOutput) if the filter is an entity role filter, None otherwise.
pub(crate) fn entity_role_filter_output(entities: &[Entity], f: Filter) -> Option<FilterOutput> {
    let role = match f {
        Filter::RegistrantEmail
        | Filter::RegistrantFullName
        | Filter::RegistrantVoice
        | Filter::RegistrantFax
        | Filter::RegistrantContactUri
        | Filter::RegistrantCountryName
        | Filter::RegistrantCountryCode => EntityRole::Registrant,
        Filter::AbuseEmail
        | Filter::AbuseFullName
        | Filter::AbuseVoice
        | Filter::AbuseFax
        | Filter::AbuseContactUri
        | Filter::AbuseCountryName
        | Filter::AbuseCountryCode => EntityRole::Abuse,
        Filter::TechnicalEmail
        | Filter::TechnicalFullName
        | Filter::TechnicalVoice
        | Filter::TechnicalFax
        | Filter::TechnicalContactUri
        | Filter::TechnicalCountryName
        | Filter::TechnicalCountryCode => EntityRole::Technical,
        Filter::RegistrarEmail
        | Filter::RegistrarFullName
        | Filter::RegistrarVoice
        | Filter::RegistrarFax
        | Filter::RegistrarContactUri
        | Filter::RegistrarCountryName
        | Filter::RegistrarCountryCode => EntityRole::Registrar,
        _ => return None,
    };

    let value = match f {
        Filter::RegistrantEmail
        | Filter::AbuseEmail
        | Filter::TechnicalEmail
        | Filter::RegistrarEmail => find_entity_email_by_role(entities, role)
            .map(|e| FilterValue::StringVal(e.to_string()))
            .unwrap_or(FilterValue::Null),
        Filter::RegistrantFullName
        | Filter::AbuseFullName
        | Filter::TechnicalFullName
        | Filter::RegistrarFullName => find_entity_full_name_by_role(entities, role)
            .map(|e| FilterValue::StringVal(e.to_string()))
            .unwrap_or(FilterValue::Null),
        Filter::RegistrantVoice
        | Filter::AbuseVoice
        | Filter::TechnicalVoice
        | Filter::RegistrarVoice => find_entity_voice_phone_by_role(entities, role)
            .map(|e| FilterValue::StringVal(e.to_string()))
            .unwrap_or(FilterValue::Null),
        Filter::RegistrantFax | Filter::AbuseFax | Filter::TechnicalFax | Filter::RegistrarFax => {
            find_entity_fax_phone_by_role(entities, role)
                .map(|e| FilterValue::StringVal(e.to_string()))
                .unwrap_or(FilterValue::Null)
        }
        Filter::RegistrantContactUri
        | Filter::AbuseContactUri
        | Filter::TechnicalContactUri
        | Filter::RegistrarContactUri => {
            FilterValue::StringArray(find_entity_contact_uris_by_role(entities, role))
        }
        Filter::RegistrantCountryName
        | Filter::AbuseCountryName
        | Filter::TechnicalCountryName
        | Filter::RegistrarCountryName => {
            FilterValue::StringArray(find_entity_country_names_by_role(entities, role))
        }
        Filter::RegistrantCountryCode
        | Filter::AbuseCountryCode
        | Filter::TechnicalCountryCode
        | Filter::RegistrarCountryCode => {
            FilterValue::StringArray(find_entity_country_codes_by_role(entities, role))
        }
        _ => return None,
    };

    Some(FilterOutput { filter: f, value })
}

/// Handles entity role filters for search results (returns arrays).
pub(crate) fn entity_role_filter_output_search<'a, T, I>(results: I, f: Filter) -> FilterOutput
where
    T: EntityRoleProvider + 'a,
    I: Iterator<Item = &'a T> + 'a,
{
    let role = match f {
        Filter::RegistrantEmail
        | Filter::RegistrantFullName
        | Filter::RegistrantVoice
        | Filter::RegistrantFax
        | Filter::RegistrantContactUri
        | Filter::RegistrantCountryName
        | Filter::RegistrantCountryCode => EntityRole::Registrant,
        Filter::AbuseEmail
        | Filter::AbuseFullName
        | Filter::AbuseVoice
        | Filter::AbuseFax
        | Filter::AbuseContactUri
        | Filter::AbuseCountryName
        | Filter::AbuseCountryCode => EntityRole::Abuse,
        Filter::TechnicalEmail
        | Filter::TechnicalFullName
        | Filter::TechnicalVoice
        | Filter::TechnicalFax
        | Filter::TechnicalContactUri
        | Filter::TechnicalCountryName
        | Filter::TechnicalCountryCode => EntityRole::Technical,
        Filter::RegistrarEmail
        | Filter::RegistrarFullName
        | Filter::RegistrarVoice
        | Filter::RegistrarFax
        | Filter::RegistrarContactUri
        | Filter::RegistrarCountryName
        | Filter::RegistrarCountryCode => EntityRole::Registrar,
        _ => {
            return FilterOutput {
                filter: f,
                value: FilterValue::Null,
            };
        }
    };

    let value = match f {
        Filter::RegistrantEmail
        | Filter::AbuseEmail
        | Filter::TechnicalEmail
        | Filter::RegistrarEmail => FilterValue::StringArray(
            results
                .filter_map(|r| find_entity_email_by_role(r.entities(), role))
                .collect(),
        ),
        Filter::RegistrantFullName
        | Filter::AbuseFullName
        | Filter::TechnicalFullName
        | Filter::RegistrarFullName => FilterValue::StringArray(
            results
                .filter_map(|r| find_entity_full_name_by_role(r.entities(), role))
                .collect(),
        ),
        Filter::RegistrantVoice
        | Filter::AbuseVoice
        | Filter::TechnicalVoice
        | Filter::RegistrarVoice => FilterValue::StringArray(
            results
                .filter_map(|r| find_entity_voice_phone_by_role(r.entities(), role))
                .collect(),
        ),
        Filter::RegistrantFax | Filter::AbuseFax | Filter::TechnicalFax | Filter::RegistrarFax => {
            FilterValue::StringArray(
                results
                    .filter_map(|r| find_entity_fax_phone_by_role(r.entities(), role))
                    .collect(),
            )
        }
        Filter::RegistrantContactUri
        | Filter::AbuseContactUri
        | Filter::TechnicalContactUri
        | Filter::RegistrarContactUri => FilterValue::StringArray(
            results
                .flat_map(|r| find_entity_contact_uris_by_role(r.entities(), role))
                .collect(),
        ),
        Filter::RegistrantCountryName
        | Filter::AbuseCountryName
        | Filter::TechnicalCountryName
        | Filter::RegistrarCountryName => FilterValue::StringArray(
            results
                .flat_map(|r| find_entity_country_names_by_role(r.entities(), role))
                .collect(),
        ),
        Filter::RegistrantCountryCode
        | Filter::AbuseCountryCode
        | Filter::TechnicalCountryCode
        | Filter::RegistrarCountryCode => FilterValue::StringArray(
            results
                .flat_map(|r| find_entity_country_codes_by_role(r.entities(), role))
                .collect(),
        ),
        _ => FilterValue::Null,
    };

    FilterOutput { filter: f, value }
}

pub(crate) trait EntityRoleProvider {
    fn entities(&self) -> &[Entity];
}

impl EntityRoleProvider for crate::response::Autnum {
    fn entities(&self) -> &[Entity] {
        ObjectCommonFields::entities(self)
    }
}

impl EntityRoleProvider for crate::response::Domain {
    fn entities(&self) -> &[Entity] {
        ObjectCommonFields::entities(self)
    }
}

impl EntityRoleProvider for crate::response::Entity {
    fn entities(&self) -> &[Entity] {
        ObjectCommonFields::entities(self)
    }
}

impl EntityRoleProvider for crate::response::Network {
    fn entities(&self) -> &[Entity] {
        ObjectCommonFields::entities(self)
    }
}

impl EntityRoleProvider for crate::response::Nameserver {
    fn entities(&self) -> &[Entity] {
        ObjectCommonFields::entities(self)
    }
}

impl Filterable for crate::response::RdapResponse {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        match self {
            crate::response::RdapResponse::Domain(d) => d.filter(filters),
            crate::response::RdapResponse::Autnum(a) => a.filter(filters),
            crate::response::RdapResponse::Entity(e) => e.filter(filters),
            crate::response::RdapResponse::Nameserver(n) => n.filter(filters),
            crate::response::RdapResponse::Network(n) => n.filter(filters),
            crate::response::RdapResponse::DomainSearchResults(d) => d.filter(filters),
            crate::response::RdapResponse::AutnumSearchResults(a) => a.filter(filters),
            crate::response::RdapResponse::EntitySearchResults(e) => e.filter(filters),
            crate::response::RdapResponse::NameserverSearchResults(n) => n.filter(filters),
            crate::response::RdapResponse::IpSearchResults(i) => i.filter(filters),
            _ => filters
                .iter()
                .map(|f| FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                })
                .collect(),
        }
    }
}
