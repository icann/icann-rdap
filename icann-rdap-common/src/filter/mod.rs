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

use std::collections::{HashMap, VecDeque};

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
pub enum FilterValue {
    StringVal(String),
    StringArray(Vec<String>),
    HashMapVal(HashMap<String, FilterValue>),
    IntVal(i64),
    IntArray(Vec<i64>),
    BoolVal(bool),
    Null,
}

/// A single filter output with a filter identifier and extracted value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterOutput {
    pub filter: Filter,
    pub value: FilterValue,
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
