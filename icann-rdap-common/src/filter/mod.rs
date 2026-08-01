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

use std::collections::VecDeque;

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
    RegistrantEmail,
    RegistrantFullName,
    RegistrantVoicePhone,
    RegistrantFaxPhone,
    RegistrantContactUri,
    RegistrantCountryName,
    RegistrantCountryCode,

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
    VoicePhone,
    FaxPhone,
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

    // Generic
    Name,
    Type,
    ParentHandle,
}

/// Name/value pair
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameValue {
    name: String,
    value: FilterValue,
}

/// The extracted value from a filter operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterValue {
    StringVal(String),
    StringArray(Vec<String>),
    NameValueArray(Vec<NameValue>),
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
        if entity.is_entity_role(&role.to_string()) {
            if let Some(contact) = entity.contact() {
                if let Some(email) = contact.email().map(|e| e.email().to_string()) {
                    return Some(email);
                }
            }
        }
        queue.extend(entity.entities());
    }
    None
}

pub(crate) fn find_entity_full_name_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Option<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string()) {
            if let Some(contact) = entity.contact() {
                if let Some(name) = contact.full_name().map(|n| n.to_string()) {
                    return Some(name);
                }
            }
        }
        queue.extend(entity.entities());
    }
    None
}

pub(crate) fn find_entity_voice_phone_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Option<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string()) {
            if let Some(contact) = entity.contact() {
                if let Some(phone) = contact.voice_phone().map(|p| p.phone().to_string()) {
                    return Some(phone);
                }
            }
        }
        queue.extend(entity.entities());
    }
    None
}

pub(crate) fn find_entity_fax_phone_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Option<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string()) {
            if let Some(contact) = entity.contact() {
                if let Some(phone) = contact.fax_phone().map(|p| p.phone().to_string()) {
                    return Some(phone);
                }
            }
        }
        queue.extend(entity.entities());
    }
    None
}

pub(crate) fn find_entity_contact_uris_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Vec<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string()) {
            if let Some(contact) = entity.contact() {
                return contact
                    .contact_uris()
                    .iter()
                    .map(|u| u.to_string())
                    .collect();
            }
        }
        queue.extend(entity.entities());
    }
    Vec::new()
}

pub(crate) fn find_entity_country_names_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Vec<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string()) {
            if let Some(contact) = entity.contact() {
                return contact
                    .postal_addresses()
                    .iter()
                    .filter_map(|a| a.country_name())
                    .map(|n| n.to_string())
                    .collect();
            }
        }
        queue.extend(entity.entities());
    }
    Vec::new()
}

pub(crate) fn find_entity_country_codes_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Vec<String> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string()) {
            if let Some(contact) = entity.contact() {
                return contact
                    .postal_addresses()
                    .iter()
                    .filter_map(|a| a.country_code())
                    .map(|c| c.to_string())
                    .collect();
            }
        }
        queue.extend(entity.entities());
    }
    Vec::new()
}
