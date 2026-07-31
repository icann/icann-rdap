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

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

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
