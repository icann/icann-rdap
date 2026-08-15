//! Filter module for extracting fields from RDAP responses.
//!
//! This module provides a way to extract selected fields from any RDAP response
//! into a typed array of name/value pairs suitable for CSV serialization.
//!
//! # Architecture
//!
//! The filter system works through three key abstractions:
//!
//! 1. [`Filter`] — An enum listing all extractable fields across all RDAP object types.
//! 2. [`Filterable`] — A trait implemented by all RDAP response types that allows
//!    extracting a subset of [`Filter`] fields into [`FilterOutput`] values.
//! 3. [`extract`] — A convenience function that works with any type implementing [`Filterable`].
//!
//! # Filterable RDAP Object Types
//!
//! The following RDAP response types implement [`Filterable`]:
//!
//! | Object Type | Key Filters |
//! |---|---|
//! | [`crate::response::Domain`] | `ldh_name`, `unicode_name`, `handle`, `status`, `nameserver`, `nameserver_ip_address`, `public_id`, entity roles |
//! | [`crate::response::DomainSearchResults`] | Same as Domain, aggregated across search results |
//! | [`crate::response::Autnum`] | `start_autnum`, `end_autnum`, `handle`, `status`, `name`, `type`, entity roles |
//! | [`crate::response::AutnumSearchResults`] | Same as Autnum, aggregated across search results |
//! | [`crate::response::Entity`] | `role`, `email`, `full_name`, `voice`, `fax`, `contact_uri`, `country_name`, `country_code`, `public_id` |
//! | [`crate::response::EntitySearchResults`] | Same as Entity, aggregated across search results |
//! | [`crate::response::Nameserver`] | `ip_address`, `handle`, `status`, entity roles |
//! | [`crate::response::NameserverSearchResults`] | Same as Nameserver, aggregated across search results |
//! | [`crate::response::Network`] | `start_ip_address`, `end_ip_address`, `ip_version`, `cidr`, `handle`, `parent_handle`, entity roles |
//! | [`crate::response::IpSearchResults`] | Same as Network, aggregated across search results |
//! | [`crate::response::RdapResponse`] | Delegates to the inner object type's filter implementation |
//!
//! # Entity Role Filters
//!
//! Several filters extract contact information from nested entities by role.
//! These work recursively through the entity hierarchy:
//!
//! - `registrant_*` — Extracts fields from entities with role `registrant`
//! - `abuse_*` — Extracts fields from entities with role `abuse`
//! - `technical_*` — Extracts fields from entities with role `technical`
//! - `registrar_*` — Extracts fields from entities with role `registrar`
//!
//! For search results, role filters aggregate values across all search result entries.
//!
//! # FilterValue Types
//!
//! Each filter extracts a value of one of the following types:
//!
//! | Variant | Description | Example |
//! |---|---|---|
//! | `StringVal` | Single string | `"example.com"` |
//! | `StringArray` | Multiple strings | `["active", "clientTransferProhibited"]` |
//! | `IntVal` | Single integer | `12345` |
//! | `IntArray` | Multiple integers | `[12345, 12350]` |
//! | `BoolVal` | Boolean | `true` |
//! | `HashMapVal` | Key-value pairs | `{"IANA Registrar ID": "1234"}` |
//! | `Null` | Missing/absent value | — |
//!
//! # Example
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//! use icann_rdap_common::filter::*;
//!
//! // Build a domain object
//! let domain = Domain::builder()
//!     .ldh_name("example.com")
//!     .handle("EXAMPLE-DOM")
//!     .statuses(vec!["active".to_string(), "client transfer prohibited".to_string()])
//!     .build();
//!
//! // Define which fields to extract
//! let filters = vec![
//!     Filter::LdhName,
//!     Filter::Handle,
//!     Filter::Status,
//! ];
//!
//! // Extract the selected fields
//! let results = extract(&domain, &filters);
//!
//! // Verify the extracted values
//! assert_eq!(results.len(), 3);
//! assert_eq!(results[0].value, FilterValue::StringVal("example.com".to_string()));
//! assert_eq!(results[1].value, FilterValue::StringVal("EXAMPLE-DOM".to_string()));
//! match &results[2].value {
//!     FilterValue::StringArray(statuses) => {
//!         assert_eq!(statuses.len(), 2);
//!     }
//!     _ => panic!("Expected StringArray for Status"),
//! }
//! ```
//!
//! # Example: Entity Role Filters
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//! use icann_rdap_common::filter::*;
//!
//! let registrant_email = Email::builder().email("admin@example.com").build();
//! let registrant_contact = Contact::builder()
//!     .full_name("Admin User")
//!     .emails(vec![registrant_email])
//!     .build();
//!
//! let domain = Domain::response_obj()
//!     .ldh_name("example.com")
//!     .entity(
//!         Entity::response_obj()
//!             .handle("REG-HANDLE")
//!             .role("registrant")
//!             .contact(registrant_contact)
//!             .build(),
//!     )
//!     .build();
//!
//! let filters = vec![
//!     Filter::RegistrantEmail,
//!     Filter::RegistrantFullName,
//! ];
//!
//! let results = extract(&domain, &filters);
//!
//! assert_eq!(results[0].value, FilterValue::StringVal("admin@example.com".to_string()));
//! assert_eq!(results[1].value, FilterValue::StringVal("Admin User".to_string()));
//! ```
//!
//! # Example: Search Results
//!
//! ```rust
//! use icann_rdap_common::prelude::*;
//! use icann_rdap_common::filter::*;
//!
//! let domain1 = Domain::response_obj()
//!     .ldh_name("example1.com")
//!     .handle("EXAMPLE1-DOM")
//!     .build();
//!
//! let domain2 = Domain::response_obj()
//!     .ldh_name("example2.com")
//!     .handle("EXAMPLE2-DOM")
//!     .build();
//!
//! let search_results = DomainSearchResults::response_obj()
//!     .results(vec![domain1, domain2])
//!     .build();
//!
//! let filters = vec![Filter::LdhName, Filter::Handle];
//! let results = extract(&search_results, &filters);
//!
//! assert_eq!(results.len(), 2);
//! match &results[0].value {
//!     FilterValue::StringArray(names) => {
//!         assert_eq!(names.len(), 2);
//!         assert!(names.contains(&"example1.com".to_string()));
//!         assert!(names.contains(&"example2.com".to_string()));
//!     }
//!     _ => panic!("Expected StringArray"),
//! }
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
///
/// Each variant corresponds to a specific field that can be extracted from
/// RDAP objects. The filter system maps each variant to the appropriate
/// extraction logic based on the RDAP object type.
///
/// # Object Class Common Fields
///
/// These fields are available on all RDAP object types:
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Filter {
    // Object class common (all types)
    /// The object's handle (e.g., `"EXAMPLE-DOM"`, `"NET-192-0-2-0-1"`).
    Handle,
    /// The object's status list (e.g., `["active", "client transfer prohibited"]`).
    Status,
    /// The object class name (e.g., `"domain"`, `"autnum"`, `"entity"`, `"network"`, `"nameserver"`).
    ObjectClassName,
    /// Event data as key-value pairs of action → date (e.g., `{"registration": "2020-01-01T00:00:00Z"}`).
    Event,
    /// RDAP conformance URIs (e.g., `["rdap_level_0", "icann_rdap_response_profile_1"]`).
    RdapConformance,

    // Domain-specific
    /// The LDH (ASCII) domain name (e.g., `"example.com"`).
    LdhName,
    /// The Unicode (internationalized) domain name (e.g., `"例え.com"`).
    UnicodeName,
    /// The list of nameserver domain names associated with this domain.
    Nameserver,
    /// IP addresses from all nameservers associated with this domain as a map of
    /// nameserver ldh_name → IP address list (both IPv4 and IPv6 combined).
    NameserverIpAddress,
    /// Public identifiers as key-value pairs (e.g., `{"IANA Registrar ID": "1234"}`).
    PublicId,

    // Nameservers
    /// IP addresses associated with nameservers (both IPv4 and IPv6 combined).
    IpAddress,

    // Entity-specific
    /// The entity's role(s) (e.g., `["registrant", "admin"]`).
    Role,
    /// Email addresses associated with the entity's contact information.
    Email,
    /// The full name from the entity's contact information.
    FullName,
    /// The voice/telephone number from the entity's contact information.
    Voice,
    /// The fax number from the entity's contact information.
    Fax,
    /// Contact URIs (URLs) from the entity's contact information.
    ContactUri,
    /// Country name(s) from the entity's postal address(es).
    CountryName,
    /// Country code(s) from the entity's postal address(es).
    CountryCode,

    // Autnum-specific
    /// The starting autonomous system number (e.g., `12345`).
    StartAutnum,
    /// The ending autonomous system number (e.g., `12350`).
    EndAutnum,

    // Network-specific
    /// The start IP address of the network range (e.g., `"192.0.2.0"`).
    StartIpAddress,
    /// The end IP address of the network range (e.g., `"192.0.2.255"`).
    EndIpAddress,
    /// The IP version (`"v4"` or `"v6"`).
    IpVersion,
    /// CIDR notation entries (e.g., `"192.0.2.0/24"`).
    Cidr,

    // Generic
    /// A generic name field (used by Autnum, Network).
    Name,
    /// A generic type field (e.g., autnum type, network type).
    Type,
    /// The parent object's handle (used by Network).
    ParentHandle,

    /// Registrant email address (extracted from nested entities with role `registrant`).
    RegistrantEmail,
    /// Registrant full name (extracted from nested entities with role `registrant`).
    RegistrantFullName,
    /// Registrant voice/phone (extracted from nested entities with role `registrant`).
    RegistrantVoice,
    /// Registrant fax (extracted from nested entities with role `registrant`).
    RegistrantFax,
    /// Registrant contact URIs (extracted from nested entities with role `registrant`).
    RegistrantContactUri,
    /// Registrant country name(s) (extracted from nested entities with role `registrant`).
    RegistrantCountryName,
    /// Registrant country code(s) (extracted from nested entities with role `registrant`).
    RegistrantCountryCode,
    /// Registrant public identifiers as key-value pairs (extracted from nested entities with role `registrant`).
    RegistrantPublicId,

    /// Abuse contact email (extracted from nested entities with role `abuse`).
    AbuseEmail,
    /// Abuse contact full name (extracted from nested entities with role `abuse`).
    AbuseFullName,
    /// Abuse contact voice/phone (extracted from nested entities with role `abuse`).
    AbuseVoice,
    /// Abuse contact fax (extracted from nested entities with role `abuse`).
    AbuseFax,
    /// Abuse contact URIs (extracted from nested entities with role `abuse`).
    AbuseContactUri,
    /// Abuse contact country name(s) (extracted from nested entities with role `abuse`).
    AbuseCountryName,
    /// Abuse contact country code(s) (extracted from nested entities with role `abuse`).
    AbuseCountryCode,
    /// Abuse contact public identifiers as key-value pairs (extracted from nested entities with role `abuse`).
    AbusePublicId,

    /// Technical contact email (extracted from nested entities with role `technical`).
    TechnicalEmail,
    /// Technical contact full name (extracted from nested entities with role `technical`).
    TechnicalFullName,
    /// Technical contact voice/phone (extracted from nested entities with role `technical`).
    TechnicalVoice,
    /// Technical contact fax (extracted from nested entities with role `technical`).
    TechnicalFax,
    /// Technical contact URIs (extracted from nested entities with role `technical`).
    TechnicalContactUri,
    /// Technical contact country name(s) (extracted from nested entities with role `technical`).
    TechnicalCountryName,
    /// Technical contact country code(s) (extracted from nested entities with role `technical`).
    TechnicalCountryCode,
    /// Technical contact public identifiers as key-value pairs (extracted from nested entities with role `technical`).
    TechnicalPublicId,

    /// Registrar email (extracted from nested entities with role `registrar`).
    RegistrarEmail,
    /// Registrar full name (extracted from nested entities with role `registrar`).
    RegistrarFullName,
    /// Registrar voice/phone (extracted from nested entities with role `registrar`).
    RegistrarVoice,
    /// Registrar fax (extracted from nested entities with role `registrar`).
    RegistrarFax,
    /// Registrar contact URIs (extracted from nested entities with role `registrar`).
    RegistrarContactUri,
    /// Registrar country name(s) (extracted from nested entities with role `registrar`).
    RegistrarCountryName,
    /// Registrar country code(s) (extracted from nested entities with role `registrar`).
    RegistrarCountryCode,
    /// Registrar public identifiers as key-value pairs (extracted from nested entities with role `registrar`).
    RegistrarPublicId,
}

/// The extracted value from a filter operation.
///
/// Each variant wraps a different Rust type that corresponds to the kind of data
/// extracted by a [`Filter`]. The `#[serde(untagged)]` attribute enables flexible
/// serialization/deserialization.
///
/// # Examples
///
/// ```rust
/// use icann_rdap_common::filter::{Filter, FilterValue};
///
/// // Single string value
/// let val = FilterValue::StringVal("example.com".to_string());
/// assert_eq!(val.string_value(), Some("example.com"));
///
/// // Array of strings
/// let val = FilterValue::StringArray(vec!["active".to_string(), "clientTransferProhibited".to_string()]);
/// assert_eq!(val.string_values().len(), 2);
///
/// // Integer value
/// let val = FilterValue::IntVal(12345);
/// assert_eq!(val.int_value(), Some(12345));
///
/// // Key-value pairs
/// let mut map = std::collections::HashMap::new();
/// map.insert("IANA Registrar ID".to_string(), FilterValue::StringVal("1234".to_string()));
/// let val = FilterValue::HashMapVal(map);
/// assert!(val.hash_map().contains_key("IANA Registrar ID"));
///
/// // Null/missing value
/// let val = FilterValue::Null;
/// assert!(val.is_null());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    /// A single string value.
    StringVal(String),
    /// An array of string values.
    StringArray(Vec<String>),
    /// A map of string keys to `FilterValue` values.
    HashMapVal(HashMap<String, FilterValue>),
    /// A single 64-bit integer value.
    IntVal(i64),
    /// An array of 64-bit integer values.
    IntArray(Vec<i64>),
    /// A boolean value.
    BoolVal(bool),
    /// A null/missing value (used when a filter has no data to extract).
    Null,
}

static EMPTY_HASHMAP: LazyLock<HashMap<String, FilterValue>> = LazyLock::new(HashMap::new);

impl FilterValue {
    /// Returns a reference to the inner string if this is `StringVal`, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::FilterValue;
    ///
    /// let val = FilterValue::StringVal("hello".to_string());
    /// assert_eq!(val.string_value(), Some("hello"));
    ///
    /// let val = FilterValue::Null;
    /// assert_eq!(val.string_value(), None);
    /// ```
    pub fn string_value(&self) -> Option<&str> {
        match self {
            FilterValue::StringVal(s) => Some(s),
            _ => None,
        }
    }

    /// Consumes `self` and returns the owned string if this is `StringVal`, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::FilterValue;
    ///
    /// let val = FilterValue::StringVal("hello".to_string());
    /// assert_eq!(val.into_string_value(), Some("hello".to_string()));
    /// ```
    pub fn into_string_value(self) -> Option<String> {
        match self {
            FilterValue::StringVal(s) => Some(s),
            _ => None,
        }
    }

    /// Returns a reference to the inner string array if this is `StringArray`,
    /// otherwise an empty slice.
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::FilterValue;
    ///
    /// let val = FilterValue::StringArray(vec!["a".to_string(), "b".to_string()]);
    /// assert_eq!(val.string_values().len(), 2);
    ///
    /// let val = FilterValue::Null;
    /// assert!(val.string_values().is_empty());
    /// ```
    pub fn string_values(&self) -> &[String] {
        match self {
            FilterValue::StringArray(v) => v,
            _ => &[],
        }
    }

    /// Consumes `self` and returns the owned string array if this is `StringArray`,
    /// otherwise an empty `Vec`.
    pub fn into_string_values(self) -> Vec<String> {
        match self {
            FilterValue::StringArray(v) => v,
            _ => Vec::new(),
        }
    }

    /// Returns the integer value if this is `IntVal`, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::FilterValue;
    ///
    /// let val = FilterValue::IntVal(42);
    /// assert_eq!(val.int_value(), Some(42));
    ///
    /// let val = FilterValue::Null;
    /// assert_eq!(val.int_value(), None);
    /// ```
    pub fn int_value(&self) -> Option<i64> {
        match self {
            FilterValue::IntVal(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns a reference to the inner integer array if this is `IntArray`,
    /// otherwise an empty slice.
    pub fn int_values(&self) -> &[i64] {
        match self {
            FilterValue::IntArray(v) => v,
            _ => &[],
        }
    }

    /// Consumes `self` and returns the owned integer array if this is `IntArray`,
    /// otherwise an empty `Vec`.
    pub fn into_int_values(self) -> Vec<i64> {
        match self {
            FilterValue::IntArray(v) => v,
            _ => Vec::new(),
        }
    }

    /// Returns the boolean value if this is `BoolVal`, otherwise `None`.
    pub fn bool_value(&self) -> Option<bool> {
        match self {
            FilterValue::BoolVal(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns a reference to the inner `HashMap` if this is `HashMapVal`,
    /// otherwise an empty static map.
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::FilterValue;
    ///
    /// let val = FilterValue::Null;
    /// assert!(val.hash_map().is_empty());
    /// ```
    pub fn hash_map(&self) -> &HashMap<String, FilterValue> {
        match self {
            FilterValue::HashMapVal(m) => m,
            _ => &EMPTY_HASHMAP,
        }
    }

    /// Consumes `self` and returns the owned `HashMap` if this is `HashMapVal`,
    /// otherwise an empty map.
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
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::FilterValue;
    ///
    /// assert!(FilterValue::Null.is_empty());
    /// assert!(FilterValue::StringArray(vec![]).is_empty());
    /// assert!(!FilterValue::StringVal("hello".to_string()).is_empty());
    /// ```
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
    /// # Formatting Rules
    ///
    /// | Variant | Format |
    /// |---|---|
    /// | `StringVal` | The string itself |
    /// | `StringArray` | Values joined by `\|` |
    /// | `HashMapVal` | `key=value` pairs joined by `\|` |
    /// | `IntVal` | Integer as string |
    /// | `IntArray` | Values joined by `\|` |
    /// | `BoolVal` | `"true"` or `"false"` |
    /// | `Null` | Empty string |
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::FilterValue;
    ///
    /// let val = FilterValue::StringArray(vec!["a".to_string(), "b".to_string()]);
    /// assert_eq!(val.to_display_string(), "a|b");
    ///
    /// let val = FilterValue::Null;
    /// assert_eq!(val.to_display_string(), "");
    /// ```
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
///
/// Each `FilterOutput` pairs a [`Filter`] variant with the [`FilterValue`]
/// extracted from an RDAP response. The `filter` field identifies which field
/// was extracted, and `value` contains the actual data.
///
/// # Example
///
/// ```rust
/// use icann_rdap_common::filter::{Filter, FilterOutput, FilterValue};
///
/// let output = FilterOutput {
///     filter: Filter::LdhName,
///     value: FilterValue::StringVal("example.com".to_string()),
/// };
///
/// assert_eq!(output.filter, Filter::LdhName);
/// assert_eq!(output.string_value(), Some("example.com"));
/// assert!(!output.is_null());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterOutput {
    /// The filter that was applied.
    pub filter: Filter,
    /// The extracted value.
    pub value: FilterValue,
}

impl FilterOutput {
    /// Returns the string value if the inner `FilterValue` is `StringVal`, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::{Filter, FilterOutput, FilterValue};
    ///
    /// let output = FilterOutput {
    ///     filter: Filter::LdhName,
    ///     value: FilterValue::StringVal("example.com".to_string()),
    /// };
    /// assert_eq!(output.string_value(), Some("example.com"));
    ///
    /// let output = FilterOutput {
    ///     filter: Filter::LdhName,
    ///     value: FilterValue::Null,
    /// };
    /// assert_eq!(output.string_value(), None);
    /// ```
    pub fn string_value(&self) -> Option<&str> {
        self.value.string_value()
    }

    /// Returns `true` if the inner `FilterValue` is `Null`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use icann_rdap_common::filter::{Filter, FilterOutput, FilterValue};
    ///
    /// let output = FilterOutput {
    ///     filter: Filter::LdhName,
    ///     value: FilterValue::Null,
    /// };
    /// assert!(output.is_null());
    /// ```
    pub fn is_null(&self) -> bool {
        self.value.is_null()
    }
}

/// The result type for filter operations — a vector of filter outputs.
///
/// Each element in the vector corresponds to one of the requested [`Filter`]
/// values, in the same order as the input filter list.
///
/// # Example
///
/// ```rust
/// use icann_rdap_common::prelude::*;
/// use icann_rdap_common::filter::*;
///
/// let domain = Domain::builder()
///     .ldh_name("example.com")
///     .handle("EXAMPLE-DOM")
///     .build();
///
/// let filters = vec![Filter::LdhName, Filter::Handle];
/// let result: FilterResult = extract(&domain, &filters);
///
/// assert_eq!(result.len(), 2);
/// ```
pub type FilterResult = Vec<FilterOutput>;

/// Trait for types that can be filtered.
///
/// Implement this trait for RDAP response types to enable field extraction
/// via the [`extract`] function. The implementation should return a [`FilterResult`]
/// containing one output for each requested filter, in the same order.
///
/// Unknown or unsupported filters should return a [`FilterValue::Null`] output.
///
/// # Implementors
///
/// This trait is implemented for all RDAP response types in this crate:
/// - [`crate::response::Domain`]
/// - [`crate::response::Autnum`]
/// - [`crate::response::Entity`]
/// - [`crate::response::Nameserver`]
/// - [`crate::response::Network`]
/// - [`crate::response::DomainSearchResults`]
/// - [`crate::response::AutnumSearchResults`]
/// - [`crate::response::EntitySearchResults`]
/// - [`crate::response::NameserverSearchResults`]
/// - [`crate::response::IpSearchResults`]
/// - [`crate::response::RdapResponse`]
///
/// # Example
///
/// ```rust
/// use icann_rdap_common::filter::{Filter, Filterable, FilterResult, FilterValue, FilterOutput};
/// use icann_rdap_common::response::Domain;
///
/// // Domain already implements Filterable
/// let domain = Domain::builder()
///     .ldh_name("example.com")
///     .build();
///
/// let filters = vec![Filter::LdhName];
/// let result: FilterResult = domain.filter(&filters);
///
/// assert_eq!(result.len(), 1);
/// assert_eq!(result[0].value, FilterValue::StringVal("example.com".to_string()));
/// ```
pub trait Filterable {
    /// Extract the requested filters from this response.
    ///
    /// Returns a [`FilterResult`] with one entry per requested filter, in the same order.
    /// Filters that don't apply to this object type produce a [`FilterValue::Null`] output.
    fn filter(&self, filters: &[Filter]) -> FilterResult;
}

/// Convenience function to extract filters from any filterable type.
///
/// This is a thin wrapper around [`Filterable::filter`] that provides a
/// function-style interface. It works with any type implementing [`Filterable`].
///
/// # Example
///
/// ```rust
/// use icann_rdap_common::prelude::*;
/// use icann_rdap_common::filter::*;
///
/// let domain = Domain::builder()
///     .ldh_name("example.com")
///     .handle("EXAMPLE-DOM")
///     .statuses(vec!["active".to_string()])
///     .build();
///
/// let filters = vec![Filter::LdhName, Filter::Handle, Filter::Status];
/// let results = extract(&domain, &filters);
///
/// assert_eq!(results.len(), 3);
/// assert_eq!(results[0].value, FilterValue::StringVal("example.com".to_string()));
/// assert_eq!(results[1].value, FilterValue::StringVal("EXAMPLE-DOM".to_string()));
/// ```
pub fn extract<T: Filterable>(response: &T, filters: &[Filter]) -> FilterResult {
    response.filter(filters)
}

/// Convert an `Option<T>` (where T: Display) into a `FilterValue::StringVal` or `Null`.
///
/// This eliminates the common pattern of manually mapping `Option` values:
///
/// ```ignore
/// self.handle()
///     .map(|h| FilterValue::StringVal(h.to_string()))
///     .unwrap_or(FilterValue::Null)
/// ```
///
/// in favor of:
///
/// ```ignore
/// opt_to_string(self.handle())
/// ```
///
/// # Example
///
/// ```rust
/// use icann_rdap_common::filter::{FilterValue, opt_to_string};
///
/// let val = opt_to_string(Some("hello"));
/// assert_eq!(val, FilterValue::StringVal("hello".to_string()));
///
/// let val: FilterValue = opt_to_string::<&str>(None);
/// assert_eq!(val, FilterValue::Null);
/// ```
pub fn opt_to_string<T: std::fmt::Display>(opt: Option<T>) -> FilterValue {
    opt.map(|v| FilterValue::StringVal(v.to_string()))
        .unwrap_or(FilterValue::Null)
}

/// Convert an `Option<u32>` into a `FilterValue::IntVal` or `Null`.
///
/// # Example
///
/// ```rust
/// use icann_rdap_common::filter::{FilterValue, opt_to_i64};
///
/// let val = opt_to_i64(Some(12345));
/// assert_eq!(val, FilterValue::IntVal(12345));
///
/// let val = opt_to_i64(None);
/// assert_eq!(val, FilterValue::Null);
/// ```
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

pub(crate) fn find_entity_public_ids_by_role(
    entities: &[Entity],
    role: EntityRole,
) -> Option<HashMap<String, FilterValue>> {
    let mut queue: VecDeque<&Entity> = entities.iter().collect();
    while let Some(entity) = queue.pop_front() {
        if entity.is_entity_role(&role.to_string()) {
            let public_ids: HashMap<String, FilterValue> = entity
                .public_ids()
                .iter()
                .filter_map(|p| {
                    let id_type = p.id_type()?;
                    let identifier = p.identifier()?;
                    Some((
                        id_type.to_string(),
                        FilterValue::StringVal(identifier.to_string()),
                    ))
                })
                .collect();
            if !public_ids.is_empty() {
                return Some(public_ids);
            }
        }
        queue.extend(ObjectCommonFields::entities(entity));
    }
    None
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
        | Filter::RegistrantCountryCode
        | Filter::RegistrantPublicId => EntityRole::Registrant,
        Filter::AbuseEmail
        | Filter::AbuseFullName
        | Filter::AbuseVoice
        | Filter::AbuseFax
        | Filter::AbuseContactUri
        | Filter::AbuseCountryName
        | Filter::AbuseCountryCode
        | Filter::AbusePublicId => EntityRole::Abuse,
        Filter::TechnicalEmail
        | Filter::TechnicalFullName
        | Filter::TechnicalVoice
        | Filter::TechnicalFax
        | Filter::TechnicalContactUri
        | Filter::TechnicalCountryName
        | Filter::TechnicalCountryCode
        | Filter::TechnicalPublicId => EntityRole::Technical,
        Filter::RegistrarEmail
        | Filter::RegistrarFullName
        | Filter::RegistrarVoice
        | Filter::RegistrarFax
        | Filter::RegistrarContactUri
        | Filter::RegistrarCountryName
        | Filter::RegistrarCountryCode
        | Filter::RegistrarPublicId => EntityRole::Registrar,
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
        Filter::RegistrantPublicId
        | Filter::AbusePublicId
        | Filter::TechnicalPublicId
        | Filter::RegistrarPublicId => FilterValue::HashMapVal(
            find_entity_public_ids_by_role(entities, role).unwrap_or_default(),
        ),
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
        | Filter::RegistrantCountryCode
        | Filter::RegistrantPublicId => EntityRole::Registrant,
        Filter::AbuseEmail
        | Filter::AbuseFullName
        | Filter::AbuseVoice
        | Filter::AbuseFax
        | Filter::AbuseContactUri
        | Filter::AbuseCountryName
        | Filter::AbuseCountryCode
        | Filter::AbusePublicId => EntityRole::Abuse,
        Filter::TechnicalEmail
        | Filter::TechnicalFullName
        | Filter::TechnicalVoice
        | Filter::TechnicalFax
        | Filter::TechnicalContactUri
        | Filter::TechnicalCountryName
        | Filter::TechnicalCountryCode
        | Filter::TechnicalPublicId => EntityRole::Technical,
        Filter::RegistrarEmail
        | Filter::RegistrarFullName
        | Filter::RegistrarVoice
        | Filter::RegistrarFax
        | Filter::RegistrarContactUri
        | Filter::RegistrarCountryName
        | Filter::RegistrarCountryCode
        | Filter::RegistrarPublicId => EntityRole::Registrar,
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
        Filter::RegistrantPublicId
        | Filter::AbusePublicId
        | Filter::TechnicalPublicId
        | Filter::RegistrarPublicId => {
            let mut public_ids: HashMap<String, FilterValue> = HashMap::new();
            for r in results {
                if let Some(pid) = find_entity_public_ids_by_role(r.entities(), role) {
                    public_ids.extend(pid);
                }
            }
            FilterValue::HashMapVal(public_ids)
        }
        _ => FilterValue::Null,
    };

    FilterOutput { filter: f, value }
}

/// Trait for types that can provide entity lists for role-based filtering.
///
/// Implemented by all RDAP response types that may contain nested entities
/// with roles (registrant, abuse, technical, registrar).
pub(crate) trait EntityRoleProvider {
    /// Returns the list of entities associated with this object.
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
