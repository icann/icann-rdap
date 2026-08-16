//! Nameserver search results filter implementation.
//!
//! Extracts fields from [`crate::response::NameserverSearchResults`] RDAP objects.
//! Values are aggregated across all search results into arrays.
//!
//! # Supported Filters
//!
//! | Filter | Value Type | Description |
//! |---|---|---|
//! | `Handle` | `StringArray` | Handles from all results |
//! | `Status` | `StringArray` | Statuses from all results |
//! | `ObjectClassName` | `StringArray` | Object class names from all results |
//! | `Event` | `HashMapVal` | Events aggregated from all results |
//! | `RdapConformance` | `StringArray` | Conformance URIs from all results |
//! | `IpAddress` | `StringArray` | IP addresses from all results |
//! | Entity roles | `StringArray` | Role-based fields aggregated from all results |

use super::*;
use crate::response::{CommonFields, NameserverSearchResults, ObjectCommonFields};

impl Filterable for NameserverSearchResults {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|n| n.handle())
                            .map(|h| h.to_string())
                            .collect(),
                    ),
                },
                Filter::Status => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|n| n.status())
                            .map(|s| s.to_string())
                            .collect(),
                    ),
                },
                Filter::ObjectClassName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .map(|n| n.object_class_name().to_string())
                            .collect(),
                    ),
                },
                Filter::Event => FilterOutput {
                    filter: *f,
                    value: FilterValue::HashMapVal(
                        self.results()
                            .iter()
                            .flat_map(|n| n.events())
                            .filter_map(|e| {
                                let action = e.event_action()?;
                                let date = e.event_date()?;
                                Some((action.to_string(), FilterValue::StringVal(date.to_string())))
                            })
                            .collect(),
                    ),
                },
                Filter::RdapConformance => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|n| n.common().rdap_conformance.as_ref())
                            .flatten()
                            .map(|ext| ext.0.clone())
                            .collect(),
                    ),
                },
                Filter::IpAddress => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|n| n.ip_addresses())
                            .flat_map(|ip| ip.v4s())
                            .chain(
                                self.results()
                                    .iter()
                                    .flat_map(|n| n.ip_addresses())
                                    .flat_map(|ip| ip.v6s()),
                            )
                            .map(|ip| ip.to_string())
                            .collect(),
                    ),
                },
                _ => entity_role_filter_output_search(self.results().iter(), *f),
            })
            .collect()
    }
}
