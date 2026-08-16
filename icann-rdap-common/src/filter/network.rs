//! Network filter implementation.
//!
//! Extracts fields from [`crate::response::Network`] RDAP objects.
//!
//! # Supported Filters
//!
//! | Filter | Value Type | Description |
//! |---|---|---|
//! | `Handle` | `StringVal` | Network handle |
//! | `Status` | `StringArray` | Status list |
//! | `ObjectClassName` | `StringVal` | Always `"network"` |
//! | `Event` | `HashMapVal` | Event actions mapped to dates |
//! | `RdapConformance` | `StringArray` | RDAP conformance URIs |
//! | `StartIpAddress` | `StringVal` | First IP in the range |
//! | `EndIpAddress` | `StringVal` | Last IP in the range |
//! | `IpVersion` | `StringVal` | `"v4"` or `"v6"` |
//! | `Name` | `StringVal` | Network name |
//! | `Type` | `StringVal` | Network type (e.g., `"ASSIGNED PORTABLE PREFIX"`) |
//! | `ParentHandle` | `StringVal` | Parent network handle |
//! | `Cidr` | `StringArray` | CIDR notation entries |
//! | Entity roles | Various | Extract from nested entities |

use super::*;
use crate::response::{CommonFields, Network, ObjectCommonFields};

impl Filterable for Network {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.handle()),
                },
                Filter::Status => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.status().iter().map(|s| s.to_string()).collect(),
                    ),
                },
                Filter::ObjectClassName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringVal(self.object_class_name().to_string()),
                },
                Filter::Event => FilterOutput {
                    filter: *f,
                    value: FilterValue::HashMapVal(
                        self.events()
                            .iter()
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
                        self.common()
                            .rdap_conformance
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|ext| ext.0.clone())
                            .collect(),
                    ),
                },
                Filter::StartIpAddress => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.start_address()),
                },
                Filter::EndIpAddress => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.end_address()),
                },
                Filter::IpVersion => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.ip_version()),
                },
                Filter::Name => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.name()),
                },
                Filter::Type => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.network_type()),
                },
                Filter::ParentHandle => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.parent_handle()),
                },
                Filter::Cidr => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.cidr0_cidrs()
                            .iter()
                            .filter_map(|c| {
                                let prefix = c.prefix()?;
                                let length = c.length()?;
                                Some(format!("{}/{}", prefix, length))
                            })
                            .collect(),
                    ),
                },
                _ => entity_role_filter_output(ObjectCommonFields::entities(self), *f).unwrap_or(
                    FilterOutput {
                        filter: *f,
                        value: FilterValue::Null,
                    },
                ),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Contact;

    fn make_test_network() -> Network {
        let registrant = Contact::builder().full_name("Network Admin").build();

        Network::builder()
            .cidr("192.0.2.0/24")
            .handle("NET-192-0-2-0-1")
            .name("EXAMPLE-NET")
            .network_type("ASSIGNED PORTABLE PREFIX")
            .parent_handle("TOP-LEVEL-NET")
            .status("active")
            .entity(
                Entity::response_obj()
                    .handle("REGISTRANT-HANDLE")
                    .role("registrant")
                    .contact(registrant)
                    .build(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("NET-192-0-2-0-1".to_string())
        );
    }

    #[test]
    fn filter_start_ip_address() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::StartIpAddress];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("192.0.2.0".to_string())
        );
    }

    #[test]
    fn filter_end_ip_address() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::EndIpAddress];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("192.0.2.255".to_string())
        );
    }

    #[test]
    fn filter_ip_version() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::IpVersion];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(results[0].value, FilterValue::StringVal("v4".to_string()));
    }

    #[test]
    fn filter_name() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::Name];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("EXAMPLE-NET".to_string())
        );
    }

    #[test]
    fn filter_type() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::Type];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("ASSIGNED PORTABLE PREFIX".to_string())
        );
    }

    #[test]
    fn filter_parent_handle() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::ParentHandle];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("TOP-LEVEL-NET".to_string())
        );
    }

    #[test]
    fn filter_cidr() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::Cidr];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 1);
                assert!(s.contains(&"192.0.2.0/24".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::Status];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 1);
                assert!(s.contains(&"active".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_full_name() {
        // GIVEN
        let network = make_test_network();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&network, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("Network Admin".to_string())
        );
    }
}
