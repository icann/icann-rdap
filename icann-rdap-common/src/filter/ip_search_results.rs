use super::*;
use crate::response::{CommonFields, IpSearchResults, ObjectCommonFields};

impl Filterable for IpSearchResults {
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
                    value: FilterValue::NameValueArray(
                        self.results()
                            .iter()
                            .flat_map(|n| n.events())
                            .filter_map(|e| {
                                let action = e.event_action()?;
                                let date = e.event_date()?;
                                Some(NameValue {
                                    name: action.to_string(),
                                    value: FilterValue::StringVal(date.to_string()),
                                })
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
                Filter::Cidr => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|n| {
                                n.cidr0_cidrs().iter().filter_map(|c| {
                                    let prefix = c.prefix()?;
                                    let length = c.length()?;
                                    Some(format!("{}/{}", prefix, length))
                                })
                            })
                            .collect(),
                    ),
                },
                _ => entity_role_filter_output_search(self.results().iter(), *f),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Contact;
    use crate::prelude::{Email, Event, ExtensionId, Network};
    use crate::response::Entity as EntityType;

    fn make_test_network_1() -> Network {
        let registrant_contact = Contact::builder()
            .full_name("Network Registrant One")
            .emails(vec![
                Email::builder().email("registrant1@example.com").build(),
            ])
            .build();
        let abuse_contact = Contact::builder()
            .full_name("Network Abuse One")
            .emails(vec![Email::builder().email("abuse1@example.com").build()])
            .build();
        let tech_contact = Contact::builder()
            .full_name("Network Tech One")
            .emails(vec![Email::builder().email("tech1@example.com").build()])
            .build();
        let registrar_contact = Contact::builder()
            .full_name("Network Registrar One")
            .emails(vec![
                Email::builder().email("registrar1@example.com").build(),
            ])
            .build();

        Network::builder()
            .cidr("192.0.2.0/24")
            .handle("NET-192-0-2-0-1")
            .name("EXAMPLE-NET-1")
            .network_type("ASSIGNED PORTABLE PREFIX")
            .parent_handle("TOP-LEVEL-NET")
            .status("active")
            .entity(
                EntityType::response_obj()
                    .handle("REGISTRANT-HANDLE-1")
                    .role("registrant")
                    .contact(registrant_contact)
                    .build(),
            )
            .entity(
                EntityType::response_obj()
                    .handle("ABUSE-HANDLE-1")
                    .role("abuse")
                    .contact(abuse_contact)
                    .build(),
            )
            .entity(
                EntityType::response_obj()
                    .handle("TECH-HANDLE-1")
                    .role("technical")
                    .contact(tech_contact)
                    .build(),
            )
            .entity(
                EntityType::response_obj()
                    .handle("REGISTRAR-HANDLE-1")
                    .role("registrar")
                    .contact(registrar_contact)
                    .build(),
            )
            .event(
                Event::builder()
                    .event_action("registration")
                    .event_date("2020-01-01T00:00:00Z")
                    .build(),
            )
            .build()
            .unwrap()
    }

    fn make_test_network_2() -> Network {
        let registrant_contact = Contact::builder()
            .full_name("Network Registrant Two")
            .emails(vec![
                Email::builder().email("registrant2@example.com").build(),
            ])
            .build();
        let abuse_contact = Contact::builder()
            .full_name("Network Abuse Two")
            .emails(vec![Email::builder().email("abuse2@example.com").build()])
            .build();
        let tech_contact = Contact::builder()
            .full_name("Network Tech Two")
            .emails(vec![Email::builder().email("tech2@example.com").build()])
            .build();
        let registrar_contact = Contact::builder()
            .full_name("Network Registrar Two")
            .emails(vec![
                Email::builder().email("registrar2@example.com").build(),
            ])
            .build();

        Network::builder()
            .cidr("198.51.100.0/24")
            .handle("NET-198-51-100-1")
            .name("EXAMPLE-NET-2")
            .network_type("ASSIGNED PORTABLE PREFIX")
            .parent_handle("TOP-LEVEL-NET")
            .status("active")
            .entity(
                EntityType::response_obj()
                    .handle("REGISTRANT-HANDLE-2")
                    .role("registrant")
                    .contact(registrant_contact)
                    .build(),
            )
            .entity(
                EntityType::response_obj()
                    .handle("ABUSE-HANDLE-2")
                    .role("abuse")
                    .contact(abuse_contact)
                    .build(),
            )
            .entity(
                EntityType::response_obj()
                    .handle("TECH-HANDLE-2")
                    .role("technical")
                    .contact(tech_contact)
                    .build(),
            )
            .entity(
                EntityType::response_obj()
                    .handle("REGISTRAR-HANDLE-2")
                    .role("registrar")
                    .contact(registrar_contact)
                    .build(),
            )
            .event(
                Event::builder()
                    .event_action("last changed")
                    .event_date("2023-06-15T12:00:00Z")
                    .build(),
            )
            .build()
            .unwrap()
    }

    fn make_test_ip_search_results() -> IpSearchResults {
        let extensions = vec![
            ExtensionId::RdapLevel0.to_extension(),
            ExtensionId::IpSearchResults.to_extension(),
        ];
        IpSearchResults::response_obj()
            .results(vec![make_test_network_1(), make_test_network_2()])
            .extensions(extensions)
            .build()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Handle);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"NET-192-0-2-0-1".to_string()));
                assert!(s.contains(&"NET-198-51-100-1".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::Status];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Status);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"active".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_object_class_name() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::ObjectClassName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::ObjectClassName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"ip network".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_event() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::Event];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Event);
        match &results[0].value {
            FilterValue::NameValueArray(nva) => {
                assert_eq!(nva.len(), 2);
                let actions: Vec<&str> = nva.iter().map(|nv| nv.name.as_str()).collect();
                assert!(actions.contains(&"registration"));
                assert!(actions.contains(&"last changed"));
            }
            _ => panic!("Expected NameValueArray"),
        }
    }

    #[test]
    fn filter_rdap_conformance() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::RdapConformance];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RdapConformance);
        // Network::builder() uses Common::builder() which sets rdap_conformance to None,
        // so the result is an empty array (no rdap_conformance on individual Network objects)
        match &results[0].value {
            FilterValue::StringArray(s) => {
                // Empty because Network::builder() doesn't set rdap_conformance
                assert_eq!(s.len(), 0);
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_cidr() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::Cidr];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Cidr);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"192.0.2.0/24".to_string()));
                assert!(s.contains(&"198.51.100.0/24".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_email() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::RegistrantEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrantEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"registrant1@example.com".to_string()));
                assert!(s.contains(&"registrant2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_full_name() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrantFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Network Registrant One".to_string()));
                assert!(s.contains(&"Network Registrant Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_abuse_email() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::AbuseEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::AbuseEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"abuse1@example.com".to_string()));
                assert!(s.contains(&"abuse2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_abuse_full_name() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::AbuseFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::AbuseFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Network Abuse One".to_string()));
                assert!(s.contains(&"Network Abuse Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_technical_email() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::TechnicalEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::TechnicalEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"tech1@example.com".to_string()));
                assert!(s.contains(&"tech2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_technical_full_name() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::TechnicalFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::TechnicalFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Network Tech One".to_string()));
                assert!(s.contains(&"Network Tech Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrar_email() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::RegistrarEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrarEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"registrar1@example.com".to_string()));
                assert!(s.contains(&"registrar2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrar_full_name() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::RegistrarFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrarFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Network Registrar One".to_string()));
                assert!(s.contains(&"Network Registrar Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_unknown_returns_null() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![Filter::LdhName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::LdhName);
        assert_eq!(results[0].value, FilterValue::Null);
    }

    #[test]
    fn filter_multiple_filters_at_once() {
        // GIVEN
        let search_results = make_test_ip_search_results();
        let filters = vec![
            Filter::Handle,
            Filter::Status,
            Filter::ObjectClassName,
            Filter::Cidr,
            Filter::RegistrantEmail,
            Filter::AbuseEmail,
        ];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 6);
        assert_eq!(results[0].filter, Filter::Handle);
        assert_eq!(results[1].filter, Filter::Status);
        assert_eq!(results[2].filter, Filter::ObjectClassName);
        assert_eq!(results[3].filter, Filter::Cidr);
        assert_eq!(results[4].filter, Filter::RegistrantEmail);
        assert_eq!(results[5].filter, Filter::AbuseEmail);
    }
}
