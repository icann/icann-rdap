use super::*;
use crate::response::{AutnumSearchResults, CommonFields, ObjectCommonFields};

impl Filterable for AutnumSearchResults {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|a| a.handle())
                            .map(|h| h.to_string())
                            .collect(),
                    ),
                },
                Filter::Status => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|a| a.status())
                            .map(|s| s.to_string())
                            .collect(),
                    ),
                },
                Filter::ObjectClassName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .map(|a| a.object_class_name().to_string())
                            .collect(),
                    ),
                },
                Filter::Event => FilterOutput {
                    filter: *f,
                    value: FilterValue::HashMapVal(
                        self.results()
                            .iter()
                            .flat_map(|a| a.events())
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
                            .filter_map(|a| a.common().rdap_conformance.as_ref())
                            .flatten()
                            .map(|ext| ext.0.clone())
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
    use crate::prelude::{Autnum, Email, Event};
    use crate::response::ExtensionId;

    fn make_test_autnum_1() -> Autnum {
        let registrant_contact = Contact::builder()
            .full_name("Autnum Registrant Owner")
            .emails(vec![
                Email::builder().email("registrant1@example.com").build(),
            ])
            .build();
        let abuse_contact = Contact::builder()
            .full_name("Autnum Abuse Contact")
            .emails(vec![Email::builder().email("abuse1@example.com").build()])
            .build();
        let tech_contact = Contact::builder()
            .full_name("Autnum Tech Contact")
            .emails(vec![Email::builder().email("tech1@example.com").build()])
            .build();
        let registrar_contact = Contact::builder()
            .full_name("Autnum Registrar Inc")
            .emails(vec![
                Email::builder().email("registrar1@example.com").build(),
            ])
            .build();

        Autnum::builder()
            .autnum_range(12345..12350)
            .handle("AS12345")
            .name("EXAMPLE-AS-1")
            .autnum_type("DIRECT ALLOCATION")
            .country("US")
            .status("active")
            .entity(
                Entity::response_obj()
                    .handle("REGISTRANT-HANDLE-1")
                    .role("registrant")
                    .contact(registrant_contact)
                    .build(),
            )
            .entity(
                Entity::response_obj()
                    .handle("ABUSE-HANDLE-1")
                    .role("abuse")
                    .contact(abuse_contact)
                    .build(),
            )
            .entity(
                Entity::response_obj()
                    .handle("TECH-HANDLE-1")
                    .role("technical")
                    .contact(tech_contact)
                    .build(),
            )
            .entity(
                Entity::response_obj()
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
    }

    fn make_test_autnum_2() -> Autnum {
        let registrant_contact = Contact::builder()
            .full_name("Autnum Registrant Two")
            .emails(vec![
                Email::builder().email("registrant2@example.com").build(),
            ])
            .build();
        let abuse_contact = Contact::builder()
            .full_name("Autnum Abuse Two")
            .emails(vec![Email::builder().email("abuse2@example.com").build()])
            .build();
        let tech_contact = Contact::builder()
            .full_name("Autnum Tech Two")
            .emails(vec![Email::builder().email("tech2@example.com").build()])
            .build();
        let registrar_contact = Contact::builder()
            .full_name("Autnum Registrar Two")
            .emails(vec![
                Email::builder().email("registrar2@example.com").build(),
            ])
            .build();

        Autnum::builder()
            .autnum_range(54321..54330)
            .handle("AS54321")
            .name("EXAMPLE-AS-2")
            .autnum_type("RESOURCE PORTABLE")
            .country("GB")
            .status("active")
            .entity(
                Entity::response_obj()
                    .handle("REGISTRANT-HANDLE-2")
                    .role("registrant")
                    .contact(registrant_contact)
                    .build(),
            )
            .entity(
                Entity::response_obj()
                    .handle("ABUSE-HANDLE-2")
                    .role("abuse")
                    .contact(abuse_contact)
                    .build(),
            )
            .entity(
                Entity::response_obj()
                    .handle("TECH-HANDLE-2")
                    .role("technical")
                    .contact(tech_contact)
                    .build(),
            )
            .entity(
                Entity::response_obj()
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
    }

    fn make_test_autnum_search_results() -> AutnumSearchResults {
        let extensions = vec![
            ExtensionId::RdapLevel0.to_extension(),
            ExtensionId::AutnumSearchResults.to_extension(),
        ];
        AutnumSearchResults::response_obj()
            .results(vec![make_test_autnum_1(), make_test_autnum_2()])
            .extensions(extensions)
            .build()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Handle);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"AS12345".to_string()));
                assert!(s.contains(&"AS54321".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
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
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::ObjectClassName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::ObjectClassName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"autnum".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_event() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::Event];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Event);
        match &results[0].value {
            FilterValue::HashMapVal(hm) => {
                assert_eq!(hm.len(), 2);
                assert!(hm.contains_key("registration"));
                assert!(hm.contains_key("last changed"));
            }
            _ => panic!("Expected HashMapVal"),
        }
    }

    #[test]
    fn filter_rdap_conformance() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::RdapConformance];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RdapConformance);
        // Autnum::builder() uses Common::builder() which sets rdap_conformance to None,
        // so the result is an empty array (no rdap_conformance on individual Autnum objects)
        match &results[0].value {
            FilterValue::StringArray(s) => {
                // Empty because Autnum::builder() doesn't set rdap_conformance
                assert_eq!(s.len(), 0);
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_email() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
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
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrantFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Autnum Registrant Owner".to_string()));
                assert!(s.contains(&"Autnum Registrant Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_abuse_email() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
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
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::AbuseFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::AbuseFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Autnum Abuse Contact".to_string()));
                assert!(s.contains(&"Autnum Abuse Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_technical_email() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
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
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::TechnicalFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::TechnicalFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Autnum Tech Contact".to_string()));
                assert!(s.contains(&"Autnum Tech Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrar_email() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
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
        let search_results = make_test_autnum_search_results();
        let filters = vec![Filter::RegistrarFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrarFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Autnum Registrar Inc".to_string()));
                assert!(s.contains(&"Autnum Registrar Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_unknown_returns_null() {
        // GIVEN
        let search_results = make_test_autnum_search_results();
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
        let search_results = make_test_autnum_search_results();
        let filters = vec![
            Filter::Handle,
            Filter::Status,
            Filter::ObjectClassName,
            Filter::RegistrantEmail,
            Filter::AbuseEmail,
        ];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 5);
        assert_eq!(results[0].filter, Filter::Handle);
        assert_eq!(results[1].filter, Filter::Status);
        assert_eq!(results[2].filter, Filter::ObjectClassName);
        assert_eq!(results[3].filter, Filter::RegistrantEmail);
        assert_eq!(results[4].filter, Filter::AbuseEmail);
    }
}
