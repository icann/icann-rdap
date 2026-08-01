use super::*;
use crate::response::{CommonFields, DomainSearchResults, ObjectCommonFields};

impl Filterable for DomainSearchResults {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|d| d.handle())
                            .map(|h| h.to_string())
                            .collect(),
                    ),
                },
                Filter::Status => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|d| d.status())
                            .map(|s| s.to_string())
                            .collect(),
                    ),
                },
                Filter::ObjectClassName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .map(|d| d.object_class_name().to_string())
                            .collect(),
                    ),
                },
                Filter::Event => FilterOutput {
                    filter: *f,
                    value: FilterValue::NameValueArray(
                        self.results()
                            .iter()
                            .flat_map(|d| d.events())
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
                            .filter_map(|d| d.common().rdap_conformance.as_ref())
                            .flatten()
                            .map(|ext| ext.0.clone())
                            .collect(),
                    ),
                },
                Filter::LdhName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|d| d.ldh_name())
                            .map(|n| n.to_string())
                            .collect(),
                    ),
                },
                Filter::UnicodeName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|d| d.unicode_name())
                            .map(|n| n.to_string())
                            .collect(),
                    ),
                },
                Filter::Nameserver => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|d| d.nameservers())
                            .filter_map(|n| n.ldh_name())
                            .map(|n| n.to_string())
                            .collect(),
                    ),
                },
                Filter::PublicId => FilterOutput {
                    filter: *f,
                    value: FilterValue::NameValueArray(
                        self.results()
                            .iter()
                            .flat_map(|d| d.public_ids())
                            .filter_map(|p| {
                                let id_type = p.id_type()?;
                                let identifier = p.identifier()?;
                                Some(NameValue {
                                    name: id_type.to_string(),
                                    value: FilterValue::StringVal(identifier.to_string()),
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
    use crate::prelude::{Domain, Email, Event, ExtensionId, Nameserver, PublicId};
    use crate::response::Entity as EntityType;

    fn make_test_domain_1() -> Domain {
        let registrant_email = Email::builder().email("registrant1@example.com").build();
        let registrant_contact = Contact::builder()
            .full_name("Domain Registrant One")
            .emails(vec![registrant_email])
            .build();

        let abuse_email = Email::builder().email("abuse1@example.com").build();
        let abuse_contact = Contact::builder()
            .full_name("Domain Abuse One")
            .emails(vec![abuse_email])
            .build();

        let tech_email = Email::builder().email("tech1@example.com").build();
        let tech_contact = Contact::builder()
            .full_name("Domain Tech One")
            .emails(vec![tech_email])
            .build();

        let registrar_email = Email::builder().email("registrar1@example.com").build();
        let registrar_contact = Contact::builder()
            .full_name("Domain Registrar One")
            .emails(vec![registrar_email])
            .build();

        Domain::response_obj()
            .handle("EXAMPLE-DOM-1")
            .ldh_name("example1.com")
            .unicode_name("例え1.com")
            .statuses(vec![
                "active".to_string(),
                "clientTransferProhibited".to_string(),
            ])
            .extension(ExtensionId::IcannRdapResponseProfile1.as_ref())
            .extension(ExtensionId::IcannRdapTechnicalImplementationGuide1.as_ref())
            .event(
                Event::builder()
                    .event_action("registration")
                    .event_date("2020-01-01T00:00:00Z")
                    .build(),
            )
            .event(
                Event::builder()
                    .event_action("last changed")
                    .event_date("2021-06-15T00:00:00Z")
                    .build(),
            )
            .nameserver(
                Nameserver::builder()
                    .ldh_name("ns1.example1.com")
                    .build()
                    .unwrap(),
            )
            .nameserver(
                Nameserver::builder()
                    .ldh_name("ns2.example1.com")
                    .build()
                    .unwrap(),
            )
            .public_id(
                PublicId::builder()
                    .id_type("IANA Registrar ID")
                    .identifier("1234")
                    .build(),
            )
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
            .build()
    }

    fn make_test_domain_2() -> Domain {
        let registrant_email = Email::builder().email("registrant2@example.com").build();
        let registrant_contact = Contact::builder()
            .full_name("Domain Registrant Two")
            .emails(vec![registrant_email])
            .build();

        let abuse_email = Email::builder().email("abuse2@example.com").build();
        let abuse_contact = Contact::builder()
            .full_name("Domain Abuse Two")
            .emails(vec![abuse_email])
            .build();

        let tech_email = Email::builder().email("tech2@example.com").build();
        let tech_contact = Contact::builder()
            .full_name("Domain Tech Two")
            .emails(vec![tech_email])
            .build();

        let registrar_email = Email::builder().email("registrar2@example.com").build();
        let registrar_contact = Contact::builder()
            .full_name("Domain Registrar Two")
            .emails(vec![registrar_email])
            .build();

        Domain::response_obj()
            .handle("EXAMPLE-DOM-2")
            .ldh_name("example2.com")
            .unicode_name("例え2.com")
            .statuses(vec!["active".to_string()])
            .extension(ExtensionId::IcannRdapResponseProfile1.as_ref())
            .event(
                Event::builder()
                    .event_action("registration")
                    .event_date("2022-03-10T08:00:00Z")
                    .build(),
            )
            .nameserver(
                Nameserver::builder()
                    .ldh_name("ns1.example2.com")
                    .build()
                    .unwrap(),
            )
            .public_id(
                PublicId::builder()
                    .id_type("IANA Registrar ID")
                    .identifier("5678")
                    .build(),
            )
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
            .build()
    }

    fn make_test_domain_search_results() -> DomainSearchResults {
        let extensions = vec![
            ExtensionId::RdapLevel0.to_extension(),
            ExtensionId::IcannRdapResponseProfile1.to_extension(),
        ];
        DomainSearchResults::response_obj()
            .results(vec![make_test_domain_1(), make_test_domain_2()])
            .extensions(extensions)
            .build()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Handle);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"EXAMPLE-DOM-1".to_string()));
                assert!(s.contains(&"EXAMPLE-DOM-2".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::Status];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Status);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert!(s.len() >= 2);
                assert!(s.contains(&"active".to_string()));
                assert!(s.contains(&"clientTransferProhibited".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_object_class_name() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::ObjectClassName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::ObjectClassName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"domain".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_event() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::Event];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Event);
        match &results[0].value {
            FilterValue::NameValueArray(nva) => {
                assert!(nva.len() >= 2);
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
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::RdapConformance];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RdapConformance);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert!(s.contains(&"rdap_level_0".to_string()));
                assert!(s.contains(&"icann_rdap_response_profile_1".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_ldh_name() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::LdhName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::LdhName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"example1.com".to_string()));
                assert!(s.contains(&"example2.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_unicode_name() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::UnicodeName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::UnicodeName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"例え1.com".to_string()));
                assert!(s.contains(&"例え2.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_nameserver() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::Nameserver];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Nameserver);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert!(s.len() >= 2);
                assert!(s.contains(&"ns1.example1.com".to_string()));
                assert!(s.contains(&"ns2.example1.com".to_string()));
                assert!(s.contains(&"ns1.example2.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_email() {
        // GIVEN
        let search_results = make_test_domain_search_results();
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
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrantFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Domain Registrant One".to_string()));
                assert!(s.contains(&"Domain Registrant Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_abuse_email() {
        // GIVEN
        let search_results = make_test_domain_search_results();
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
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::AbuseFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::AbuseFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Domain Abuse One".to_string()));
                assert!(s.contains(&"Domain Abuse Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_technical_email() {
        // GIVEN
        let search_results = make_test_domain_search_results();
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
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::TechnicalFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::TechnicalFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Domain Tech One".to_string()));
                assert!(s.contains(&"Domain Tech Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrar_email() {
        // GIVEN
        let search_results = make_test_domain_search_results();
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
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::RegistrarFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrarFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Domain Registrar One".to_string()));
                assert!(s.contains(&"Domain Registrar Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_public_id() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::PublicId];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::PublicId);
        match &results[0].value {
            FilterValue::NameValueArray(nva) => {
                assert!(nva.len() >= 2);
                let types: Vec<&str> = nva.iter().map(|nv| nv.name.as_str()).collect();
                assert!(types.contains(&"IANA Registrar ID"));
            }
            _ => panic!("Expected NameValueArray"),
        }
    }

    #[test]
    fn filter_unknown_returns_null() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![Filter::StartAutnum];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::StartAutnum);
        assert_eq!(results[0].value, FilterValue::Null);
    }

    #[test]
    fn filter_multiple_filters_at_once() {
        // GIVEN
        let search_results = make_test_domain_search_results();
        let filters = vec![
            Filter::Handle,
            Filter::Status,
            Filter::ObjectClassName,
            Filter::RegistrantEmail,
            Filter::AbuseEmail,
            Filter::TechnicalEmail,
            Filter::RegistrarEmail,
        ];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 7);
        assert_eq!(results[0].filter, Filter::Handle);
        assert_eq!(results[1].filter, Filter::Status);
        assert_eq!(results[2].filter, Filter::ObjectClassName);
        assert_eq!(results[3].filter, Filter::RegistrantEmail);
        assert_eq!(results[4].filter, Filter::AbuseEmail);
        assert_eq!(results[5].filter, Filter::TechnicalEmail);
        assert_eq!(results[6].filter, Filter::RegistrarEmail);
    }
}
