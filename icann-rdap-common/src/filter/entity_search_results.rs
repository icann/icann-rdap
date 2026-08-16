//! Entity search results filter implementation.
//!
//! Extracts fields from [`crate::response::EntitySearchResults`] RDAP objects.
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
//! | `Role` | `StringArray` | Roles from all results |
//! | `PublicId` | `HashMapVal` | Public IDs aggregated from all results |
//! | `Voice` | `StringArray` | Phone numbers from all results |
//! | `Fax` | `StringArray` | Fax numbers from all results |
//! | `ContactUri` | `StringArray` | Contact URIs from all results |
//! | `CountryName` | `StringArray` | Country names from all results |
//! | `CountryCode` | `StringArray` | Country codes from all results |
//! | Entity roles | `StringArray` | Role-based fields aggregated from all results |

use super::*;
use crate::response::{CommonFields, EntitySearchResults, ObjectCommonFields};

impl Filterable for EntitySearchResults {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| e.handle())
                            .map(|h| h.to_string())
                            .collect(),
                    ),
                },
                Filter::Status => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|e| e.status())
                            .map(|s| s.to_string())
                            .collect(),
                    ),
                },
                Filter::ObjectClassName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .map(|e| e.object_class_name().to_string())
                            .collect(),
                    ),
                },
                Filter::Event => FilterOutput {
                    filter: *f,
                    value: FilterValue::HashMapVal(
                        self.results()
                            .iter()
                            .flat_map(|e| e.events())
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
                            .filter_map(|e| e.common().rdap_conformance.as_ref())
                            .flatten()
                            .map(|ext| ext.0.clone())
                            .collect(),
                    ),
                },
                Filter::Role => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|e| e.roles())
                            .map(|r| r.to_string())
                            .collect(),
                    ),
                },
                Filter::PublicId => FilterOutput {
                    filter: *f,
                    value: FilterValue::HashMapVal(
                        self.results()
                            .iter()
                            .flat_map(|e| e.public_ids())
                            .filter_map(|p| {
                                let id_type = p.id_type()?;
                                let identifier = p.identifier()?;
                                Some((
                                    id_type.to_string(),
                                    FilterValue::StringVal(identifier.to_string()),
                                ))
                            })
                            .collect(),
                    ),
                },
                Filter::Voice => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| e.contact())
                            .filter_map(|c| c.voice_phone().map(|p| p.phone().to_string()))
                            .collect(),
                    ),
                },
                Filter::Fax => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| e.contact())
                            .filter_map(|c| c.fax_phone().map(|p| p.phone().to_string()))
                            .collect(),
                    ),
                },
                Filter::ContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| e.contact())
                            .flat_map(|c| {
                                let uris: Vec<String> =
                                    c.contact_uris().iter().map(|u| u.to_string()).collect();
                                uris
                            })
                            .collect(),
                    ),
                },
                Filter::CountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| e.contact())
                            .flat_map(|c| {
                                let names: Vec<String> = c
                                    .postal_addresses()
                                    .iter()
                                    .filter_map(|a| a.country_name())
                                    .map(|n| n.to_string())
                                    .collect();
                                names
                            })
                            .collect(),
                    ),
                },
                Filter::CountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| e.contact())
                            .flat_map(|c| {
                                let codes: Vec<String> = c
                                    .postal_addresses()
                                    .iter()
                                    .filter_map(|a| a.country_code())
                                    .map(|c| c.to_string())
                                    .collect();
                                codes
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
    use crate::prelude::{Email, Event, ExtensionId};
    use crate::response::Entity as EntityType;

    fn make_test_entity_1() -> Entity {
        let contact = Contact::builder()
            .full_name("Entity One")
            .emails(vec![Email::builder().email("entity1@example.com").build()])
            .build();

        let child_registrant_contact = Contact::builder()
            .full_name("Child Registrant One")
            .emails(vec![
                Email::builder().email("child-reg1@example.com").build(),
            ])
            .build();
        let child_abuse_contact = Contact::builder()
            .full_name("Child Abuse One")
            .emails(vec![
                Email::builder().email("child-abuse1@example.com").build(),
            ])
            .build();
        let child_tech_contact = Contact::builder()
            .full_name("Child Tech One")
            .emails(vec![
                Email::builder().email("child-tech1@example.com").build(),
            ])
            .build();
        let child_registrar_contact = Contact::builder()
            .full_name("Child Registrar One")
            .emails(vec![
                Email::builder().email("child-reg1@example.com").build(),
            ])
            .build();

        let child_registrant = EntityType::response_obj()
            .handle("CHILD-REGISTRANT-1")
            .role("registrant")
            .contact(child_registrant_contact)
            .build();
        let child_abuse = EntityType::response_obj()
            .handle("CHILD-ABUSE-1")
            .role("abuse")
            .contact(child_abuse_contact)
            .build();
        let child_tech = EntityType::response_obj()
            .handle("CHILD-TECH-1")
            .role("technical")
            .contact(child_tech_contact)
            .build();
        let child_registrar = EntityType::response_obj()
            .handle("CHILD-REGISTRAR-1")
            .role("registrar")
            .contact(child_registrar_contact)
            .build();

        EntityType::response_obj()
            .handle("ENTITY-ONE")
            .role("admin")
            .contact(contact)
            .statuses(vec!["active".to_string()])
            .entity(child_registrant)
            .entity(child_abuse)
            .entity(child_tech)
            .entity(child_registrar)
            .event(
                Event::builder()
                    .event_action("last changed")
                    .event_date("2021-06-15T00:00:00Z")
                    .build(),
            )
            .build()
    }

    fn make_test_entity_2() -> Entity {
        let contact = Contact::builder()
            .full_name("Entity Two")
            .emails(vec![Email::builder().email("entity2@example.com").build()])
            .build();

        let child_registrant_contact = Contact::builder()
            .full_name("Child Registrant Two")
            .emails(vec![
                Email::builder().email("child-reg2@example.com").build(),
            ])
            .build();
        let child_abuse_contact = Contact::builder()
            .full_name("Child Abuse Two")
            .emails(vec![
                Email::builder().email("child-abuse2@example.com").build(),
            ])
            .build();
        let child_tech_contact = Contact::builder()
            .full_name("Child Tech Two")
            .emails(vec![
                Email::builder().email("child-tech2@example.com").build(),
            ])
            .build();
        let child_registrar_contact = Contact::builder()
            .full_name("Child Registrar Two")
            .emails(vec![
                Email::builder().email("child-reg2@example.com").build(),
            ])
            .build();

        let child_registrant = EntityType::response_obj()
            .handle("CHILD-REGISTRANT-2")
            .role("registrant")
            .contact(child_registrant_contact)
            .build();
        let child_abuse = EntityType::response_obj()
            .handle("CHILD-ABUSE-2")
            .role("abuse")
            .contact(child_abuse_contact)
            .build();
        let child_tech = EntityType::response_obj()
            .handle("CHILD-TECH-2")
            .role("technical")
            .contact(child_tech_contact)
            .build();
        let child_registrar = EntityType::response_obj()
            .handle("CHILD-REGISTRAR-2")
            .role("registrar")
            .contact(child_registrar_contact)
            .build();

        EntityType::response_obj()
            .handle("ENTITY-TWO")
            .role("admin")
            .contact(contact)
            .statuses(vec![
                "active".to_string(),
                "clientDeleteProhibited".to_string(),
            ])
            .entity(child_registrant)
            .entity(child_abuse)
            .entity(child_tech)
            .entity(child_registrar)
            .event(
                Event::builder()
                    .event_action("registration")
                    .event_date("2022-03-10T08:00:00Z")
                    .build(),
            )
            .build()
    }

    fn make_test_entity_search_results() -> EntitySearchResults {
        let extensions = vec![
            ExtensionId::RdapLevel0.to_extension(),
            ExtensionId::IcannRdapResponseProfile1.to_extension(),
        ];
        EntitySearchResults::response_obj()
            .results(vec![make_test_entity_1(), make_test_entity_2()])
            .extensions(extensions)
            .build()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Handle);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"ENTITY-ONE".to_string()));
                assert!(s.contains(&"ENTITY-TWO".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let search_results = make_test_entity_search_results();
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
                assert!(s.contains(&"clientDeleteProhibited".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_object_class_name() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::ObjectClassName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::ObjectClassName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"entity".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_event() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::Event];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Event);
        match &results[0].value {
            FilterValue::HashMapVal(hm) => {
                assert_eq!(hm.len(), 2);
                assert!(hm.contains_key("last changed"));
                assert!(hm.contains_key("registration"));
            }
            _ => panic!("Expected HashMapVal"),
        }
    }

    #[test]
    fn filter_rdap_conformance() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::RdapConformance];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RdapConformance);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                // rdap_level_0 comes from Common::level0() used by Entity::response_obj()
                assert!(s.contains(&"rdap_level_0".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_role() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::Role];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Role);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                // Top-level entities have role "admin"
                assert!(s.contains(&"admin".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_voice() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::Voice];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Voice);
        // Entity One and Two have no voice phone, so should be empty
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 0);
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_fax() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::Fax];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Fax);
        // Entity One and Two have no fax phone, so should be empty
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 0);
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_contact_uri() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::ContactUri];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::ContactUri);
        // Entity One and Two have no contact URIs, so should be empty
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 0);
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_country_name() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::CountryName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::CountryName);
        // Entity One and Two have no postal addresses, so should be empty
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 0);
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_country_code() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::CountryCode];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::CountryCode);
        // Entity One and Two have no postal addresses, so should be empty
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 0);
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_email() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::RegistrantEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrantEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"child-reg1@example.com".to_string()));
                assert!(s.contains(&"child-reg2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_full_name() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrantFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Child Registrant One".to_string()));
                assert!(s.contains(&"Child Registrant Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_abuse_email() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::AbuseEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::AbuseEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"child-abuse1@example.com".to_string()));
                assert!(s.contains(&"child-abuse2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_abuse_full_name() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::AbuseFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::AbuseFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Child Abuse One".to_string()));
                assert!(s.contains(&"Child Abuse Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_technical_email() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::TechnicalEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::TechnicalEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"child-tech1@example.com".to_string()));
                assert!(s.contains(&"child-tech2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_technical_full_name() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::TechnicalFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::TechnicalFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Child Tech One".to_string()));
                assert!(s.contains(&"Child Tech Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrar_email() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::RegistrarEmail];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrarEmail);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"child-reg1@example.com".to_string()));
                assert!(s.contains(&"child-reg2@example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrar_full_name() {
        // GIVEN
        let search_results = make_test_entity_search_results();
        let filters = vec![Filter::RegistrarFullName];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::RegistrarFullName);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"Child Registrar One".to_string()));
                assert!(s.contains(&"Child Registrar Two".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_unknown_returns_null() {
        // GIVEN
        let search_results = make_test_entity_search_results();
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
        let search_results = make_test_entity_search_results();
        let filters = vec![
            Filter::Handle,
            Filter::Status,
            Filter::ObjectClassName,
            Filter::Role,
            Filter::RegistrantEmail,
            Filter::AbuseEmail,
            Filter::TechnicalEmail,
            Filter::RegistrarEmail,
        ];

        // WHEN
        let results = extract(&search_results, &filters);

        // THEN
        assert_eq!(results.len(), 8);
        assert_eq!(results[0].filter, Filter::Handle);
        assert_eq!(results[1].filter, Filter::Status);
        assert_eq!(results[2].filter, Filter::ObjectClassName);
        assert_eq!(results[3].filter, Filter::Role);
        assert_eq!(results[4].filter, Filter::RegistrantEmail);
        assert_eq!(results[5].filter, Filter::AbuseEmail);
        assert_eq!(results[6].filter, Filter::TechnicalEmail);
        assert_eq!(results[7].filter, Filter::RegistrarEmail);
    }
}
