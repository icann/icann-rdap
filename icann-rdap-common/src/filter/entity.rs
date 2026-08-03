use super::*;
use crate::response::{CommonFields, Entity, ObjectCommonFields};

impl Filterable for Entity {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: self
                        .handle()
                        .map(|h| FilterValue::StringVal(h.to_string()))
                        .unwrap_or(FilterValue::Null),
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
                Filter::Role => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.roles().iter().map(|r| r.to_string()).collect(),
                    ),
                },
                Filter::Email => FilterOutput {
                    filter: *f,
                    value: self
                        .contact()
                        .and_then(|c| {
                            let emails: Vec<String> =
                                c.emails().iter().map(|e| e.email().to_string()).collect();
                            if emails.is_empty() {
                                None
                            } else {
                                Some(FilterValue::StringArray(emails))
                            }
                        })
                        .unwrap_or(FilterValue::Null),
                },
                Filter::FullName => FilterOutput {
                    filter: *f,
                    value: self
                        .contact()
                        .and_then(|c| c.full_name().map(|n| FilterValue::StringVal(n.to_string())))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::PublicId => FilterOutput {
                    filter: *f,
                    value: FilterValue::HashMapVal(
                        self.public_ids()
                            .iter()
                            .filter_map(|p| {
                                let id_type = p.id_type()?;
                                let identifier = p.identifier()?;
                                Some((id_type.to_string(), FilterValue::StringVal(identifier.to_string())))
                            })
                            .collect(),
                    ),
                },
                Filter::Voice => FilterOutput {
                    filter: *f,
                    value: self
                        .contact()
                        .and_then(|c| {
                            c.voice_phone()
                                .map(|p| FilterValue::StringVal(p.phone().to_string()))
                        })
                        .unwrap_or(FilterValue::Null),
                },
                Filter::Fax => FilterOutput {
                    filter: *f,
                    value: self
                        .contact()
                        .and_then(|c| {
                            c.fax_phone()
                                .map(|p| FilterValue::StringVal(p.phone().to_string()))
                        })
                        .unwrap_or(FilterValue::Null),
                },
                Filter::ContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.contact()
                            .map(|c| c.contact_uris().iter().map(|u| u.to_string()).collect())
                            .unwrap_or_default(),
                    ),
                },
                Filter::CountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.contact()
                            .map(|c| {
                                c.postal_addresses()
                                    .iter()
                                    .filter_map(|a| a.country_name())
                                    .map(|n| n.to_string())
                                    .collect()
                            })
                            .unwrap_or_default(),
                    ),
                },
                Filter::CountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.contact()
                            .map(|c| {
                                c.postal_addresses()
                                    .iter()
                                    .filter_map(|a| a.country_code())
                                    .map(|c| c.to_string())
                                    .collect()
                            })
                            .unwrap_or_default(),
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
    use crate::{
        contact::Contact,
        prelude::{Email, Event},
    };

    fn make_test_entity() -> Entity {
        let contact = Contact::builder().full_name("John User").build();

        Entity::builder()
            .handle("EntityHandle-1")
            .role("registrant")
            .contact(contact)
            .statuses(vec!["active".to_string()])
            .event(
                Event::builder()
                    .event_action("last changed")
                    .event_date("2021-06-15T00:00:00Z")
                    .build(),
            )
            .build()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let entity = make_test_entity();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&entity, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("EntityHandle-1".to_string())
        );
    }

    #[test]
    fn filter_object_class_name() {
        // GIVEN
        let entity = make_test_entity();
        let filters = vec![Filter::ObjectClassName];

        // WHEN
        let results = extract(&entity, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("entity".to_string())
        );
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let entity = make_test_entity();
        let filters = vec![Filter::Status];

        // WHEN
        let results = extract(&entity, &filters);

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
    fn filter_role() {
        // GIVEN
        let entity = make_test_entity();
        let filters = vec![Filter::Role];

        // WHEN
        let results = extract(&entity, &filters);

        // THEN
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 1);
                assert!(s.contains(&"registrant".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_full_name() {
        // GIVEN
        let entity = make_test_entity();
        let filters = vec![Filter::FullName];

        // WHEN
        let results = extract(&entity, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("John User".to_string())
        );
    }

    #[test]
    fn filter_email() {
        // GIVEN
        let contact = Contact::builder()
            .full_name("John User")
            .emails(vec![Email::builder().email("john@example.com").build()])
            .build();
        let entity = Entity::builder()
            .handle("EntityHandle-1")
            .role("registrant")
            .contact(contact)
            .statuses(vec!["active".to_string()])
            .event(
                Event::builder()
                    .event_action("last changed")
                    .event_date("2021-06-15T00:00:00Z")
                    .build(),
            )
            .build();
        let filters = vec![Filter::Email];

        // WHEN
        let results = extract(&entity, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringArray(vec!["john@example.com".to_string()])
        );
    }

    #[test]
    fn filter_registrant_full_name() {
        // GIVEN
        let child_contact = Contact::builder().full_name("Child Registrant").build();
        let child_entity = Entity::response_obj()
            .handle("CHILD-HANDLE")
            .role("registrant")
            .contact(child_contact)
            .build();

        let parent_entity = Entity::response_obj()
            .handle("PARENT-HANDLE")
            .role("admin")
            .entity(child_entity)
            .build();

        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&parent_entity, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("Child Registrant".to_string())
        );
    }

    #[test]
    fn filter_event() {
        // GIVEN
        let entity = make_test_entity();
        let filters = vec![Filter::Event];

        // WHEN
        let results = extract(&entity, &filters);

        // THEN
        match &results[0].value {
            FilterValue::HashMapVal(hm) => {
                assert_eq!(hm.len(), 1);
                assert_eq!(
                    hm.get("last changed"),
                    Some(&FilterValue::StringVal("2021-06-15T00:00:00Z".to_string()))
                );
            }
            _ => panic!("Expected HashMapVal"),
        }
    }
}
