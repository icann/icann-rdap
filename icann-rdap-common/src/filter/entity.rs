use super::*;
use crate::response::{CommonFields, Entity, EntityRole, ObjectCommonFields};

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
                    value: FilterValue::NameValueArray(
                        self.events()
                            .iter()
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
                    value: FilterValue::NameValueArray(
                        self.public_ids()
                            .iter()
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
                Filter::RegistrantEmail => FilterOutput {
                    filter: *f,
                    value: find_entity_email_by_role(self.entities(), EntityRole::Registrant)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrantFullName => FilterOutput {
                    filter: *f,
                    value: find_entity_full_name_by_role(self.entities(), EntityRole::Registrant)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrantVoice => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Registrant)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrantFax => FilterOutput {
                    filter: *f,
                    value: find_entity_fax_phone_by_role(self.entities(), EntityRole::Registrant)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrantContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_contact_uris_by_role(
                        self.entities(),
                        EntityRole::Registrant,
                    )),
                },
                Filter::RegistrantCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_names_by_role(
                        self.entities(),
                        EntityRole::Registrant,
                    )),
                },
                Filter::RegistrantCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_codes_by_role(
                        self.entities(),
                        EntityRole::Registrant,
                    )),
                },

                Filter::AbuseEmail => FilterOutput {
                    filter: *f,
                    value: find_entity_email_by_role(self.entities(), EntityRole::Abuse)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::AbuseFullName => FilterOutput {
                    filter: *f,
                    value: find_entity_full_name_by_role(self.entities(), EntityRole::Abuse)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::AbuseVoice => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Abuse)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::AbuseFax => FilterOutput {
                    filter: *f,
                    value: find_entity_fax_phone_by_role(self.entities(), EntityRole::Abuse)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::AbuseContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_contact_uris_by_role(
                        self.entities(),
                        EntityRole::Abuse,
                    )),
                },
                Filter::AbuseCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_names_by_role(
                        self.entities(),
                        EntityRole::Abuse,
                    )),
                },
                Filter::AbuseCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_codes_by_role(
                        self.entities(),
                        EntityRole::Abuse,
                    )),
                },
                Filter::TechnicalEmail => FilterOutput {
                    filter: *f,
                    value: find_entity_email_by_role(self.entities(), EntityRole::Technical)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::TechnicalFullName => FilterOutput {
                    filter: *f,
                    value: find_entity_full_name_by_role(self.entities(), EntityRole::Technical)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::TechnicalVoice => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Technical)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::TechnicalFax => FilterOutput {
                    filter: *f,
                    value: find_entity_fax_phone_by_role(self.entities(), EntityRole::Technical)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::TechnicalContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_contact_uris_by_role(
                        self.entities(),
                        EntityRole::Technical,
                    )),
                },
                Filter::TechnicalCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_names_by_role(
                        self.entities(),
                        EntityRole::Technical,
                    )),
                },
                Filter::TechnicalCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_codes_by_role(
                        self.entities(),
                        EntityRole::Technical,
                    )),
                },
                Filter::RegistrarEmail => FilterOutput {
                    filter: *f,
                    value: find_entity_email_by_role(self.entities(), EntityRole::Registrar)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrarFullName => FilterOutput {
                    filter: *f,
                    value: find_entity_full_name_by_role(self.entities(), EntityRole::Registrar)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrarVoice => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Registrar)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrarFax => FilterOutput {
                    filter: *f,
                    value: find_entity_fax_phone_by_role(self.entities(), EntityRole::Registrar)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrarContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_contact_uris_by_role(
                        self.entities(),
                        EntityRole::Registrar,
                    )),
                },
                Filter::RegistrarCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_names_by_role(
                        self.entities(),
                        EntityRole::Registrar,
                    )),
                },
                Filter::RegistrarCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(find_entity_country_codes_by_role(
                        self.entities(),
                        EntityRole::Registrar,
                    )),
                },
                _ => FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                },
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
            FilterValue::NameValueArray(nva) => {
                assert_eq!(nva.len(), 1);
                assert_eq!(nva[0].name, "last changed");
                assert_eq!(
                    nva[0].value,
                    FilterValue::StringVal("2021-06-15T00:00:00Z".to_string())
                );
            }
            _ => panic!("Expected NameValueArray"),
        }
    }
}
