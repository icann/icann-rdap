use super::*;
use crate::response::{CommonFields, Domain, EntityRole, ObjectCommonFields};

impl Filterable for Domain {
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
                Filter::LdhName => FilterOutput {
                    filter: *f,
                    value: self
                        .ldh_name()
                        .map(|n| FilterValue::StringVal(n.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::UnicodeName => FilterOutput {
                    filter: *f,
                    value: self
                        .unicode_name()
                        .map(|n| FilterValue::StringVal(n.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::Nameserver => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.nameservers()
                            .iter()
                            .filter_map(|n| n.ldh_name())
                            .map(|n| n.to_string())
                            .collect(),
                    ),
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
    use crate::contact::Contact;
    use crate::prelude::Email;
    use crate::prelude::{ExtensionId, Nameserver, PublicId};
    use crate::response::{Event, Notice};

    fn make_test_domain() -> Domain {
        let registrant_email = Email::builder().email("registrant@example.com").build();
        let registrant = Contact::builder()
            .full_name("John Registrant")
            .emails(vec![registrant_email])
            .build();

        let abuse_email = Email::builder().email("abuse@example.com").build();
        let abuse = Contact::builder()
            .full_name("Abuse Contact")
            .emails(vec![abuse_email])
            .build();

        let tech_email = Email::builder().email("tech@example.com").build();
        let technical = Contact::builder()
            .full_name("Tech Contact")
            .emails(vec![tech_email])
            .build();

        let registrar_email = Email::builder().email("registrar@example.com").build();
        let registrar = Contact::builder()
            .full_name("Registrar Inc")
            .emails(vec![registrar_email])
            .build();

        Domain::response_obj()
            .handle("EXAMPLE-DOM")
            .ldh_name("example.com")
            .unicode_name("例え.com")
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
                    .ldh_name("ns1.example.com")
                    .build()
                    .unwrap(),
            )
            .nameserver(
                Nameserver::builder()
                    .ldh_name("ns2.example.com")
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
                Entity::response_obj()
                    .handle("REGISTRANT-HANDLE")
                    .role("registrant")
                    .contact(registrant)
                    .build(),
            )
            .entity(
                Entity::response_obj()
                    .handle("ABUSE-HANDLE")
                    .role("abuse")
                    .contact(abuse)
                    .build(),
            )
            .entity(
                Entity::response_obj()
                    .handle("TECH-HANDLE")
                    .role("technical")
                    .contact(technical)
                    .build(),
            )
            .entity(
                Entity::response_obj()
                    .handle("REGISTRAR-HANDLE")
                    .role("registrar")
                    .contact(registrar)
                    .build(),
            )
            .notice(Notice::builder().title("Test Notice").build())
            .build()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Handle);
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("EXAMPLE-DOM".to_string())
        );
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::Status];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filter, Filter::Status);
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"active".to_string()));
                assert!(s.contains(&"clientTransferProhibited".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_object_class_name() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::ObjectClassName];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("domain".to_string())
        );
    }

    #[test]
    fn filter_event() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::Event];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(results.len(), 1);
        match &results[0].value {
            FilterValue::NameValueArray(nva) => {
                assert_eq!(nva.len(), 2);
                assert_eq!(nva[0].name, "registration");
                assert_eq!(
                    nva[0].value,
                    FilterValue::StringVal("2020-01-01T00:00:00Z".to_string())
                );
                assert_eq!(nva[1].name, "last changed");
                assert_eq!(
                    nva[1].value,
                    FilterValue::StringVal("2021-06-15T00:00:00Z".to_string())
                );
            }
            _ => panic!("Expected NameValueArray"),
        }
    }

    #[test]
    fn filter_ldh_name() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::LdhName];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("example.com".to_string())
        );
    }

    #[test]
    fn filter_unicode_name() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::UnicodeName];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("例え.com".to_string())
        );
    }

    #[test]
    fn filter_nameserver() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::Nameserver];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"ns1.example.com".to_string()));
                assert!(s.contains(&"ns2.example.com".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_email() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::RegistrantEmail];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("registrant@example.com".to_string())
        );
    }

    #[test]
    fn filter_registrant_full_name() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("John Registrant".to_string())
        );
    }

    #[test]
    fn filter_abuse_email() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::AbuseEmail];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("abuse@example.com".to_string())
        );
    }

    #[test]
    fn filter_technical_email() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::TechnicalEmail];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("tech@example.com".to_string())
        );
    }

    #[test]
    fn filter_registrar_email() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::RegistrarEmail];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("registrar@example.com".to_string())
        );
    }

    #[test]
    fn filter_rdap_conformance() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::RdapConformance];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert!(s.contains(&"rdap_level_0".to_string()));
                assert!(s.contains(&"icann_rdap_response_profile_1".to_string()));
                assert!(s.contains(&"icann_rdap_technical_implementation_guide_1".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_unknown() {
        // GIVEN
        let domain = make_test_domain();
        let filters = vec![Filter::Name];

        // WHEN
        let results = extract(&domain, &filters);

        // THEN
        assert_eq!(results[0].value, FilterValue::Null);
    }
}
