use super::*;
use crate::response::{CommonFields, EntityRole, Network, ObjectCommonFields};

impl Filterable for Network {
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
                Filter::StartIpAddress => FilterOutput {
                    filter: *f,
                    value: self
                        .start_address()
                        .map(|s| FilterValue::StringVal(s.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::EndIpAddress => FilterOutput {
                    filter: *f,
                    value: self
                        .end_address()
                        .map(|s| FilterValue::StringVal(s.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::IpVersion => FilterOutput {
                    filter: *f,
                    value: self
                        .ip_version()
                        .map(|v| FilterValue::StringVal(v.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::Name => FilterOutput {
                    filter: *f,
                    value: self
                        .name()
                        .map(|n| FilterValue::StringVal(n.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::Type => FilterOutput {
                    filter: *f,
                    value: self
                        .network_type()
                        .map(|t| FilterValue::StringVal(t.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::ParentHandle => FilterOutput {
                    filter: *f,
                    value: self
                        .parent_handle()
                        .map(|p| FilterValue::StringVal(p.to_string()))
                        .unwrap_or(FilterValue::Null),
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
