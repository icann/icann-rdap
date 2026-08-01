use super::*;
use crate::response::{CommonFields, EntityRole, EntitySearchResults, ObjectCommonFields};

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
                    value: FilterValue::NameValueArray(
                        self.results()
                            .iter()
                            .flat_map(|e| e.events())
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
                    value: FilterValue::NameValueArray(
                        self.results()
                            .iter()
                            .flat_map(|e| e.public_ids())
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
                Filter::VoicePhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| e.contact())
                            .filter_map(|c| c.voice_phone().map(|p| p.phone().to_string()))
                            .collect(),
                    ),
                },
                Filter::FaxPhone => FilterOutput {
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
                Filter::RegistrantEmail => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| {
                                find_entity_email_by_role(e.entities(), EntityRole::Registrant)
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrantFullName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_full_name_by_role(r.entities(), EntityRole::Registrant)
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrantVoicePhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_voice_phone_by_role(
                                    r.entities(),
                                    EntityRole::Registrant,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrantFaxPhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_fax_phone_by_role(r.entities(), EntityRole::Registrant)
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrantContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_contact_uris_by_role(
                                    r.entities(),
                                    EntityRole::Registrant,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrantCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_names_by_role(
                                    r.entities(),
                                    EntityRole::Registrant,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrantCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_codes_by_role(
                                    r.entities(),
                                    EntityRole::Registrant,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::AbuseEmail => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| {
                                find_entity_email_by_role(e.entities(), EntityRole::Abuse)
                            })
                            .collect(),
                    ),
                },
                Filter::AbuseFullName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_full_name_by_role(r.entities(), EntityRole::Abuse)
                            })
                            .collect(),
                    ),
                },
                Filter::AbuseVoicePhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_voice_phone_by_role(r.entities(), EntityRole::Abuse)
                            })
                            .collect(),
                    ),
                },
                Filter::AbuseFaxPhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_fax_phone_by_role(r.entities(), EntityRole::Abuse)
                            })
                            .collect(),
                    ),
                },
                Filter::AbuseContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_contact_uris_by_role(r.entities(), EntityRole::Abuse)
                            })
                            .collect(),
                    ),
                },
                Filter::AbuseCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_names_by_role(r.entities(), EntityRole::Abuse)
                            })
                            .collect(),
                    ),
                },
                Filter::AbuseCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_codes_by_role(r.entities(), EntityRole::Abuse)
                            })
                            .collect(),
                    ),
                },
                Filter::TechnicalEmail => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| {
                                find_entity_email_by_role(e.entities(), EntityRole::Technical)
                            })
                            .collect(),
                    ),
                },
                Filter::TechnicalFullName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_full_name_by_role(r.entities(), EntityRole::Technical)
                            })
                            .collect(),
                    ),
                },
                Filter::TechnicalVoicePhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_voice_phone_by_role(r.entities(), EntityRole::Technical)
                            })
                            .collect(),
                    ),
                },
                Filter::TechnicalFaxPhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_fax_phone_by_role(r.entities(), EntityRole::Technical)
                            })
                            .collect(),
                    ),
                },
                Filter::TechnicalContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_contact_uris_by_role(
                                    r.entities(),
                                    EntityRole::Technical,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::TechnicalCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_names_by_role(
                                    r.entities(),
                                    EntityRole::Technical,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::TechnicalCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_codes_by_role(
                                    r.entities(),
                                    EntityRole::Technical,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrarEmail => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|e| {
                                find_entity_email_by_role(e.entities(), EntityRole::Registrar)
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrarFullName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_full_name_by_role(r.entities(), EntityRole::Registrar)
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrarVoicePhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_voice_phone_by_role(r.entities(), EntityRole::Registrar)
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrarFaxPhone => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|r| {
                                find_entity_fax_phone_by_role(r.entities(), EntityRole::Registrar)
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrarContactUri => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_contact_uris_by_role(
                                    r.entities(),
                                    EntityRole::Registrar,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrarCountryName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_names_by_role(
                                    r.entities(),
                                    EntityRole::Registrar,
                                )
                            })
                            .collect(),
                    ),
                },
                Filter::RegistrarCountryCode => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|r| {
                                find_entity_country_codes_by_role(
                                    r.entities(),
                                    EntityRole::Registrar,
                                )
                            })
                            .collect(),
                    ),
                },
                _ => FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                },
            })
            .collect()
    }
}
