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
                        .map(|c| {
                            FilterValue::StringArray(
                                c.emails().iter().map(|e| e.email().to_string()).collect(),
                            )
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
                Filter::VoicePhone => FilterOutput {
                    filter: *f,
                    value: self
                        .contact()
                        .and_then(|c| {
                            c.voice_phone()
                                .map(|p| FilterValue::StringVal(p.phone().to_string()))
                        })
                        .unwrap_or(FilterValue::Null),
                },
                Filter::FaxPhone => FilterOutput {
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
                Filter::RegistrantVoicePhone => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Registrant)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrantFaxPhone => FilterOutput {
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
                Filter::AbuseVoicePhone => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Abuse)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::AbuseFaxPhone => FilterOutput {
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
                Filter::TechnicalVoicePhone => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Technical)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::TechnicalFaxPhone => FilterOutput {
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
                Filter::RegistrarVoicePhone => FilterOutput {
                    filter: *f,
                    value: find_entity_voice_phone_by_role(self.entities(), EntityRole::Registrar)
                        .map(|e| FilterValue::StringVal(e.to_string()))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::RegistrarFaxPhone => FilterOutput {
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
