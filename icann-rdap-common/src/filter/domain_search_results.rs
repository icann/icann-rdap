use super::*;
use crate::response::{CommonFields, DomainSearchResults, EntityRole, ObjectCommonFields};

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
                Filter::RegistrantEmail => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|d| {
                                find_entity_email_by_role(d.entities(), EntityRole::Registrant)
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
                _ => FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                },
            })
            .collect()
    }
}
