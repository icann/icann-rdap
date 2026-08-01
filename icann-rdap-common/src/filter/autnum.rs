use super::*;
use crate::response::{Autnum, CommonFields, EntityRole, ObjectCommonFields};

impl Filterable for Autnum {
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
                Filter::StartAutnum => FilterOutput {
                    filter: *f,
                    value: self
                        .start_autnum()
                        .map(|v| FilterValue::IntVal(v as i64))
                        .unwrap_or(FilterValue::Null),
                },
                Filter::EndAutnum => FilterOutput {
                    filter: *f,
                    value: self
                        .end_autnum()
                        .map(|v| FilterValue::IntVal(v as i64))
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
                        .autnum_type()
                        .map(|t| FilterValue::StringVal(t.to_string()))
                        .unwrap_or(FilterValue::Null),
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
                _ => FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                },
            })
            .collect()
    }
}
