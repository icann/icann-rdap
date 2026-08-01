use super::*;
use crate::response::{AutnumSearchResults, CommonFields, EntityRole, ObjectCommonFields};

impl Filterable for AutnumSearchResults {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|a| a.handle())
                            .map(|h| h.to_string())
                            .collect(),
                    ),
                },
                Filter::Status => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .flat_map(|a| a.status())
                            .map(|s| s.to_string())
                            .collect(),
                    ),
                },
                Filter::ObjectClassName => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .map(|a| a.object_class_name().to_string())
                            .collect(),
                    ),
                },
                Filter::Event => FilterOutput {
                    filter: *f,
                    value: FilterValue::NameValueArray(
                        self.results()
                            .iter()
                            .flat_map(|a| a.events())
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
                            .filter_map(|a| a.common().rdap_conformance.as_ref())
                            .flatten()
                            .map(|ext| ext.0.clone())
                            .collect(),
                    ),
                },
                Filter::RegistrantEmail => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.results()
                            .iter()
                            .filter_map(|a| {
                                find_entity_email_by_role(a.entities(), EntityRole::Registrant)
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
                _ => FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                },
            })
            .collect()
    }
}
