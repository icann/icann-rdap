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
                    value: FilterValue::StringArray(
                        self.events()
                            .iter()
                            .map(|e| {
                                let action = e.event_action().unwrap_or("");
                                let actor = e.event_actor().unwrap_or("");
                                let date = e.event_date().unwrap_or("");
                                format!("{}:{}:{}", action, actor, date)
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
                _ => FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                },
            })
            .collect()
    }
}
