use super::*;
use crate::response::{Autnum, CommonFields, ObjectCommonFields};

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
                _ => FilterOutput {
                    filter: *f,
                    value: FilterValue::Null,
                },
            })
            .collect()
    }
}
