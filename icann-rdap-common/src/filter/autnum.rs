use super::*;
use crate::response::{Autnum, CommonFields, ObjectCommonFields};

impl Filterable for Autnum {
    fn filter(&self, filters: &[Filter]) -> FilterResult {
        filters
            .iter()
            .map(|f| match f {
                Filter::Handle => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.handle()),
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
                    value: FilterValue::HashMapVal(
                        self.events()
                            .iter()
                            .filter_map(|e| {
                                let action = e.event_action()?;
                                let date = e.event_date()?;
                                Some((action.to_string(), FilterValue::StringVal(date.to_string())))
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
                    value: opt_to_i64(self.start_autnum()),
                },
                Filter::EndAutnum => FilterOutput {
                    filter: *f,
                    value: opt_to_i64(self.end_autnum()),
                },
                Filter::Name => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.name()),
                },
                Filter::Type => FilterOutput {
                    filter: *f,
                    value: opt_to_string(self.autnum_type()),
                },
                _ => entity_role_filter_output(ObjectCommonFields::entities(self), *f).unwrap_or(
                    FilterOutput {
                        filter: *f,
                        value: FilterValue::Null,
                    },
                ),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::Contact;
    use crate::prelude::Entity;

    fn make_test_autnum() -> Autnum {
        let registrant = Contact::builder().full_name("Autnum Owner").build();

        Autnum::builder()
            .autnum_range(12345..12350)
            .handle("AS12345")
            .name("EXAMPLE-AS")
            .autnum_type("DIRECT ALLOCATION")
            .country("US")
            .status("active")
            .entity(
                Entity::response_obj()
                    .handle("REGISTRANT-HANDLE")
                    .role("registrant")
                    .contact(registrant)
                    .build(),
            )
            .build()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let autnum = make_test_autnum();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&autnum, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("AS12345".to_string())
        );
    }

    #[test]
    fn filter_start_autnum() {
        // GIVEN
        let autnum = make_test_autnum();
        let filters = vec![Filter::StartAutnum];

        // WHEN
        let results = extract(&autnum, &filters);

        // THEN
        assert_eq!(results[0].value, FilterValue::IntVal(12345));
    }

    #[test]
    fn filter_end_autnum() {
        // GIVEN
        let autnum = make_test_autnum();
        let filters = vec![Filter::EndAutnum];

        // WHEN
        let results = extract(&autnum, &filters);

        // THEN
        assert_eq!(results[0].value, FilterValue::IntVal(12350));
    }

    #[test]
    fn filter_name() {
        // GIVEN
        let autnum = make_test_autnum();
        let filters = vec![Filter::Name];

        // WHEN
        let results = extract(&autnum, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("EXAMPLE-AS".to_string())
        );
    }

    #[test]
    fn filter_type() {
        // GIVEN
        let autnum = make_test_autnum();
        let filters = vec![Filter::Type];

        // WHEN
        let results = extract(&autnum, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("DIRECT ALLOCATION".to_string())
        );
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let autnum = make_test_autnum();
        let filters = vec![Filter::Status];

        // WHEN
        let results = extract(&autnum, &filters);

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
        let autnum = make_test_autnum();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&autnum, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("Autnum Owner".to_string())
        );
    }
}
