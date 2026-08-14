use super::*;
use crate::response::{CommonFields, Nameserver, ObjectCommonFields};

impl Filterable for Nameserver {
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
                Filter::IpAddress => FilterOutput {
                    filter: *f,
                    value: FilterValue::StringArray(
                        self.ip_addresses()
                            .iter()
                            .flat_map(|ip| ip.v4s())
                            .chain(self.ip_addresses().iter().flat_map(|ip| ip.v6s()))
                            .map(|ip| ip.to_string())
                            .collect(),
                    ),
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
    use crate::prelude::{Entity, Event, IpAddresses};

    fn make_test_nameserver() -> Nameserver {
        Nameserver::builder()
            .ldh_name("ns1.example.com")
            .handle("NAMESERVER-HANDLE")
            .statuses(vec!["active".to_string()])
            .entity(
                Entity::response_obj()
                    .handle("REGISTRANT-HANDLE")
                    .role("registrant")
                    .contact(Contact::builder().full_name("Ns Owner").build())
                    .build(),
            )
            .event(
                Event::builder()
                    .event_action("last changed")
                    .event_date("2020-01-01T00:00:00Z")
                    .build(),
            )
            .build()
            .unwrap()
    }

    #[test]
    fn filter_handle() {
        // GIVEN
        let nameserver = make_test_nameserver();
        let filters = vec![Filter::Handle];

        // WHEN
        let results = extract(&nameserver, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("NAMESERVER-HANDLE".to_string())
        );
    }

    #[test]
    fn filter_object_class_name() {
        // GIVEN
        let nameserver = make_test_nameserver();
        let filters = vec![Filter::ObjectClassName];

        // WHEN
        let results = extract(&nameserver, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("nameserver".to_string())
        );
    }

    #[test]
    fn filter_status() {
        // GIVEN
        let nameserver = make_test_nameserver();
        let filters = vec![Filter::Status];

        // WHEN
        let results = extract(&nameserver, &filters);

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
    fn filter_ip_address() {
        // GIVEN
        let mut nameserver = make_test_nameserver();
        let ip_addresses = IpAddresses::builder()
            .address("192.0.2.1".to_string())
            .address("2001:db8::1".to_string())
            .build()
            .unwrap();
        nameserver.ip_addresses = Some(ip_addresses);

        let filters = vec![Filter::IpAddress];

        // WHEN
        let results = extract(&nameserver, &filters);

        // THEN
        match &results[0].value {
            FilterValue::StringArray(s) => {
                assert_eq!(s.len(), 2);
                assert!(s.contains(&"192.0.2.1".to_string()));
                assert!(s.contains(&"2001:db8::1".to_string()));
            }
            _ => panic!("Expected StringArray"),
        }
    }

    #[test]
    fn filter_registrant_full_name() {
        // GIVEN
        let nameserver = make_test_nameserver();
        let filters = vec![Filter::RegistrantFullName];

        // WHEN
        let results = extract(&nameserver, &filters);

        // THEN
        assert_eq!(
            results[0].value,
            FilterValue::StringVal("Ns Owner".to_string())
        );
    }

    #[test]
    fn filter_event() {
        // GIVEN
        let nameserver = make_test_nameserver();
        let filters = vec![Filter::Event];

        // WHEN
        let results = extract(&nameserver, &filters);

        // THEN
        match &results[0].value {
            FilterValue::HashMapVal(hm) => {
                assert_eq!(hm.len(), 1);
                assert_eq!(
                    hm.get("last changed"),
                    Some(&FilterValue::StringVal("2020-01-01T00:00:00Z".to_string()))
                );
            }
            _ => panic!("Expected HashMapVal"),
        }
    }
}
