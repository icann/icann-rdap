//! Convert a Contact to jCard/vCard.
use std::str::FromStr;

use serde_json::{json, Map, Value};

use super::Contact;

impl Contact {
    /// Output the Contact data as vCard in JSON values ([`Vec<Value>`]).
    ///
    /// ```rust
    /// use icann_rdap_common::contact::Contact;
    /// use serde::Serialize;
    /// use serde_json::Value;
    ///
    /// let contact = Contact::builder()
    ///   .kind("individual")
    ///   .full_name("Bob Smurd")
    ///   .build();
    ///
    /// let v = contact.to_vcard();
    /// let json = serde_json::to_string(&v);
    /// ```

    pub fn to_vcard(&self) -> Vec<Value> {
        // start the vcard with the version.
        let mut vcard: Vec<Value> = vec![json!(["version", {}, "text", "4.0"])];

        if let Some(full_name) = &self.full_name {
            vcard.push(json!(["fn", {}, "text", full_name]));
        }

        if let Some(name_parts) = &self.name_parts {
            let surnames = vec_string_to_value(&name_parts.surnames);
            let given_names = vec_string_to_value(&name_parts.given_names);
            let middle_names = vec_string_to_value(&name_parts.middle_names);
            let prefixes = vec_string_to_value(&name_parts.prefixes);
            let suffixes = vec_string_to_value(&name_parts.suffixes);
            vcard.push(json!([
                "n",
                {},
                "text",
                [surnames, given_names, middle_names, prefixes, suffixes]
            ]));
        }

        if let Some(kind) = &self.kind {
            vcard.push(json!(["kind", {}, "text", kind]));
        }

        if let Some(langs) = &self.langs {
            for lang in langs {
                let mut params: Map<String, Value> = Map::new();
                if let Some(pref) = lang.preference {
                    params.insert("pref".to_string(), Value::String(pref.to_string()));
                }
                vcard.push(json!([
                    "lang",
                    Value::from(params),
                    "language-tag",
                    lang.tag
                ]))
            }
        }

        if let Some(org_names) = &self.organization_names {
            for org_name in org_names {
                vcard.push(json!(["org", {}, "text", org_name]));
            }
        }

        if let Some(titles) = &self.titles {
            for title in titles {
                vcard.push(json!(["title", {}, "text", title]));
            }
        }

        if let Some(roles) = &self.roles {
            for role in roles {
                vcard.push(json!(["role", {}, "text", role]));
            }
        }

        if let Some(nick_names) = &self.nick_names {
            for nick_name in nick_names {
                vcard.push(json!(["nickname", {}, "text", nick_name]));
            }
        }

        if let Some(emails) = &self.emails {
            for email in emails {
                let mut params: Map<String, Value> = Map::new();
                if let Some(pref) = email.preference {
                    params.insert("pref".to_string(), Value::String(pref.to_string()));
                }
                if let Some(contexts) = email.contexts.as_ref() {
                    params.insert("type".to_string(), vec_string_to_param(contexts));
                }
                vcard.push(json!(["email", Value::from(params), "text", email.email]))
            }
        }

        if let Some(phones) = &self.phones {
            for phone in phones {
                let mut params: Map<String, Value> = Map::new();
                if let Some(pref) = phone.preference {
                    params.insert("pref".to_string(), Value::String(pref.to_string()));
                }
                let mut types: Vec<String> = Vec::new();
                if let Some(contexts) = &phone.contexts {
                    types.append(&mut contexts.clone());
                }
                if let Some(features) = &phone.features {
                    types.append(&mut features.clone());
                }
                params.insert("type".to_string(), vec_string_to_param(&types));
                vcard.push(json!(["tel", Value::from(params), "text", phone.phone]))
            }
        }

        if let Some(addrs) = &self.postal_addresses {
            for addr in addrs {
                let mut params: Map<String, Value> = Map::new();
                if let Some(pref) = addr.preference {
                    params.insert("pref".to_string(), Value::String(pref.to_string()));
                }
                if let Some(contexts) = addr.contexts.as_ref() {
                    params.insert("type".to_string(), vec_string_to_param(contexts));
                }
                if let Some(full_address) = &addr.full_address {
                    params.insert(
                        "label".to_string(),
                        Value::from_str(full_address).expect("serializing full address"),
                    );
                }
                let mut lines: Vec<String> = Vec::new();
                if let Some(street_parts) = &addr.street_parts {
                    lines.push(street_parts.first().cloned().unwrap_or("".to_string()));
                    lines.push(street_parts.get(1).cloned().unwrap_or("".to_string()));
                    lines.push(street_parts.get(2).cloned().unwrap_or("".to_string()));
                } else {
                    lines.push("".to_string());
                    lines.push("".to_string());
                    lines.push("".to_string());
                }
                if let Some(locality) = &addr.locality {
                    lines.push(locality.to_owned());
                } else {
                    lines.push("".to_string());
                }
                if let Some(region_name) = &addr.region_name {
                    lines.push(region_name.to_owned());
                } else if let Some(region_code) = &addr.region_code {
                    lines.push(region_code.to_owned());
                } else {
                    lines.push("".to_string());
                }
                if let Some(postal_code) = &addr.postal_code {
                    lines.push(postal_code.to_owned());
                } else {
                    lines.push("".to_string());
                }
                if let Some(country_name) = &addr.country_name {
                    lines.push(country_name.to_owned());
                } else if let Some(country_code) = &addr.country_code {
                    lines.push(country_code.to_owned());
                } else {
                    lines.push("".to_string());
                }
                vcard.push(json!(["adr", Value::from(params), "text", lines]))
            }
        }

        if let Some(contact_uris) = &self.contact_uris {
            for uri in contact_uris {
                vcard.push(json!(["contact-uri", {}, "uri", uri]));
            }
        }

        if let Some(urls) = &self.urls {
            for url in urls {
                vcard.push(json!(["url", {}, "uri", url]));
            }
        }

        // return the vcard array
        vec![Value::String("vcard".to_string()), Value::from(vcard)]
    }
}

fn vec_string_to_value(strings: &Option<Vec<String>>) -> Value {
    let Some(strings) = strings else {
        return Value::String("".to_string());
    };

    if strings.is_empty() {
        return Value::String("".to_string());
    };

    if strings.len() == 1 {
        let Some(one) = strings.first() else {
            panic!("couldn't get first element on length of 1")
        };
        return Value::String(one.to_owned());
    };

    // else
    Value::from(strings.clone())
}

fn vec_string_to_param(strings: &[String]) -> Value {
    if strings.is_empty() {
        return Value::String("".to_string());
    };

    if strings.len() == 1 {
        let Some(one) = strings.first() else {
            panic!("couldn't get first element on length of 1")
        };
        return Value::String(one.to_owned());
    };

    // else
    Value::from(strings)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use crate::contact::{Contact, Email, Lang, NameParts, Phone, PostalAddress};

    #[test]
    fn GIVEN_contact_WHEN_to_vcard_THEN_from_vcard_is_same() {
        // GIVEN
        let contact = Contact::builder()
            .full_name("Joe User")
            .name_parts(
                NameParts::builder()
                    .surnames(vec!["User".to_string()])
                    .given_names(vec!["Joe".to_string()])
                    .suffixes(vec!["ing. jr".to_string(), "M.Sc.".to_string()])
                    .build(),
            )
            .kind("individual")
            .langs(vec![
                Lang::builder().preference(1).tag("fr").build(),
                Lang::builder().preference(2).tag("en").build(),
            ])
            .organization_names(vec!["Example".to_string()])
            .titles(vec!["Research Scientist".to_string()])
            .roles(vec!["Project Lead".to_string()])
            .contact_uris(vec!["https://example.com/contact-form".to_string()])
            .postal_addresses(vec![PostalAddress::builder()
                .country_name("Canada")
                .postal_code("G1V 2M2")
                .region_code("QC")
                .locality("Quebec")
                .street_parts(vec![
                    "Suite 1234".to_string(),
                    "4321 Rue Somewhere".to_string(),
                ])
                .build()])
            .phones(vec![
                Phone::builder()
                    .preference(1)
                    .contexts(vec!["work".to_string()])
                    .features(vec!["voice".to_string()])
                    .phone("tel:+1-555-555-1234;ext=102")
                    .build(),
                Phone::builder()
                    .contexts(vec!["work".to_string(), "cell".to_string()])
                    .features(vec![
                        "voice".to_string(),
                        "video".to_string(),
                        "text".to_string(),
                    ])
                    .phone("tel:+1-555-555-4321")
                    .build(),
            ])
            .emails(vec![Email::builder()
                .contexts(vec!["work".to_string()])
                .email("joe.user@example.com")
                .build()])
            .urls(vec!["https://example.com/some-url".to_string()])
            .build();

        // WHEN
        let actual = Contact::from_vcard(&contact.to_vcard()).expect("from vcard");

        // THEN
        assert_eq!(contact.full_name, actual.full_name);
        assert_eq!(contact.name_parts, actual.name_parts);
        assert_eq!(contact.kind, actual.kind);
        assert_eq!(contact.langs, actual.langs);
        assert_eq!(contact.organization_names, actual.organization_names);
        assert_eq!(contact.titles, actual.titles);
        assert_eq!(contact.roles, actual.roles);
        assert_eq!(contact.postal_addresses, actual.postal_addresses);
        assert_eq!(contact.phones, actual.phones);
        assert_eq!(contact.emails, actual.emails);
        assert_eq!(contact.contact_uris, actual.contact_uris);
        assert_eq!(contact.urls, actual.urls);
    }
}
