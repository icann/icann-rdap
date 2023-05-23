use std::str::FromStr;

use serde_json::{json, Map, Value};

use super::Contact;

impl Contact {
    // Outputs the vcard array.
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
                    params.insert("pref".to_string(), Value::from(pref));
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

        if let Some(nick_names) = &self.nick_names {
            for nick_name in nick_names {
                vcard.push(json!(["nickname", {}, "text", nick_name]));
            }
        }

        if let Some(emails) = &self.emails {
            for email in emails {
                let mut params: Map<String, Value> = Map::new();
                if let Some(pref) = email.preference {
                    params.insert("pref".to_string(), Value::from(pref));
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
                    params.insert("pref".to_string(), Value::from(pref));
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
                    params.insert("pref".to_string(), Value::from(pref));
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
                    lines.push(street_parts.get(0).cloned().unwrap_or("".to_string()));
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

        // return the vcard array
        vec![
            Value::from_str("vcard").expect("unable to create vcard literal"),
            Value::from(vcard),
        ]
    }
}

fn vec_string_to_value(strings: &Option<Vec<String>>) -> Value {
    let Some(strings) = strings else {
        return Value::from_str("").expect("empty string serialization bombed");
    };

    if strings.is_empty() {
        return Value::from_str("").expect("empty string serialization bombed");
    };

    if strings.len() == 1 {
        let Some(one) = strings.first() else {panic!("couldn't get first element on length of 1")};
        return Value::from_str(one).expect("serializing string");
    };

    // else
    Value::from(strings.clone())
}

fn vec_string_to_param(strings: &Vec<String>) -> Value {
    if strings.is_empty() {
        return Value::from_str("").expect("empty string serialization bombed");
    };

    if strings.len() == 1 {
        let Some(one) = strings.first() else {panic!("couldn't get first element on length of 1")};
        return Value::from_str(one).expect("serializing string");
    };

    // else
    Value::from(strings.clone())
}
