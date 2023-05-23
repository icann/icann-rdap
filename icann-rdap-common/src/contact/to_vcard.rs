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
