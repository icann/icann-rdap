use std::str::FromStr;

use serde_json::{json, Value};

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
            let given_names= vec_string_to_value(&name_parts.given_names);
            let middle_names= vec_string_to_value(&name_parts.middle_names);
            let prefixes= vec_string_to_value(&name_parts.prefixes);
            let suffixes = vec_string_to_value(&name_parts.suffixes);
            vcard.push(json!(["n", {}, "text", 
                [surnames, given_names, middle_names, prefixes, suffixes]]))
        }

        if let Some(kind) = &self.kind{
            vcard.push(json!(["kind", {}, "text", kind]));
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
