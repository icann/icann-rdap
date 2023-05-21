use serde_json::Value;

use super::Contact;

impl Contact {
    pub fn to_vcard(&self) -> Vec<Value> {
        vec![]
    }
}
