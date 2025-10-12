use icann_rdap_common::prelude::{Autnum, CommonFields, ObjectCommonFields};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{
    push_entities, push_manditory_attribute, push_notices, push_obj_common,
    push_optional_attribute, AttrName, KeyRef,
};

impl ToRpsl for Autnum {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_manditory_attribute(rpsl, key_name, &key_value);

        // range
        let range = format!(
            "{} - {}",
            self.start_autnum()
                .map(|s| s.to_string())
                .unwrap_or("NO START".to_string()),
            self.end_autnum()
                .map(|e| e.to_string())
                .unwrap_or("NO END".to_string()),
        );
        rpsl = push_optional_attribute(rpsl, AttrName::AutnumRange, Some(range.as_str()));

        // type
        rpsl = push_optional_attribute(rpsl, AttrName::Type, self.autnum_type());

        // name
        rpsl = push_optional_attribute(rpsl, AttrName::AsName, self.name());

        // push things common to object classes
        rpsl = push_obj_common(rpsl, params, self);

        //end
        rpsl.push('\n');

        // output entities
        rpsl = push_entities(rpsl, self.entities(), params);

        //return
        rpsl
    }
}

impl KeyRef for Autnum {
    fn key_ref(&self, _params: RpslParams) -> (super::AttrName, String) {
        let value = self
            .start_autnum()
            .map(|s| s.to_string())
            .or_else(|| self.end_autnum().map(|e| e.to_string()))
            .or_else(|| self.handle().map(|h| h.to_string()))
            .unwrap_or("AUT-NUM ID NOT AVAILABLE".to_string());
        let name = AttrName::Autnum;
        (name, value)
    }
}
