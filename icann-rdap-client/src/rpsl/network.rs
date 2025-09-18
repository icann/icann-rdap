use icann_rdap_common::prelude::{CommonFields, Network, ObjectCommonFields};

use crate::rpsl::{RpslParams, ToRpsl};

use super::{
    push_entities, push_manditory_attribute, push_notices, push_obj_common,
    push_optional_attribute, AttrName, KeyRef,
};

impl ToRpsl for Network {
    fn to_rpsl(&self, params: RpslParams) -> String {
        let mut rpsl = String::new();

        // notices are comments before the objects
        rpsl = push_notices(rpsl, self.notices());

        // key
        let (key_name, key_value) = self.key_ref(params);
        rpsl = push_manditory_attribute(rpsl, key_name, &key_value);

        // type
        rpsl = push_optional_attribute(rpsl, AttrName::Type, self.network_type());

        // name
        rpsl = push_optional_attribute(rpsl, AttrName::NetName, self.name());

        // parent handle
        rpsl = push_optional_attribute(rpsl, AttrName::ParentHandle, self.parent_handle());

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

impl KeyRef for Network {
    fn key_ref(&self, _params: RpslParams) -> (super::AttrName, String) {
        let mut name = AttrName::Inetnum;
        if let Some(ip_version) = self.ip_version() {
            if ip_version.eq_ignore_ascii_case("v6") {
                name = AttrName::Inet6num;
            }
        }
        let value = format!(
            "{} - {}",
            self.start_address().unwrap_or("NO START ADDR"),
            self.end_address().unwrap_or("NO END ADDR")
        );
        (name, value)
    }
}
