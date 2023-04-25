use std::any::TypeId;

use icann_rdap_common::response::domain::Domain;

use super::{to_header, MdParams, SimpleTable, ToMd};

impl ToMd for Domain {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Domain>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Domain {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Domain {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Domain {handle}")
        } else {
            "Domain".to_string()
        };
        md.push_str(&to_header(
            &header_text,
            params.heading_level,
            params.options,
        ));

        let identifiers = SimpleTable::new("Indentifiers")
            .and_row(&"LDH Name", &self.ldh_name)
            .and_row(&"Unicode Name", &self.unicode_name)
            .and_row(&"Handle", &self.object_common.handle);
        md.push_str(&identifiers.to_md(params));

        // Common Object
        md.push_str(&self.object_common.to_md(params.from_parent(typeid)));
        md.push('\n');
        md
    }
}
