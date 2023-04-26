use std::any::TypeId;

use icann_rdap_common::response::nameserver::Nameserver;

use super::{to_header, MdParams, SimpleTable, ToMd};

impl ToMd for Nameserver {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Nameserver>();
        let mut md = String::new();

        // other common stuff
        md.push_str(&self.common.to_md(params.from_parent(typeid)));

        // header
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Nameserver {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Nameserver {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Nameserver {handle}")
        } else {
            "Domain".to_string()
        };
        md.push_str(&to_header(
            &header_text,
            params.heading_level,
            params.options,
        ));

        // identifiers
        let mut identifiers = SimpleTable::new("Identifiers")
            .and_row(&"LDH Name", &self.ldh_name)
            .and_row(&"Unicode Name", &self.unicode_name)
            .and_row(&"Handle", &self.object_common.handle);
        if let Some(addresses) = &self.ip_addresses {
            if let Some(v4) = &addresses.v4 {
                identifiers = identifiers.row_ul(&"Ipv4", v4.iter().collect());
            }
            if let Some(v6) = &addresses.v6 {
                identifiers = identifiers.row_ul(&"Ipv6", v6.iter().collect());
            }
        }
        md.push_str(&identifiers.to_md(params));

        // common object stuff
        md.push_str(&self.object_common.to_md(params.from_parent(typeid)));
        md.push('\n');
        md
    }
}
