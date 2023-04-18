use icann_rdap_common::response::nameserver::Nameserver;

use super::{to_header, MdParams, ToMd};

impl ToMd for Nameserver {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params));
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
        md.push_str(&self.object_common.to_md(params));
        md.push('\n');
        md
    }
}
