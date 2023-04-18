use icann_rdap_common::response::network::Network;

use super::{to_header, MdParams, ToMd};

impl ToMd for Network {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params));
        let header_text = if self.start_address.is_some() && self.end_address.is_some() {
            format!(
                "IP Network {}-{}",
                &self.start_address.as_ref().unwrap(),
                &self.end_address.as_ref().unwrap()
            )
        } else if let Some(start_address) = &self.start_address {
            format!("IP Network {start_address}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("IP Network {handle}")
        } else if let Some(name) = &self.name {
            format!("IP Network {name}")
        } else {
            "IP Network".to_string()
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
