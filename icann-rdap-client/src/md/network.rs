use icann_rdap_common::response::network::Network;

use super::{to_header, MdOptions, ToMd};

impl ToMd for Network {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[crate::check::CheckType],
        options: &MdOptions,
    ) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(heading_level, check_types, options));
        let header_text = if self.start_address.is_some() && self.end_address.is_some() {
            format!(
                "IP Network {}-{}",
                &self.start_address.as_ref().unwrap(),
                &self.end_address.as_ref().unwrap()
            )
        } else if let Some(start_address) = &self.start_address {
            format!("IP Network {}", start_address)
        } else if let Some(handle) = &self.object_common.handle {
            format!("IP Network {}", handle)
        } else if let Some(name) = &self.name {
            format!("IP Network {}", name)
        } else {
            "IP Network".to_string()
        };
        md.push_str(&to_header(&header_text, heading_level, options));
        md.push_str(
            &self
                .object_common
                .to_md(heading_level, check_types, options),
        );
        md.push('\n');
        md
    }
}
