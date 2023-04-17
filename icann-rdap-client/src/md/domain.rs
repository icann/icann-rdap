use icann_rdap_common::response::domain::Domain;

use super::{to_header, MdOptions, ToMd};

impl ToMd for Domain {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[crate::check::CheckType],
        options: &MdOptions,
    ) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(heading_level, check_types, options));
        let header_text = if let Some(unicode_name) = &self.unicode_name {
            format!("Domain {unicode_name}")
        } else if let Some(ldh_name) = &self.ldh_name {
            format!("Domain {ldh_name}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Domain {handle}")
        } else {
            "Domain".to_string()
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
