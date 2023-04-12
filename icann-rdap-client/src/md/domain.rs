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
        md.push_str(&to_header("Domain\n", heading_level, options));
        md.push('\n');
        md
    }
}
