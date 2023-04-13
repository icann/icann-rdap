use icann_rdap_common::response::help::Help;

use super::ToMd;

impl ToMd for Help {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[crate::check::CheckType],
        options: &super::MdOptions,
    ) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(heading_level, check_types, options));
        md.push('\n');
        md
    }
}
