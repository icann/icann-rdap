use icann_rdap_common::response::error::Error;

use super::ToMd;

impl ToMd for Error {
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
