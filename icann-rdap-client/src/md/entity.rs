use icann_rdap_common::response::entity::Entity;

use super::{to_header, ToMd};

impl ToMd for Entity {
    fn to_md(
        &self,
        heading_level: usize,
        check_types: &[crate::check::CheckType],
        options: &super::MdOptions,
    ) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(heading_level, check_types, options));
        md.push_str(&to_header("Entity", heading_level, options));
        md.push_str(
            &self
                .object_common
                .to_md(heading_level, check_types, options),
        );
        md.push('\n');
        md
    }
}
