use std::any::TypeId;

use icann_rdap_common::response::help::Help;

use super::{MdParams, ToMd};

impl ToMd for Help {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(TypeId::of::<Help>())));
        md.push('\n');
        md
    }
}
