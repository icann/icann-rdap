use std::any::TypeId;

use icann_rdap_common::response::error::Error;

use super::{MdParams, ToMd};

impl ToMd for Error {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(TypeId::of::<Error>())));
        md.push('\n');
        md
    }
}
