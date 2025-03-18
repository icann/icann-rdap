use std::any::TypeId;

use icann_rdap_common::response::error::Error;

use super::{MdHeaderText, MdParams, MdUtil, ToMd, HR};

impl ToMd for Error {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(TypeId::of::<Self>())));
        md.push_str(HR);
        md.push('\n');
        md
    }
}

impl MdUtil for Error {
    fn get_header_text(&self) -> MdHeaderText {
        MdHeaderText::builder().header_text("RDAP Error").build()
    }
}
