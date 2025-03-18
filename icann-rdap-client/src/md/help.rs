use std::any::TypeId;

use icann_rdap_common::response::help::Help;

use super::{MdHeaderText, MdParams, MdUtil, ToMd, HR};

impl ToMd for Help {
    fn to_md(&self, params: MdParams) -> String {
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(TypeId::of::<Self>())));
        md.push_str(HR);
        md.push('\n');
        md
    }
}

impl MdUtil for Help {
    fn get_header_text(&self) -> MdHeaderText {
        MdHeaderText::builder().header_text("Server Help").build()
    }
}
