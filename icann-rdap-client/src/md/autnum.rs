use std::any::TypeId;

use icann_rdap_common::response::autnum::Autnum;

use super::{to_header, MdParams, ToMd};

impl ToMd for Autnum {
    fn to_md(&self, params: MdParams) -> String {
        let typeid = TypeId::of::<Autnum>();
        let mut md = String::new();
        md.push_str(&self.common.to_md(params.from_parent(typeid)));
        let header_text = if self.start_autnum.is_some() && self.end_autnum.is_some() {
            format!(
                "Autonomous Systems {}-{}",
                &self.start_autnum.unwrap(),
                &self.end_autnum.unwrap()
            )
        } else if let Some(start_autnum) = &self.start_autnum {
            format!("Autonomous System {start_autnum}")
        } else if let Some(handle) = &self.object_common.handle {
            format!("Autonomous System {handle}")
        } else if let Some(name) = &self.name {
            format!("Autonomous System {name}")
        } else {
            "Autonomous System".to_string()
        };
        md.push_str(&to_header(
            &header_text,
            params.heading_level,
            params.options,
        ));
        md.push_str(&self.object_common.to_md(params.from_parent(typeid)));
        md.push('\n');
        md
    }
}
